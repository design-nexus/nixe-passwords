//! One-time codes from an item's TOTP seed, in the forms Bitwarden stores: an
//! `otpauth://totp/…` URI, `steam://SECRET`, or a bare base32 secret. Short secrets are
//! accepted (many sites use 80 bits), as other authenticators do.

use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, Builder, Secret as Seed, Totp};

use crate::secret::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSeed;

impl std::fmt::Display for BadSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("the item's one-time code setting isn't valid")
    }
}

impl std::error::Error for BadSeed {}

pub struct Generator {
    totp: Totp,
    period: u64,
}

/// A code and how many seconds it stays valid.
pub struct Code {
    pub code: Secret,
    pub remaining: u64,
    pub period: u64,
}

impl Generator {
    pub fn parse(seed: &Secret) -> Result<Generator, BadSeed> {
        let text = seed.expose().trim();
        let lower = text.to_ascii_lowercase();
        let (builder, period) = if lower.starts_with("otpauth://") {
            from_uri(text)?
        } else if lower.starts_with("steam://") {
            (Builder::new_steam().with_secret(base32(&text["steam://".len()..])?), 30)
        } else {
            (Builder::new().with_algorithm(Algorithm::SHA1).with_secret(base32(text)?), 30)
        };
        Ok(Generator { totp: builder.with_step_duration(period).build_noncompliant(), period })
    }

    pub fn now(&self) -> Code {
        self.at(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    }

    pub fn at(&self, time: u64) -> Code {
        let period = self.period;
        Code { code: Secret::new(self.totp.generate(time).to_string()), remaining: period - time % period, period }
    }
}

/// `otpauth://totp/LABEL?secret=…&algorithm=…&digits=…&period=…` (Steam as
/// `otpauth://steam/…` or `encoder=steam`).
fn from_uri(text: &str) -> Result<(Builder, u64), BadSeed> {
    let url = url::Url::parse(text).map_err(|_| BadSeed)?;
    let mut secret = None;
    let (mut digits, mut period, mut algorithm) = (6u8, 30u64, Algorithm::SHA1);
    let mut steam = url.host_str().is_some_and(|h| h.eq_ignore_ascii_case("steam"));
    for (key, value) in url.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(base32(&value)?),
            "digits" => digits = value.parse().map_err(|_| BadSeed)?,
            "period" => period = value.parse().map_err(|_| BadSeed)?,
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::SHA1,
                    "SHA256" => Algorithm::SHA256,
                    "SHA512" => Algorithm::SHA512,
                    _ => return Err(BadSeed),
                }
            }
            "encoder" if value.eq_ignore_ascii_case("steam") => steam = true,
            _ => {}
        }
    }
    let secret = secret.ok_or(BadSeed)?;
    if !(1..=300).contains(&period) {
        return Err(BadSeed);
    }
    if steam {
        return Ok((Builder::new_steam().with_secret(secret), period));
    }
    if !(6..=10).contains(&digits) || !url.host_str().is_some_and(|h| h.eq_ignore_ascii_case("totp")) {
        return Err(BadSeed);
    }
    Ok((Builder::new().with_algorithm(algorithm).with_digits(digits).with_secret(secret), period))
}

fn base32(text: &str) -> Result<Seed, BadSeed> {
    let clean: String =
        text.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=').map(|c| c.to_ascii_uppercase()).collect();
    let seed = Seed::try_from_base32(&clean).map_err(|_| BadSeed)?;
    if seed.as_bytes().is_empty() { Err(BadSeed) } else { Ok(seed) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B: SHA-1, the ASCII secret "12345678901234567890".
    const RFC: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        let g = Generator::parse(&Secret::new(RFC)).unwrap();
        assert_eq!(g.at(59).code.expose(), "287082");
        assert_eq!(g.at(1111111109).code.expose(), "081804");
        let c = g.at(1111111109);
        assert_eq!((c.period, c.remaining), (30, 1));
    }

    #[test]
    fn seed_forms() {
        let spaced = Secret::new("gezd gnbv gy3t qojq gezd gnbv gy3t qojq");
        assert_eq!(Generator::parse(&spaced).unwrap().at(59).code.expose(), "287082");
        let uri = Secret::new(format!("otpauth://totp/Example:octo?secret={RFC}&issuer=Example&digits=8&period=30"));
        assert_eq!(Generator::parse(&uri).unwrap().at(59).code.expose(), "94287082");
        let sixty = Secret::new(format!("otpauth://totp/x?secret={RFC}&period=60"));
        let c = Generator::parse(&sixty).unwrap().at(59);
        assert_eq!((c.period, c.remaining), (60, 1));
        // An 80-bit secret, as many sites issue.
        assert!(Generator::parse(&Secret::new("JBSWY3DPEHPK3PXP")).is_ok());
        let steam = Generator::parse(&Secret::new(format!("steam://{RFC}"))).unwrap().at(59);
        assert_eq!(steam.code.expose().len(), 5);
        assert!(steam.code.expose().chars().all(|c| "23456789BCDFGHJKMNPQRTVWXY".contains(c)));
        for bad in [
            "",
            "not base32 !!",
            "otpauth://totp/x?digits=6",
            "steam://",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
        ] {
            assert!(Generator::parse(&Secret::new(bad)).is_err(), "{bad}");
        }
    }
}
