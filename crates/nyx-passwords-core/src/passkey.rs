//! Passkeys stored on login items (`login.fido2Credentials`), made and used the way the
//! official clients do as an authenticator (docs/PASSKEYS.md): ES256 keys, attestation
//! "none" with Bitwarden's AAGUID, user presence always, the backup flags set, and a
//! counter that stays 0 so devices that sync never disagree about it.
//!
//! This module builds WebAuthn's structures; the key operations are in `crypto.rs`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};

use crate::crypto::{CryptoError, ItemKey, passkey_key, passkey_public, passkey_sign, sha256};
use crate::model::Cipher;
use crate::secret::Secret;

/// Bitwarden's authenticator id (`d548826e-79b4-db40-a3d8-11116f7e8349`).
pub const AAGUID: [u8; 16] = [0xd5, 0x48, 0x82, 0x6e, 0x79, 0xb4, 0xdb, 0x40, 0xa3, 0xd8, 0x11, 0x11, 0x6f, 0x7e, 0x83, 0x49];

/// Authenticator data flags.
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED: u8 = 0x40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyError {
    NotFound,
    /// The stored passkey isn't one this client can use (not ES256, or malformed).
    Unusable,
    /// It belongs to another site than the one asking.
    WrongSite,
    Crypto(CryptoError),
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such passkey"),
            Self::Unusable => f.write_str("this passkey can't be used here"),
            Self::WrongSite => f.write_str("this passkey is for another site"),
            Self::Crypto(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PasskeyError {}

impl From<CryptoError> for PasskeyError {
    fn from(e: CryptoError) -> Self {
        PasskeyError::Crypto(e)
    }
}

/// A passkey as listed: everything but its key.
#[derive(Debug, Clone, PartialEq)]
pub struct Passkey {
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    /// base64url without padding.
    pub user_handle: String,
    pub discoverable: bool,
    pub creation_date: String,
}

/// The stored passkeys of an item (encrypted), as a list.
pub fn stored(c: &Cipher) -> Vec<Value> {
    c.login.as_ref().and_then(|l| l.extra.get("fido2Credentials")).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn text(key: &mut ItemKey, v: &Value, name: &str) -> Result<String, CryptoError> {
    Ok(key.decrypt_opt(v.get(name).and_then(Value::as_str))?.map(|s| s.expose().to_string()).unwrap_or_default())
}

/// The passkeys on an item, decrypted except for their keys.
pub fn list(key: &mut ItemKey, c: &Cipher) -> Result<Vec<Passkey>, CryptoError> {
    stored(c)
        .iter()
        .map(|p| {
            Ok(Passkey {
                credential_id: text(key, p, "credentialId")?,
                rp_id: text(key, p, "rpId")?,
                rp_name: text(key, p, "rpName")?,
                user_name: text(key, p, "userName")?,
                user_display_name: text(key, p, "userDisplayName")?,
                user_handle: text(key, p, "userHandle")?,
                discoverable: text(key, p, "discoverable")? == "true",
                creation_date: p.get("creationDate").and_then(Value::as_str).unwrap_or_default().to_string(),
            })
        })
        .collect()
}

/// A credential id as bytes: a UUID (what the official clients make) is its 16 bytes;
/// `b64.` and base64url is an imported one.
pub fn credential_bytes(id: &str) -> Option<Vec<u8>> {
    if let Some(b64) = id.strip_prefix("b64.") {
        return URL_SAFE_NO_PAD.decode(b64.trim_end_matches('=')).ok();
    }
    uuid::Uuid::parse_str(id).ok().map(|u| u.as_bytes().to_vec())
}

/// The credential id text for bytes, the other way round.
pub fn credential_text(bytes: &[u8]) -> String {
    match uuid::Uuid::from_slice(bytes) {
        Ok(u) => u.to_string(),
        Err(_) => format!("b64.{}", URL_SAFE_NO_PAD.encode(bytes)),
    }
}

fn authenticator_data(rp_id: &str, verified: bool, attested: Option<&[u8]>) -> Vec<u8> {
    let mut flags = USER_PRESENT | BACKUP_ELIGIBLE | BACKED_UP;
    if verified {
        flags |= USER_VERIFIED;
    }
    if attested.is_some() {
        flags |= ATTESTED;
    }
    let mut data = sha256(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend([0, 0, 0, 0]);
    data.extend(attested.unwrap_or_default());
    data
}

/// A COSE EC2 public key (ES256, P-256).
fn cose_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    use ciborium::value::Value as Cbor;
    let key = Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (Cbor::Integer((-2).into()), Cbor::Bytes(x.to_vec())),
        (Cbor::Integer((-3).into()), Cbor::Bytes(y.to_vec())),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&key, &mut out).expect("a CBOR map encodes");
    out
}

/// What a site gets back when signing in with a passkey.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Signs in to `rp_id` with the item's passkey `credential_id`: the signature over the
/// authenticator data and the hash of the client data the extension built.
pub fn assert(
    key: &mut ItemKey,
    c: &Cipher,
    credential_id: &str,
    rp_id: &str,
    client_data_hash: &[u8],
    verified: bool,
) -> Result<Assertion, PasskeyError> {
    for p in stored(c) {
        if text(key, &p, "credentialId")? != credential_id {
            continue;
        }
        if text(key, &p, "rpId")? != rp_id {
            return Err(PasskeyError::WrongSite);
        }
        let algorithm = (text(key, &p, "keyAlgorithm")?, text(key, &p, "keyCurve")?);
        if algorithm != ("ECDSA".into(), "P-256".into()) {
            return Err(PasskeyError::Unusable);
        }
        let stored_key = Secret::new(text(key, &p, "keyValue")?);
        let authenticator_data = authenticator_data(rp_id, verified, None);
        let mut signed = authenticator_data.clone();
        signed.extend(client_data_hash);
        let signature = passkey_sign(&stored_key, &signed)?;
        let user_handle =
            URL_SAFE_NO_PAD.decode(text(key, &p, "userHandle")?.trim_end_matches('=')).map_err(|_| PasskeyError::Unusable)?;
        return Ok(Assertion {
            credential_id: credential_bytes(credential_id).ok_or(PasskeyError::Unusable)?,
            authenticator_data,
            signature,
            user_handle,
        });
    }
    Err(PasskeyError::NotFound)
}

/// What the site sees for a new passkey, and its fields to store (plain, encrypted when
/// the item is saved).
#[derive(Debug, Clone)]
pub struct Created {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// The COSE public key, for `getPublicKey()` and the attested data.
    pub public_key: Vec<u8>,
    pub fields: Map<String, Value>,
}

/// The site's account a passkey is made for.
pub struct NewPasskey<'a> {
    pub rp_id: &'a str,
    pub rp_name: &'a str,
    pub user_handle: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub discoverable: bool,
    pub verified: bool,
}

/// Makes a passkey: a new ES256 key, a UUID credential id, attestation "none".
pub fn create(new: &NewPasskey, now: &str) -> Result<Created, PasskeyError> {
    let (stored_key, x, y) = passkey_key()?;
    let id = uuid::Uuid::new_v4();
    let credential_id = id.as_bytes().to_vec();
    let public_key = cose_key(&x, &y);
    let mut attested = AAGUID.to_vec();
    attested.extend((credential_id.len() as u16).to_be_bytes());
    attested.extend(&credential_id);
    attested.extend(&public_key);
    let authenticator_data = authenticator_data(new.rp_id, new.verified, Some(&attested));
    use ciborium::value::Value as Cbor;
    let object = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(authenticator_data.clone())),
    ]);
    let mut attestation_object = Vec::new();
    ciborium::into_writer(&object, &mut attestation_object).expect("a CBOR map encodes");
    let fields = json!({
        "credentialId": id.to_string(),
        "keyType": "public-key",
        "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256",
        "keyValue": stored_key.expose(),
        "rpId": new.rp_id,
        "rpName": new.rp_name,
        "userHandle": URL_SAFE_NO_PAD.encode(new.user_handle),
        "userName": new.user_name,
        "userDisplayName": new.user_display_name,
        "counter": "0",
        "discoverable": if new.discoverable { "true" } else { "false" },
        "creationDate": now,
    });
    let Value::Object(fields) = fields else { unreachable!() };
    Ok(Created { credential_id, attestation_object, authenticator_data, public_key, fields })
}

/// A stored passkey's public key, as COSE (for checking it fits its key).
pub fn public_key_of(stored_key: &Secret) -> Result<Vec<u8>, CryptoError> {
    let (x, y) = passkey_public(stored_key)?;
    Ok(cose_key(&x, &y))
}

/// Encrypts a new passkey's fields for storing on an item; `creationDate` stays plain.
pub fn encrypt(key: &mut ItemKey, fields: &Map<String, Value>) -> Result<Value, CryptoError> {
    let mut out = Map::new();
    for (name, v) in fields {
        let plain = v.as_str().unwrap_or_default();
        let value = if name == "creationDate" { Value::String(plain.into()) } else { Value::String(key.encrypt(plain)?) };
        out.insert(name.clone(), value);
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    fn verify(cose: &[u8], data: &[u8], der: &[u8]) -> bool {
        let key: ciborium::value::Value = ciborium::from_reader(cose).unwrap();
        let map = key.as_map().unwrap();
        let get = |k: i64| map.iter().find(|(n, _)| n.as_integer() == Some(k.into())).unwrap().1.as_bytes().unwrap().clone();
        let mut sec1 = vec![4u8];
        sec1.extend(get(-2));
        sec1.extend(get(-3));
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        verifying.verify(data, &p256::ecdsa::Signature::from_der(der).unwrap()).is_ok()
    }

    #[test]
    fn made_passkeys_attest_and_sign() {
        let new = NewPasskey {
            rp_id: "example.com",
            rp_name: "Example",
            user_handle: b"user-1",
            user_name: "me@example.com",
            user_display_name: "Me",
            discoverable: true,
            verified: true,
        };
        let made = create(&new, "2026-10-28T00:00:00.000Z").unwrap();
        // Attestation "none", and the authenticator data a relying party reads.
        let object: ciborium::value::Value = ciborium::from_reader(made.attestation_object.as_slice()).unwrap();
        let entries = object.as_map().unwrap();
        let find = |k: &str| entries.iter().find(|(n, _)| n.as_text() == Some(k)).unwrap().1.clone();
        assert_eq!(find("fmt").as_text(), Some("none"));
        let data = find("authData").as_bytes().unwrap().clone();
        assert_eq!(&data[..32], &sha256(b"example.com"));
        assert_eq!(data[32], USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP | ATTESTED);
        assert_eq!(&data[33..37], &[0, 0, 0, 0]);
        assert_eq!(&data[37..53], &AAGUID);
        assert_eq!(u16::from_be_bytes([data[53], data[54]]), 16);
        assert_eq!(&data[55..71], made.credential_id.as_slice());
        assert_eq!(&data[71..], made.public_key.as_slice());
        assert_eq!(made.fields["credentialId"], credential_text(&made.credential_id));
        assert_eq!(public_key_of(&Secret::new(made.fields["keyValue"].as_str().unwrap())).unwrap(), made.public_key);

        // Signing in: the signature checks out with the public key the site keeps.
        let client = sha256(b"{\"type\":\"webauthn.get\"}");
        let stored_key = Secret::new(made.fields["keyValue"].as_str().unwrap());
        let auth = authenticator_data("example.com", false, None);
        let mut signed = auth.clone();
        signed.extend(client);
        assert!(verify(&made.public_key, &signed, &passkey_sign(&stored_key, &signed).unwrap()));
        assert_eq!(auth[32], USER_PRESENT | BACKUP_ELIGIBLE | BACKED_UP);
    }

    #[test]
    fn credential_ids() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(credential_bytes(&id.to_string()).unwrap(), id.as_bytes());
        assert_eq!(credential_text(id.as_bytes()), id.to_string());
        assert_eq!(credential_bytes("b64.AAECAw").unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(credential_text(&[0, 1, 2, 3]), "b64.AAECAw");
        assert!(credential_bytes("nonsense").is_none());
    }
}
