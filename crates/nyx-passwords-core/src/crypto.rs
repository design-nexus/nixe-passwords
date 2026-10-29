//! The only module that names bitwarden-crypto or any cryptographic primitive (see
//! docs/SECURITY.md, rule 1). Vault keys live in bitwarden-crypto's `KeyStore` and are
//! referred to by slot; nothing outside this module touches key material. Pairing a
//! browser extension uses RustCrypto's X25519, HKDF-SHA256 and AES-256-GCM. Errors say
//! what failed, never with what.

use std::fmt;
use std::str::FromStr;

use bitwarden_crypto as bw;
use bitwarden_crypto::{Decryptable, PrimitiveEncryptable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use zeroize::Zeroizing;

use crate::secret::{Secret, SecretBytes};

mod slots {
    use bitwarden_crypto::key_slot_ids;

    key_slot_ids! {
        #[symmetric]
        pub enum Symmetric {
            User,
            Organization(uuid::Uuid),
            #[local]
            Local(LocalId),
        }
        #[private]
        pub enum Private {
            User,
            #[local]
            Local(LocalId),
        }
        #[signing]
        pub enum Signing {
            User,
            #[local]
            Local(LocalId),
        }
        pub Slots => Symmetric, Private, Signing;
    }
}
use slots::{Private, Slots, Symmetric};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// KDF parameters outside what the official clients allow.
    KdfParameters,
    /// The protected user key didn't open: almost always a wrong master password.
    WrongPassword,
    /// A value isn't a well-formed EncString or key.
    Malformed,
    /// Decryption or authentication of a value failed.
    Decrypt,
    Encrypt,
    /// The key a value needs isn't loaded (an organization without its key, a locked vault).
    MissingKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::KdfParameters => "the server's key derivation settings are out of range",
            Self::WrongPassword => "wrong master password",
            Self::Malformed => "malformed encrypted value",
            Self::Decrypt => "couldn't decrypt a value",
            Self::Encrypt => "couldn't encrypt a value",
            Self::MissingKey => "a needed key isn't available",
        })
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Key derivation settings, as prelogin reports them and the store keeps them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

// Upper limits, so a hostile server can't make unlock take forever or exhaust memory.
// Lower limits are bitwarden-crypto's (PBKDF2 ≥ 5000; Argon2id ≥ 2, 16 MiB, 1).
const PBKDF2_MAX: u32 = 2_000_000;
const ARGON2_MAX_ITERATIONS: u32 = 10;
const ARGON2_MAX_MEMORY_MIB: u32 = 1024;
const ARGON2_MAX_PARALLELISM: u32 = 16;

impl Kdf {
    /// From prelogin's `kdf` (0 = PBKDF2-SHA256, 1 = Argon2id) and its parameters.
    pub fn from_server(kind: u64, iterations: u64, memory: Option<u64>, parallelism: Option<u64>) -> Result<Kdf> {
        let small = |v: u64| u32::try_from(v).map_err(|_| CryptoError::KdfParameters);
        let kdf = match kind {
            0 => Kdf::Pbkdf2 { iterations: small(iterations)? },
            1 => Kdf::Argon2id {
                iterations: small(iterations)?,
                memory_mib: small(memory.ok_or(CryptoError::KdfParameters)?)?,
                parallelism: small(parallelism.ok_or(CryptoError::KdfParameters)?)?,
            },
            _ => return Err(CryptoError::KdfParameters),
        };
        kdf.to_bw()?;
        Ok(kdf)
    }

    /// Whether `self` is at least as costly as `before`, so a server can't quietly weaken
    /// the KDF of an account this device already knows.
    pub fn at_least(&self, before: &Kdf) -> bool {
        match (self, before) {
            (Kdf::Pbkdf2 { iterations: a }, Kdf::Pbkdf2 { iterations: b }) => a >= b,
            (
                Kdf::Argon2id { iterations: a, memory_mib: m, parallelism: p },
                Kdf::Argon2id { iterations: b, memory_mib: n, parallelism: q },
            ) => a >= b && m >= n && p >= q,
            (Kdf::Argon2id { .. }, Kdf::Pbkdf2 { .. }) => true,
            (Kdf::Pbkdf2 { .. }, Kdf::Argon2id { .. }) => false,
        }
    }

    fn to_bw(self) -> Result<bw::Kdf> {
        let nz = |v: u32| std::num::NonZeroU32::new(v).ok_or(CryptoError::KdfParameters);
        match self {
            Kdf::Pbkdf2 { iterations } if iterations <= PBKDF2_MAX => Ok(bw::Kdf::PBKDF2 { iterations: nz(iterations)? }),
            Kdf::Argon2id { iterations, memory_mib, parallelism }
                if iterations <= ARGON2_MAX_ITERATIONS
                    && memory_mib <= ARGON2_MAX_MEMORY_MIB
                    && parallelism <= ARGON2_MAX_PARALLELISM =>
            {
                Ok(bw::Kdf::Argon2id { iterations: nz(iterations)?, memory: nz(memory_mib)?, parallelism: nz(parallelism)? })
            }
            _ => Err(CryptoError::KdfParameters),
        }
    }
}

/// The key derived from the master password. Lives only for the length of a login or
/// unlock.
pub struct MasterKey(bw::MasterKey);

impl MasterKey {
    /// Runs the KDF; slow by design (call it off the UI thread).
    pub fn derive(password: &Secret, email: &str, kdf: &Kdf) -> Result<MasterKey> {
        bw::MasterKey::derive(password.expose(), email, &kdf.to_bw()?).map(MasterKey).map_err(|_| CryptoError::KdfParameters)
    }

    /// The hash the server checks at login (`password` in the token request).
    pub fn server_hash(&self, password: &Secret) -> Secret {
        Secret::new(self.0.derive_master_key_hash(password.expose().as_bytes(), bw::HashPurpose::ServerAuthorization).to_string())
    }
}

/// Base64 SHA-256 of a URI, which official clients store encrypted as `uriChecksum` and
/// check before trusting a URI.
pub fn uri_checksum(uri: &str) -> Secret {
    use sha2::Digest;
    Secret::new(bitwarden_encoding::B64::from(sha2::Sha256::digest(uri.as_bytes()).to_vec()).to_string())
}

/// A password's SHA-256, for telling reused passwords apart in the security report.
pub fn password_digest(password: &Secret) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(password.expose().as_bytes()).into()
}

/// A password's SHA-1 as upper-case hex: the format of Have I Been Pwned's range API.
pub fn breach_hash(password: &Secret) -> Zeroizing<String> {
    use sha1::Digest;
    Zeroizing::new(sha1::Sha1::digest(password.expose().as_bytes()).iter().map(|b| format!("{b:02X}")).collect())
}

/// Checks that a value parses as an EncString without decrypting it.
pub fn is_enc_string(value: &str) -> bool {
    bw::EncString::parse_strict(value).is_ok()
}

/// The keys of an unlocked vault: the user key, the private key and organization keys.
/// `lock` (or dropping it) clears them.
pub struct Keys {
    store: bw::KeyStore<Slots>,
}

impl Keys {
    /// Opens the protected user key (`profile.key`) with the master key.
    pub fn unlock(master: &MasterKey, protected_user_key: &str) -> Result<Keys> {
        let wrapped = bw::EncString::parse_strict(protected_user_key).map_err(|_| CryptoError::Malformed)?;
        let user = master.0.decrypt_user_key(wrapped).map_err(|_| CryptoError::WrongPassword)?;
        let keys = Keys { store: bw::KeyStore::default() };
        {
            let mut ctx = keys.store.context_mut();
            let local = ctx.add_local_symmetric_key(user);
            ctx.persist_symmetric_key(local, Symmetric::User).map_err(|_| CryptoError::MissingKey)?;
        }
        Ok(keys)
    }

    /// The user key, base64: what "unlock with the system keyring" keeps there.
    pub fn export_user_key(&self) -> Result<Secret> {
        let ctx = self.store.context();
        #[allow(deprecated)] // the export this feature exists for
        let key = ctx.dangerous_get_symmetric_key(Symmetric::User).map_err(|_| CryptoError::MissingKey)?;
        Ok(Secret::new(key.to_base64().to_string()))
    }

    /// Opens with a user key from `export_user_key`, in place of the master password.
    pub fn from_user_key(exported: &Secret) -> Result<Keys> {
        let user = bw::SymmetricCryptoKey::try_from(exported.expose().to_string()).map_err(|_| CryptoError::Malformed)?;
        let keys = Keys { store: bw::KeyStore::default() };
        {
            let mut ctx = keys.store.context_mut();
            let local = ctx.add_local_symmetric_key(user);
            ctx.persist_symmetric_key(local, Symmetric::User).map_err(|_| CryptoError::MissingKey)?;
        }
        Ok(keys)
    }

    /// Adds the account's private key (`profile.privateKey`, wrapped by the user key),
    /// needed for organization keys.
    pub fn add_private_key(&self, wrapped: &str) -> Result<()> {
        let wrapped = bw::EncString::parse_strict(wrapped).map_err(|_| CryptoError::Malformed)?;
        let mut ctx = self.store.context_mut();
        let local = ctx.unwrap_private_key(Symmetric::User, &wrapped).map_err(|_| CryptoError::Decrypt)?;
        ctx.persist_private_key(local, Private::User).map_err(|_| CryptoError::MissingKey)
    }

    /// Adds an organization's key (`profile.organizations[].key`, wrapped for the
    /// account's public key).
    pub fn add_organization(&self, id: Uuid, wrapped: &str) -> Result<()> {
        let shared = bw::UnsignedSharedKey::from_str(wrapped).map_err(|_| CryptoError::Malformed)?;
        let mut ctx = self.store.context_mut();
        if !ctx.has_private_key(Private::User) {
            return Err(CryptoError::MissingKey);
        }
        let local = shared.decapsulate(Private::User, &mut ctx).map_err(|_| CryptoError::Decrypt)?;
        ctx.persist_symmetric_key(local, Symmetric::Organization(id)).map_err(|_| CryptoError::MissingKey)
    }

    pub fn has_organization(&self, id: Uuid) -> bool {
        self.store.context().has_symmetric_key(Symmetric::Organization(id))
    }

    /// The key for one item: its own key (`cipher.key`) if it has one, else its
    /// organization's or the user's. Folder names use `item(None, None)`.
    pub fn item(&self, organization: Option<Uuid>, own_key: Option<&str>) -> Result<ItemKey<'_>> {
        let mut ctx = self.store.context();
        let base = match organization {
            Some(id) => Symmetric::Organization(id),
            None => Symmetric::User,
        };
        if !ctx.has_symmetric_key(base) {
            return Err(CryptoError::MissingKey);
        }
        let key = match own_key {
            Some(wrapped) => {
                let wrapped = bw::EncString::parse_strict(wrapped).map_err(|_| CryptoError::Malformed)?;
                ctx.unwrap_symmetric_key(base, &wrapped).map_err(|_| CryptoError::Decrypt)?
            }
            None => base,
        };
        Ok(ItemKey { ctx, key })
    }

    /// A new item key under the organization's key or the user's, with its wrapped form
    /// for `cipher.key`.
    pub fn new_item(&self, organization: Option<Uuid>) -> Result<(ItemKey<'_>, String)> {
        let mut ctx = self.store.context();
        let base = match organization {
            Some(id) => Symmetric::Organization(id),
            None => Symmetric::User,
        };
        if !ctx.has_symmetric_key(base) {
            return Err(CryptoError::MissingKey);
        }
        let key = ctx.make_symmetric_key(bw::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapped = ctx.wrap_symmetric_key(base, key).map_err(|_| CryptoError::Encrypt)?;
        let wrapped =
            serde_json::to_value(&wrapped).ok().and_then(|v| v.as_str().map(str::to_string)).ok_or(CryptoError::Encrypt)?;
        Ok((ItemKey { ctx, key }, wrapped))
    }

    /// An item's own key, wrapped by `from`'s key (the user's when `None`), rewrapped by
    /// `to`'s: moving the item doesn't touch its fields.
    pub fn rewrap(&self, own_key: &str, from: Option<Uuid>, to: Option<Uuid>) -> Result<String> {
        let slot = |org: Option<Uuid>| org.map_or(Symmetric::User, Symmetric::Organization);
        let mut ctx = self.store.context();
        for s in [slot(from), slot(to)] {
            if !ctx.has_symmetric_key(s) {
                return Err(CryptoError::MissingKey);
            }
        }
        let wrapped = bw::EncString::parse_strict(own_key).map_err(|_| CryptoError::Malformed)?;
        let key = ctx.unwrap_symmetric_key(slot(from), &wrapped).map_err(|_| CryptoError::Decrypt)?;
        let rewrapped = ctx.wrap_symmetric_key(slot(to), key).map_err(|_| CryptoError::Encrypt)?;
        serde_json::to_value(&rewrapped).ok().and_then(|v| v.as_str().map(str::to_string)).ok_or(CryptoError::Encrypt)
    }

    /// The user key, encrypted for another device's public key (base64 SPKI DER), to
    /// approve its request to sign in.
    pub fn share_user_key(&self, their_public: &str) -> Result<String> {
        let public = public_key(their_public)?;
        let ctx = self.store.context();
        let shared = bw::UnsignedSharedKey::encapsulate(Symmetric::User, &public, &ctx).map_err(|_| CryptoError::Encrypt)?;
        Ok(shared.to_string())
    }

    /// Another account's keys, from its user key encrypted for this account's public key
    /// (emergency access): opened with this account's private key into keys of their own.
    pub fn open_shared(&self, shared: &str, their_private_key: Option<&str>) -> Result<Keys> {
        let shared = bw::UnsignedSharedKey::from_str(shared).map_err(|_| CryptoError::Malformed)?;
        let key = {
            let mut ctx = self.store.context_mut();
            if !ctx.has_private_key(Private::User) {
                return Err(CryptoError::MissingKey);
            }
            let local = shared.decapsulate(Private::User, &mut ctx).map_err(|_| CryptoError::Decrypt)?;
            #[allow(deprecated)] // copied into the other account's own store, dropped with it
            let key = ctx.dangerous_get_symmetric_key(local).map_err(|_| CryptoError::MissingKey)?.clone();
            key
        };
        let keys = Keys { store: bw::KeyStore::default() };
        {
            let mut ctx = keys.store.context_mut();
            let local = ctx.add_local_symmetric_key(key);
            ctx.persist_symmetric_key(local, Symmetric::User).map_err(|_| CryptoError::MissingKey)?;
        }
        if let Some(private) = their_private_key {
            keys.add_private_key(private)?;
        }
        Ok(keys)
    }

    /// Drops every key. The vault is locked afterwards.
    pub fn lock(&self) {
        self.store.clear();
    }

    pub fn is_unlocked(&self) -> bool {
        self.store.context().has_symmetric_key(Symmetric::User)
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.store.clear();
    }
}

/// Decrypts and encrypts the fields of one item. Short-lived: it holds a read lock on
/// the key store, so `lock` waits for it.
pub struct ItemKey<'a> {
    ctx: bw::KeyStoreContext<'a, Slots>,
    key: Symmetric,
}

impl ItemKey<'_> {
    pub fn decrypt(&mut self, value: &str) -> Result<Secret> {
        let enc = bw::EncString::parse_strict(value).map_err(|_| CryptoError::Malformed)?;
        let plain: String = enc.decrypt(&mut self.ctx, self.key).map_err(|_| CryptoError::Decrypt)?;
        Ok(Secret::new(plain))
    }

    /// For optional fields: `None` and empty strings stay `None`.
    pub fn decrypt_opt(&mut self, value: Option<&str>) -> Result<Option<Secret>> {
        match value {
            Some(v) if !v.is_empty() => self.decrypt(v).map(Some),
            _ => Ok(None),
        }
    }

    pub fn decrypt_bytes(&mut self, value: &str) -> Result<SecretBytes> {
        let enc = bw::EncString::parse_strict(value).map_err(|_| CryptoError::Malformed)?;
        let plain: Vec<u8> = enc.decrypt(&mut self.ctx, self.key).map_err(|_| CryptoError::Decrypt)?;
        Ok(SecretBytes::new(plain))
    }

    /// Decrypts an attachment's file: with the attachment's own key (`attachment.key`,
    /// wrapped by this item key), or with this item key itself for attachments from
    /// before attachment keys.
    pub fn decrypt_file(&mut self, attachment_key: Option<&str>, data: &[u8]) -> Result<SecretBytes> {
        let enc = bw::EncString::from_buffer(data).map_err(|_| CryptoError::Malformed)?;
        let key = match attachment_key {
            Some(wrapped) => {
                let wrapped = bw::EncString::parse_strict(wrapped).map_err(|_| CryptoError::Malformed)?;
                self.ctx.unwrap_symmetric_key(self.key, &wrapped).map_err(|_| CryptoError::Decrypt)?
            }
            None => self.key,
        };
        let plain: Vec<u8> = enc.decrypt(&mut self.ctx, key).map_err(|_| CryptoError::Decrypt)?;
        Ok(SecretBytes::new(plain))
    }

    /// Encrypts a file for a new attachment under a new key of its own. Returns the key
    /// wrapped by this item key (`attachment.key`) and the encrypted file.
    pub fn encrypt_file(&mut self, data: &[u8]) -> Result<(String, Vec<u8>)> {
        let key = self.ctx.make_symmetric_key(bw::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapped = self.ctx.wrap_symmetric_key(self.key, key).map_err(|_| CryptoError::Encrypt)?;
        let wrapped =
            serde_json::to_value(&wrapped).ok().and_then(|v| v.as_str().map(str::to_string)).ok_or(CryptoError::Encrypt)?;
        let enc: bw::EncString =
            bw::OctetStreamBytes::from(data.to_vec()).encrypt(&mut self.ctx, key).map_err(|_| CryptoError::Encrypt)?;
        Ok((wrapped, enc.to_buffer().map_err(|_| CryptoError::Encrypt)?))
    }

    /// Encrypts a key (an attachment's), which is bytes rather than text.
    pub fn encrypt_key_bytes(&mut self, plain: &[u8]) -> Result<String> {
        let enc: bw::EncString = bw::BitwardenLegacyKeyBytes::from(plain.to_vec())
            .encrypt(&mut self.ctx, self.key)
            .map_err(|_| CryptoError::Encrypt)?;
        serde_json::to_value(&enc).ok().and_then(|v| v.as_str().map(str::to_string)).ok_or(CryptoError::Encrypt)
    }

    pub fn encrypt(&mut self, plain: &str) -> Result<String> {
        let enc: bw::EncString = plain.encrypt(&mut self.ctx, self.key).map_err(|_| CryptoError::Encrypt)?;
        serde_json::to_value(&enc).ok().and_then(|v| v.as_str().map(str::to_string)).ok_or(CryptoError::Encrypt)
    }
}

/// The key of a password-protected export, in Bitwarden's format: the password run
/// through the KDF with the export's salt (its base64 text, as the official clients
/// use it), then stretched as a PIN key is.
pub struct ExportKey(bw::PinKey);

impl ExportKey {
    /// Slow by design (call it off the UI thread).
    pub fn derive(password: &Secret, salt: &str, kdf: &Kdf) -> Result<ExportKey> {
        bw::PinKey::derive(password.expose().as_bytes(), salt.as_bytes(), &kdf.to_bw()?)
            .map(ExportKey)
            .map_err(|_| CryptoError::KdfParameters)
    }

    pub fn encrypt(&self, plain: &str) -> Result<String> {
        use bitwarden_crypto::KeyEncryptable;
        let enc: bw::EncString = plain.to_string().encrypt_with_key(&self.0).map_err(|_| CryptoError::Encrypt)?;
        Ok(enc.to_string())
    }

    pub fn decrypt(&self, value: &str) -> Result<Secret> {
        use bitwarden_crypto::KeyDecryptable;
        let enc = bw::EncString::parse_strict(value).map_err(|_| CryptoError::Malformed)?;
        let plain: String = enc.decrypt_with_key(&self.0).map_err(|_| CryptoError::WrongPassword)?;
        Ok(Secret::new(plain))
    }
}

fn public_key(b64: &str) -> Result<bw::PublicKey> {
    let der = bitwarden_encoding::B64::try_from(b64.to_string()).map_err(|_| CryptoError::Malformed)?;
    bw::PublicKey::from_der(&bw::SpkiPublicKeyBytes::from(der.as_bytes().to_vec())).map_err(|_| CryptoError::Malformed)
}

/// The words both devices show for a sign-in request, so the user can tell it's the same
/// request: Bitwarden's fingerprint phrase of the account's email and the requesting
/// device's public key.
pub fn fingerprint_phrase(email: &str, public: &str) -> Result<String> {
    let der = bitwarden_encoding::B64::try_from(public.to_string()).map_err(|_| CryptoError::Malformed)?;
    bw::fingerprint(email, &bw::SpkiPublicKeyBytes::from(der.as_bytes().to_vec())).map_err(|_| CryptoError::Malformed)
}

/// This device's side of "sign in with another device": a key pair made for one request.
/// The approving device sends the user key encrypted for its public key.
pub struct DeviceRequest(Option<bw::PrivateKey>);

impl DeviceRequest {
    /// A new key pair and its public key (base64 SPKI DER).
    pub fn new() -> Result<(DeviceRequest, String)> {
        let private = bw::PrivateKey::make(bw::PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let der = private.to_public_key().to_der().map_err(|_| CryptoError::Encrypt)?;
        let public = bitwarden_encoding::B64::from(der.as_ref().to_vec()).to_string();
        Ok((DeviceRequest(Some(private)), public))
    }

    /// The keys, from the user key the other device sent; the request's key pair is used
    /// up. The account's private key must open with it, or it isn't this account's key.
    pub fn open(&mut self, shared: &str, wrapped_private_key: &str) -> Result<Keys> {
        let private = self.0.take().ok_or(CryptoError::MissingKey)?;
        let shared = bw::UnsignedSharedKey::from_str(shared).map_err(|_| CryptoError::Malformed)?;
        let keys = Keys { store: bw::KeyStore::default() };
        {
            let mut ctx = keys.store.context_mut();
            let request = ctx.add_local_private_key(private);
            let user = shared.decapsulate(request, &mut ctx).map_err(|_| CryptoError::Decrypt)?;
            ctx.persist_symmetric_key(user, Symmetric::User).map_err(|_| CryptoError::MissingKey)?;
        }
        keys.add_private_key(wrapped_private_key)?;
        Ok(keys)
    }
}

/// SHA-256, for WebAuthn's relying-party id hash and client data hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// A new passkey key (ES256: P-256), as the official clients store it in `keyValue`:
/// PKCS#8, base64url without padding. Also its public key's x and y.
pub fn passkey_key() -> Result<(Secret, [u8; 32], [u8; 32])> {
    use base64::Engine;
    use p256::elliptic_curve::Generate;
    use p256::pkcs8::EncodePrivateKey;
    let key = p256::SecretKey::generate_from_rng(&mut rand::rng());
    let der = key.to_pkcs8_der().map_err(|_| CryptoError::Encrypt)?;
    let stored = Secret::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.as_bytes()));
    let (x, y) = passkey_point(&key)?;
    Ok((stored, x, y))
}

fn passkey_secret(stored: &Secret) -> Result<p256::SecretKey> {
    use base64::Engine;
    use p256::pkcs8::DecodePrivateKey;
    let text = stored.expose().trim_end_matches('=');
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .map_err(|_| CryptoError::Malformed)?;
    p256::SecretKey::from_pkcs8_der(&der).map_err(|_| CryptoError::Malformed)
}

fn passkey_point(key: &p256::SecretKey) -> Result<([u8; 32], [u8; 32])> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = key.public_key().to_sec1_point(false);
    let (x, y) = (point.x().ok_or(CryptoError::Malformed)?, point.y().ok_or(CryptoError::Malformed)?);
    Ok(((*x).into(), (*y).into()))
}

/// A stored passkey key's public key: x and y.
pub fn passkey_public(stored: &Secret) -> Result<([u8; 32], [u8; 32])> {
    passkey_point(&passkey_secret(stored)?)
}

/// The ES256 signature (DER, as WebAuthn wants it) of `data` with a stored passkey key.
pub fn passkey_sign(stored: &Secret, data: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::Signer;
    let signing = p256::ecdsa::SigningKey::from(passkey_secret(stored)?);
    let signature: p256::ecdsa::Signature = signing.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// A fresh salt for an export: 16 random bytes, base64.
pub fn export_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    bitwarden_encoding::B64::from(bytes.to_vec()).to_string()
}

/// A browser extension's pairing key (docs/NATIVE_MESSAGING.md).
pub struct PairKey(Zeroizing<[u8; 32]>);

/// This side of a new pairing: the public key to send back, the shared key, and the
/// six-digit code both sides show so the user can confirm them.
pub struct Paired {
    pub public: [u8; 32],
    pub key: PairKey,
    pub code: String,
}

// Protocol constants from before the rename: changing them would unpair every browser.
const PAIR_INFO: &[u8] = b"nixe-passwords pair v1";
const CODE_INFO: &[u8] = b"nixe-passwords code v1";
const NONCE: usize = 12;

/// Answers an extension's X25519 public key: `salt = theirs ‖ ours`,
/// `key = HKDF(…, "nixe-passwords pair v1")`, `code = HKDF(…, "nixe-passwords code v1")`
/// read as a big-endian u32, mod 1 000 000. A low-order point is refused.
pub fn pair(their_public: &[u8]) -> Result<Paired> {
    let theirs: [u8; 32] = their_public.try_into().map_err(|_| CryptoError::Malformed)?;
    let theirs = x25519_dalek::PublicKey::from(theirs);
    let secret = x25519_dalek::EphemeralSecret::random();
    let public = x25519_dalek::PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&theirs);
    if !shared.was_contributory() {
        return Err(CryptoError::Malformed);
    }
    let (key, code) = derive_pairing(shared.as_bytes(), theirs.as_bytes(), public.as_bytes())?;
    Ok(Paired { public: public.to_bytes(), key, code })
}

/// The pairing key and code from the X25519 shared secret and both public keys
/// (the extension's first). apps/passwords/browser/test/pairing-vector.mjs does the same
/// in WebCrypto; a test below holds both to one vector.
fn derive_pairing(shared: &[u8; 32], extension: &[u8; 32], daemon: &[u8; 32]) -> Result<(PairKey, String)> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(extension);
    salt[32..].copy_from_slice(daemon);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(PAIR_INFO, &mut *key).map_err(|_| CryptoError::Encrypt)?;
    let mut code = [0u8; 4];
    hk.expand(CODE_INFO, &mut code).map_err(|_| CryptoError::Encrypt)?;
    Ok((PairKey(key), format!("{:06}", u32::from_be_bytes(code) % 1_000_000)))
}

impl PairKey {
    /// `nonce ‖ AES-256-GCM(plain, aad)` with a random 96-bit nonce.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&*self.0).map_err(|_| CryptoError::Encrypt)?;
        let mut nonce = [0u8; NONCE];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);
        let sealed = cipher.encrypt(&nonce.into(), Payload { msg: plain, aad }).map_err(|_| CryptoError::Encrypt)?;
        Ok([&nonce[..], &sealed].concat())
    }

    /// The plaintext of `seal`'s output; fails on any change to it or to `aad`.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<SecretBytes> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        if sealed.len() < NONCE + 16 {
            return Err(CryptoError::Malformed);
        }
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&*self.0).map_err(|_| CryptoError::Decrypt)?;
        let (nonce, body) = sealed.split_at(NONCE);
        let nonce: [u8; NONCE] = nonce.try_into().map_err(|_| CryptoError::Malformed)?;
        cipher.decrypt(&nonce.into(), Payload { msg: body, aad }).map(SecretBytes::new).map_err(|_| CryptoError::Decrypt)
    }

    /// For storing (encrypted with the user key) and reading back.
    pub fn export(&self) -> Secret {
        Secret::new(bitwarden_encoding::B64::from(self.0.to_vec()).to_string())
    }

    pub fn import(stored: &Secret) -> Result<PairKey> {
        let bytes = bitwarden_encoding::B64::try_from(stored.expose()).map_err(|_| CryptoError::Malformed)?;
        let key: [u8; 32] = bytes.as_bytes().try_into().map_err(|_| CryptoError::Malformed)?;
        Ok(PairKey(Zeroizing::new(key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_agrees_and_seals() {
        let ext_secret = x25519_dalek::StaticSecret::random();
        let ext_public = x25519_dalek::PublicKey::from(&ext_secret);
        let paired = pair(ext_public.as_bytes()).unwrap();
        // The extension derives the same key and code.
        let shared = ext_secret.diffie_hellman(&x25519_dalek::PublicKey::from(paired.public));
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(ext_public.as_bytes());
        salt[32..].copy_from_slice(&paired.public);
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(PAIR_INFO, &mut key).unwrap();
        let mut code = [0u8; 4];
        hk.expand(CODE_INFO, &mut code).unwrap();
        assert_eq!(format!("{:06}", u32::from_be_bytes(code) % 1_000_000), paired.code);
        let theirs = PairKey(Zeroizing::new(key));

        let sealed = paired.key.seal(b"p1|7", b"{\"t\":\"status\"}").unwrap();
        assert_eq!(theirs.open(b"p1|7", &sealed).unwrap().expose(), b"{\"t\":\"status\"}");
        // Another aad (a replayed counter) or a flipped bit fails.
        assert_eq!(theirs.open(b"p1|8", &sealed).err(), Some(CryptoError::Decrypt));
        let mut bent = sealed.clone();
        bent[20] ^= 1;
        assert_eq!(theirs.open(b"p1|7", &bent).err(), Some(CryptoError::Decrypt));
        assert_eq!(theirs.open(b"p1|7", &sealed[..10]).err(), Some(CryptoError::Malformed));
        // Two seals of the same message differ (fresh nonces).
        assert_ne!(paired.key.seal(b"a", b"x").unwrap(), paired.key.seal(b"a", b"x").unwrap());
        // Storage round trip.
        let back = PairKey::import(&paired.key.export()).unwrap();
        assert_eq!(back.open(b"p1|7", &sealed).unwrap().expose(), b"{\"t\":\"status\"}");
    }

    /// The same vector as apps/passwords/browser/test/pairing-vector.mjs (WebCrypto).
    #[test]
    fn pairing_matches_webcrypto() {
        let ext: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let daemon: [u8; 32] = std::array::from_fn(|i| i as u8 + 33);
        let ext_secret = x25519_dalek::StaticSecret::from(ext);
        let daemon_secret = x25519_dalek::StaticSecret::from(daemon);
        let ext_public = x25519_dalek::PublicKey::from(&ext_secret);
        let daemon_public = x25519_dalek::PublicKey::from(&daemon_secret);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(ext_public.as_bytes()), "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
        assert_eq!(hex(daemon_public.as_bytes()), "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b");
        let shared = daemon_secret.diffie_hellman(&ext_public);
        let (key, code) = derive_pairing(shared.as_bytes(), ext_public.as_bytes(), daemon_public.as_bytes()).unwrap();
        assert_eq!(hex(&*key.0), "6d901307a3ed370eeb7ab8620e7eeaa9bf4b62e8ede14fe720daee41de4fb16b");
        assert_eq!(code, "538653");
    }

    #[test]
    fn low_order_points_are_refused() {
        assert_eq!(pair(&[0u8; 32]).err(), Some(CryptoError::Malformed));
        assert_eq!(pair(&[1u8; 31]).err(), Some(CryptoError::Malformed));
    }

    #[test]
    fn kdf_limits() {
        assert!(Kdf::from_server(0, 600_000, None, None).is_ok());
        assert_eq!(Kdf::from_server(0, 3_000_000, None, None), Err(CryptoError::KdfParameters));
        assert!(Kdf::from_server(1, 3, Some(64), Some(4)).is_ok());
        assert_eq!(Kdf::from_server(1, 3, Some(4096), Some(4)), Err(CryptoError::KdfParameters));
        assert_eq!(Kdf::from_server(1, 3, None, Some(4)), Err(CryptoError::KdfParameters));
        assert_eq!(Kdf::from_server(7, 3, None, None), Err(CryptoError::KdfParameters));
        // Too weak for bitwarden-crypto: rejected when deriving.
        let weak = Kdf::from_server(0, 1000, None, None).unwrap();
        assert!(MasterKey::derive(&Secret::new("pw"), "a@b.c", &weak).is_err());
    }

    #[test]
    fn kdf_downgrade() {
        let strong = Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        assert!(strong.at_least(&Kdf::Pbkdf2 { iterations: 600_000 }));
        assert!(!Kdf::Pbkdf2 { iterations: 600_000 }.at_least(&strong));
        assert!(!Kdf::Argon2id { iterations: 3, memory_mib: 32, parallelism: 4 }.at_least(&strong));
        assert!(!Kdf::Pbkdf2 { iterations: 100_000 }.at_least(&Kdf::Pbkdf2 { iterations: 600_000 }));
    }

    #[test]
    fn checksum_is_base64_sha256() {
        assert_eq!(uri_checksum("https://example.com").expose(), "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=");
    }
}
