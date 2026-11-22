//! Secret bundles and their XChaCha20-Poly1305 encryption in
//! `.scrim/secrets/<scope>.enc`.
//!
//! The plaintext is a canonical JSON object of secret names to values. The
//! associated data is `"scrim-secrets-v1\n<scope>\n<generation>"`, so a
//! ciphertext only decrypts under the scope and generation it was written for.

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::validation::{validate_generation, validate_scope_name, validate_version};
use crate::{
    CryptoError, FILE_FORMAT_VERSION, MAX_SECRET_VALUE_BYTES, MAX_SECRETS_PER_SCOPE, ScopeDataKey,
    validate_secret_key,
};

/// XChaCha20-Poly1305 nonce length, in bytes.
const NONCE_BYTES: usize = 24;
/// Poly1305 tag length, in bytes.
const TAG_BYTES: usize = 16;

/// A scope's secrets, keyed by environment-variable-style names.
///
/// Every entry is validated on insertion, so a bundle always satisfies the
/// name, size and count limits. `Debug` lists key names only, never values.
#[derive(Default)]
pub struct SecretBundle(BTreeMap<String, SecretString>);

impl SecretBundle {
    /// Creates an empty bundle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of secrets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the bundle holds no secrets.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the value stored under `key`.
    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.0.get(key)
    }

    /// Stores `value` under `key`, returning the previous value.
    ///
    /// # Errors
    ///
    /// Fails if `key` is invalid (see [`validate_secret_key`]), `value` is
    /// larger than [`MAX_SECRET_VALUE_BYTES`], or a new key would exceed
    /// [`MAX_SECRETS_PER_SCOPE`]. The bundle is unchanged on error.
    pub fn set(
        &mut self,
        key: &str,
        value: SecretString,
    ) -> Result<Option<SecretString>, CryptoError> {
        if let Err(error) = validate_entry(key, &value) {
            return Err(error);
        }
        let is_new_key = !self.0.contains_key(key);
        if is_new_key && self.0.len() >= MAX_SECRETS_PER_SCOPE {
            return Err(CryptoError::TooManySecrets {
                max: MAX_SECRETS_PER_SCOPE,
            });
        }
        Ok(self.0.insert(key.to_owned(), value))
    }

    /// Removes and returns the value stored under `key`.
    pub fn remove(&mut self, key: &str) -> Option<SecretString> {
        self.0.remove(key)
    }

    /// Secret names in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Secrets in ascending key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &SecretString)> {
        self.0.iter().map(|(key, value)| (key.as_str(), value))
    }
}

impl fmt::Debug for SecretBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBundle")
            .field("keys", &self.0.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

/// Validates one secret's name and value size.
fn validate_entry(key: &str, value: &SecretString) -> Result<(), CryptoError> {
    if let Err(error) = validate_secret_key(key) {
        return Err(error);
    }
    if value.expose_secret().len() > MAX_SECRET_VALUE_BYTES {
        return Err(CryptoError::SecretValueTooLarge {
            key: key.to_owned(),
            max_bytes: MAX_SECRET_VALUE_BYTES,
        });
    }
    Ok(())
}

/// Contents of `.scrim/secrets/<scope>.enc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecretsFile {
    /// File format version; must be [`FILE_FORMAT_VERSION`].
    pub version: u32,
    /// Scope the secrets belong to.
    pub scope: String,
    /// Generation of the scope data key that encrypted the secrets.
    pub generation: u64,
    /// Standard base64 of the random 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Standard base64 of the ciphertext followed by the 16-byte tag.
    pub ciphertext: String,
}

impl EncryptedSecretsFile {
    /// Encrypts `secrets` under `data_key` with a fresh random nonce, bound to
    /// `scope` and `generation` through the associated data.
    ///
    /// # Errors
    ///
    /// Fails on an invalid scope, generation 0, an invalid secret, an RNG
    /// failure, or an encryption failure.
    pub fn encrypt(
        scope: &str,
        generation: u64,
        data_key: &ScopeDataKey,
        secrets: &SecretBundle,
    ) -> Result<Self, CryptoError> {
        if let Err(error) = validate_scope_name(scope) {
            return Err(error);
        }
        if let Err(error) = validate_generation(generation) {
            return Err(error);
        }
        if secrets.len() > MAX_SECRETS_PER_SCOPE {
            return Err(CryptoError::TooManySecrets {
                max: MAX_SECRETS_PER_SCOPE,
            });
        }
        for (key, value) in secrets.iter() {
            if let Err(error) = validate_entry(key, value) {
                return Err(error);
            }
        }
        let plaintext = match serialize_secrets(secrets) {
            Ok(plaintext) => plaintext,
            Err(error) => return Err(error),
        };
        let mut nonce = [0_u8; NONCE_BYTES];
        if let Err(error) = getrandom::fill(&mut nonce) {
            return Err(CryptoError::Random(error.to_string()));
        }
        let cipher = match XChaCha20Poly1305::new_from_slice(data_key.as_bytes()) {
            Ok(cipher) => cipher,
            Err(error) => return Err(CryptoError::Encryption(error.to_string())),
        };
        let aad = associated_data(scope, generation);
        let payload = Payload {
            msg: &plaintext,
            aad: aad.as_bytes(),
        };
        let ciphertext = match cipher.encrypt(&XNonce::from(nonce), payload) {
            Ok(ciphertext) => ciphertext,
            Err(error) => return Err(CryptoError::Encryption(error.to_string())),
        };
        Ok(Self {
            version: FILE_FORMAT_VERSION,
            scope: scope.to_owned(),
            generation,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
    }

    /// Decrypts the secrets, checking that the file belongs to
    /// `expected_scope` at `expected_generation`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecryptionFailed`] when authentication fails
    /// (wrong key, or tampered ciphertext, nonce, scope or generation), and
    /// version, scope, generation, encoding or payload errors otherwise.
    pub fn decrypt(
        &self,
        expected_scope: &str,
        expected_generation: u64,
        data_key: &ScopeDataKey,
    ) -> Result<SecretBundle, CryptoError> {
        if let Err(error) = validate_version(self.version) {
            return Err(error);
        }
        if self.scope != expected_scope {
            return Err(CryptoError::ScopeMismatch {
                expected: expected_scope.to_owned(),
                found: self.scope.clone(),
            });
        }
        if self.generation != expected_generation {
            return Err(CryptoError::GenerationMismatch {
                expected: expected_generation,
                found: self.generation,
            });
        }
        if let Err(error) = validate_generation(self.generation) {
            return Err(error);
        }
        let (nonce, ciphertext) = match self.decode_fields() {
            Ok(fields) => fields,
            Err(error) => return Err(error),
        };
        let cipher = match XChaCha20Poly1305::new_from_slice(data_key.as_bytes()) {
            Ok(cipher) => cipher,
            Err(_) => return Err(CryptoError::DecryptionFailed),
        };
        let aad = associated_data(&self.scope, self.generation);
        let payload = Payload {
            msg: &ciphertext,
            aad: aad.as_bytes(),
        };
        let plaintext = match cipher.decrypt(&XNonce::from(nonce), payload) {
            Ok(plaintext) => Zeroizing::new(plaintext),
            Err(_) => return Err(CryptoError::DecryptionFailed),
        };
        parse_secrets(&plaintext)
    }

    /// Serializes the file as TOML.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Serialization`] if TOML encoding fails.
    pub fn to_toml_string(&self) -> Result<String, CryptoError> {
        match toml::to_string(self) {
            Ok(text) => Ok(text),
            Err(error) => Err(CryptoError::Serialization(error.to_string())),
        }
    }

    /// Parses and validates a secrets file: version, scope name, generation,
    /// a 24-byte nonce and a ciphertext at least as long as the tag.
    ///
    /// # Errors
    ///
    /// Returns the [`CryptoError`] for the first problem found.
    pub fn from_toml_str(input: &str) -> Result<Self, CryptoError> {
        let file: Self = match toml::from_str(input) {
            Ok(file) => file,
            Err(error) => return Err(CryptoError::InvalidToml(error.to_string())),
        };
        if let Err(error) = validate_version(file.version) {
            return Err(error);
        }
        if let Err(error) = validate_scope_name(&file.scope) {
            return Err(error);
        }
        if let Err(error) = validate_generation(file.generation) {
            return Err(error);
        }
        if let Err(error) = file.decode_fields() {
            return Err(error);
        }
        Ok(file)
    }

    /// Decodes the base64 nonce and ciphertext, checking their lengths.
    fn decode_fields(&self) -> Result<([u8; NONCE_BYTES], Vec<u8>), CryptoError> {
        let nonce_bytes = match BASE64.decode(&self.nonce) {
            Ok(bytes) => bytes,
            Err(_) => return Err(CryptoError::InvalidEncoding { field: "nonce" }),
        };
        let nonce: [u8; NONCE_BYTES] = match nonce_bytes.try_into() {
            Ok(nonce) => nonce,
            Err(_) => return Err(CryptoError::InvalidEncoding { field: "nonce" }),
        };
        let ciphertext = match BASE64.decode(&self.ciphertext) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(CryptoError::InvalidEncoding {
                    field: "ciphertext",
                });
            }
        };
        if ciphertext.len() < TAG_BYTES {
            return Err(CryptoError::InvalidEncoding {
                field: "ciphertext",
            });
        }
        Ok((nonce, ciphertext))
    }
}

/// Associated data binding the format version, scope and generation.
fn associated_data(scope: &str, generation: u64) -> String {
    format!("scrim-secrets-v1\n{scope}\n{generation}")
}

/// Counts bytes written, to size the JSON buffer exactly before serializing.
struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serializes the bundle as a canonical (sorted, compact) JSON object.
fn serialize_secrets(secrets: &SecretBundle) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let exposed: BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(key, value)| (key, value.expose_secret()))
        .collect();
    // Serialize twice: first to measure, then into an exactly sized buffer, so
    // the buffer never reallocates and leaves unzeroized copies behind.
    let mut counter = ByteCounter(0);
    if let Err(error) = serde_json::to_writer(&mut counter, &exposed) {
        return Err(CryptoError::Serialization(error.to_string()));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(counter.0));
    match serde_json::to_writer(&mut *plaintext, &exposed) {
        Ok(()) => Ok(plaintext),
        Err(error) => Err(CryptoError::Serialization(error.to_string())),
    }
}

/// Parses decrypted JSON into a validated bundle, zeroizing the parsed
/// intermediate strings.
fn parse_secrets(plaintext: &[u8]) -> Result<SecretBundle, CryptoError> {
    let mut parsed: BTreeMap<String, String> = match serde_json::from_slice(plaintext) {
        Ok(parsed) => parsed,
        Err(_) => return Err(CryptoError::MalformedSecretsPayload),
    };
    let mut bundle = SecretBundle::new();
    let mut result = Ok(());
    for (key, value) in &mut parsed {
        // Copy into a fresh secret allocation; the parsed String is zeroized
        // below instead of being shrunk (which could leave a stray copy).
        if let Err(error) = bundle.set(key, SecretString::from(value.as_str())) {
            result = Err(error);
            break;
        }
    }
    for value in parsed.values_mut() {
        value.zeroize();
    }
    match result {
        Ok(()) => Ok(bundle),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scope_key::tests::data_key;

    /// Predicate recognising the expected error in table-driven tests.
    type ErrorCheck = fn(&CryptoError) -> bool;

    pub(crate) fn bundle(entries: &[(&str, &str)]) -> SecretBundle {
        let mut bundle = SecretBundle::new();
        for (key, value) in entries {
            if let Err(error) = bundle.set(key, SecretString::from(*value)) {
                panic!("{key:?} should be accepted: {error}");
            }
        }
        bundle
    }

    pub(crate) fn exposed(bundle: &SecretBundle) -> Vec<(String, String)> {
        bundle
            .iter()
            .map(|(key, value)| (key.to_owned(), value.expose_secret().to_owned()))
            .collect()
    }

    fn encrypt(
        scope: &str,
        generation: u64,
        key: &ScopeDataKey,
        secrets: &SecretBundle,
    ) -> EncryptedSecretsFile {
        match EncryptedSecretsFile::encrypt(scope, generation, key, secrets) {
            Ok(file) => file,
            Err(error) => panic!("encryption should succeed: {error}"),
        }
    }

    fn expect_decryption_failure(
        file: &EncryptedSecretsFile,
        scope: &str,
        generation: u64,
        key: &ScopeDataKey,
    ) {
        match file.decrypt(scope, generation, key) {
            Err(CryptoError::DecryptionFailed) => {}
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    fn flip_first_bit(base64_text: &str) -> String {
        let mut bytes = match BASE64.decode(base64_text) {
            Ok(bytes) => bytes,
            Err(error) => panic!("field should be base64: {error}"),
        };
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x01;
        }
        BASE64.encode(bytes)
    }

    #[test]
    fn bundle_debug_never_shows_values() {
        let secrets = bundle(&[("API_TOKEN", "hunter2-super-secret")]);
        let debug = format!("{secrets:?}");
        assert!(debug.contains("API_TOKEN"));
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn bundle_set_validates_and_replaces() {
        let mut secrets = bundle(&[("A", "1")]);
        match secrets.set("A", SecretString::from("2")) {
            Ok(Some(previous)) => assert_eq!(previous.expose_secret(), "1"),
            other => panic!("expected previous value, got {other:?}"),
        }
        match secrets.set("BAD-KEY", SecretString::from("x")) {
            Err(CryptoError::InvalidSecretKey { .. }) => {}
            other => panic!("expected InvalidSecretKey, got {other:?}"),
        }
        let huge = "x".repeat(MAX_SECRET_VALUE_BYTES + 1);
        match secrets.set("HUGE", SecretString::from(huge)) {
            Err(CryptoError::SecretValueTooLarge { .. }) => {}
            other => panic!("expected SecretValueTooLarge, got {other:?}"),
        }
        assert_eq!(secrets.keys().collect::<Vec<_>>(), ["A"]);
        assert!(secrets.remove("A").is_some());
        assert!(secrets.is_empty());
    }

    #[test]
    fn bundle_enforces_secret_count_limit() {
        let mut secrets = SecretBundle::new();
        for index in 0..MAX_SECRETS_PER_SCOPE {
            if let Err(error) = secrets.set(&format!("K{index}"), SecretString::from("v")) {
                panic!("secret {index} should fit: {error}");
            }
        }
        match secrets.set("ONE_TOO_MANY", SecretString::from("v")) {
            Err(CryptoError::TooManySecrets { .. }) => {}
            other => panic!("expected TooManySecrets, got {other:?}"),
        }
        // Replacing an existing key is still allowed at the limit.
        if let Err(error) = secrets.set("K0", SecretString::from("w")) {
            panic!("replacing should succeed: {error}");
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip_through_toml() {
        let key = data_key();
        let secrets = bundle(&[
            ("DATABASE_URL", "postgres://user:p@ss@db/app"),
            ("EMPTY", ""),
            ("MULTILINE", "line one\nline \"two\"\n"),
            ("UNICODE", "pässwörd 🔑"),
        ]);
        let file = encrypt("dev", 2, &key, &secrets);
        let text = match file.to_toml_string() {
            Ok(text) => text,
            Err(error) => panic!("serialization should succeed: {error}"),
        };
        assert!(!text.contains("postgres"));
        let parsed = match EncryptedSecretsFile::from_toml_str(&text) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parsing should succeed: {error}"),
        };
        assert_eq!(parsed, file);
        match parsed.decrypt("dev", 2, &key) {
            Ok(decrypted) => assert_eq!(exposed(&decrypted), exposed(&secrets)),
            Err(error) => panic!("decryption should succeed: {error}"),
        }
    }

    #[test]
    fn every_encryption_uses_a_fresh_nonce() {
        let key = data_key();
        let secrets = bundle(&[("A", "1")]);
        let first = encrypt("dev", 1, &key, &secrets);
        let second = encrypt("dev", 1, &key, &secrets);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let file = encrypt("dev", 1, &data_key(), &bundle(&[("A", "1")]));
        expect_decryption_failure(&file, "dev", 1, &data_key());
    }

    #[test]
    fn ciphertext_copied_across_scopes_or_generations_fails() {
        let key = data_key();
        let file = encrypt("dev", 1, &key, &bundle(&[("A", "1")]));

        // Relabelled to look like prod (same key reused by mistake/attack).
        let mut as_prod = file.clone();
        as_prod.scope = "prod".to_owned();
        expect_decryption_failure(&as_prod, "prod", 1, &key);

        // Generation edited forward or back.
        let mut bumped = file.clone();
        bumped.generation = 2;
        expect_decryption_failure(&bumped, "dev", 2, &key);

        // A caller expecting another scope or generation is refused upfront.
        match file.decrypt("prod", 1, &key) {
            Err(CryptoError::ScopeMismatch { .. }) => {}
            other => panic!("expected ScopeMismatch, got {other:?}"),
        }
        match file.decrypt("dev", 2, &key) {
            Err(CryptoError::GenerationMismatch { .. }) => {}
            other => panic!("expected GenerationMismatch, got {other:?}"),
        }
    }

    #[test]
    fn bit_flips_in_ciphertext_or_nonce_fail_authentication() {
        let key = data_key();
        let file = encrypt("dev", 1, &key, &bundle(&[("A", "1")]));
        let mut flipped_ciphertext = file.clone();
        flipped_ciphertext.ciphertext = flip_first_bit(&file.ciphertext);
        expect_decryption_failure(&flipped_ciphertext, "dev", 1, &key);
        let mut flipped_nonce = file.clone();
        flipped_nonce.nonce = flip_first_bit(&file.nonce);
        expect_decryption_failure(&flipped_nonce, "dev", 1, &key);
    }

    #[test]
    fn malformed_files_are_rejected() {
        let file = encrypt("dev", 1, &data_key(), &bundle(&[("A", "1")]));
        let mut short_nonce = file.clone();
        short_nonce.nonce = BASE64.encode([0_u8; 12]);
        let mut short_ciphertext = file.clone();
        short_ciphertext.ciphertext = BASE64.encode([0_u8; 4]);
        let mut bad_version = file.clone();
        bad_version.version = 0;
        let mut bad_scope = file.clone();
        bad_scope.scope = ".hidden".to_owned();
        let mut bad_generation = file.clone();
        bad_generation.generation = 0;
        let cases: [(EncryptedSecretsFile, ErrorCheck); 5] = [
            (short_nonce, |e| {
                matches!(e, CryptoError::InvalidEncoding { field: "nonce" })
            }),
            (short_ciphertext, |e| {
                matches!(
                    e,
                    CryptoError::InvalidEncoding {
                        field: "ciphertext"
                    }
                )
            }),
            (bad_version, |e| {
                matches!(e, CryptoError::UnsupportedVersion { found: 0 })
            }),
            (bad_scope, |e| {
                matches!(e, CryptoError::InvalidScopeName { .. })
            }),
            (bad_generation, |e| {
                matches!(e, CryptoError::InvalidGeneration)
            }),
        ];
        for (case, is_expected) in cases {
            let text = match case.to_toml_string() {
                Ok(text) => text,
                Err(error) => panic!("serialization should succeed: {error}"),
            };
            match EncryptedSecretsFile::from_toml_str(&text) {
                Err(error) if is_expected(&error) => {}
                other => panic!("unexpected result for {case:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn decrypted_payload_with_invalid_keys_is_rejected() {
        match parse_secrets(br#"{"BAD-KEY":"x"}"#) {
            Err(CryptoError::InvalidSecretKey { .. }) => {}
            other => panic!("expected InvalidSecretKey, got {other:?}"),
        }
        match parse_secrets(br#"{"A":1}"#) {
            Err(CryptoError::MalformedSecretsPayload) => {}
            other => panic!("expected MalformedSecretsPayload, got {other:?}"),
        }
    }

    #[test]
    fn serialized_payload_is_canonical_json() {
        let secrets = bundle(&[("B", "2"), ("A", "1\n")]);
        match serialize_secrets(&secrets) {
            Ok(json) => assert_eq!(json.as_slice(), br#"{"A":"1\n","B":"2"}"#),
            Err(error) => panic!("serialization should succeed: {error}"),
        }
    }
}
