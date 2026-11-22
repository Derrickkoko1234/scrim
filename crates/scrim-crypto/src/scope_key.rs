//! Per-scope data keys and their per-member wrapping in
//! `.scrim/keys/<scope>.toml`.
//!
//! The `age` plaintext for each recipient is not the bare data key but a
//! domain-bound payload:
//!
//! ```text
//! "scrim-scope-key-v1\n" || scope || "\n" || generation (decimal) || "\n" || key[32]
//! ```
//!
//! Unwrapping checks the scope and generation inside the ciphertext, so a
//! wrapped key copied from `dev.toml` into `prod.toml`, or an older
//! generation's blob, is rejected even though `age` decrypts it.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::iter;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::validation::{validate_generation, validate_scope_name, validate_version};
use crate::{
    CryptoError, FILE_FORMAT_VERSION, MAX_SCOPE_NAME_BYTES, MemberIdentity, MemberPublicKey,
};

/// Length of a scope data key, in bytes.
const DATA_KEY_BYTES: usize = 32;

/// Domain-separation prefix of every wrapped-key payload.
const WRAPPED_KEY_DOMAIN: &[u8] = b"scrim-scope-key-v1\n";

/// Upper bound on a well-formed wrapped-key payload: domain, longest scope,
/// newline, the 20 digits of `u64::MAX`, newline and the key itself. Reads stop
/// one byte past it so oversized payloads are detected without buffering them.
const MAX_WRAPPED_PAYLOAD_BYTES: usize =
    WRAPPED_KEY_DOMAIN.len() + MAX_SCOPE_NAME_BYTES + 1 + 20 + 1 + DATA_KEY_BYTES;

/// A random 256-bit key that encrypts one scope's secrets for one generation.
///
/// The bytes are zeroized on drop and never appear in `Debug` output.
pub struct ScopeDataKey(Zeroizing<[u8; DATA_KEY_BYTES]>);

impl ScopeDataKey {
    /// Generates a fresh key from the operating system's RNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Random`] if the RNG fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Zeroizing::new([0_u8; DATA_KEY_BYTES]);
        match getrandom::fill(key.as_mut_slice()) {
            Ok(()) => Ok(Self(key)),
            Err(error) => Err(CryptoError::Random(error.to_string())),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8; DATA_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ScopeDataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeDataKey([REDACTED])")
    }
}

/// One member's copy of a scope data key, wrapped to their public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedRecipientKey {
    /// Member name, unique within the file.
    pub member: String,
    /// The member's canonical `age1...` public key.
    pub public_key: String,
    /// Standard base64 of the binary `age` ciphertext of the domain-bound
    /// key payload.
    pub wrapped_key: String,
}

/// Contents of `.scrim/keys/<scope>.toml`: one scope data key wrapped for
/// every member allowed to read the scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeKeysFile {
    /// File format version; must be [`FILE_FORMAT_VERSION`].
    pub version: u32,
    /// Scope the key belongs to.
    pub scope: String,
    /// Key generation, starting at 1 and incremented on every rotation.
    pub generation: u64,
    /// Wrapped copies of the key, sorted by member name for stable diffs.
    pub recipients: Vec<WrappedRecipientKey>,
}

impl ScopeKeysFile {
    /// Wraps `data_key` for each recipient, bound to `scope` and `generation`.
    ///
    /// Recipients come out sorted by member name (the `BTreeMap` order).
    ///
    /// # Errors
    ///
    /// Fails on an invalid scope, generation 0, an empty recipient map, or an
    /// `age` encryption error.
    pub fn wrap_for_recipients(
        scope: &str,
        generation: u64,
        data_key: &ScopeDataKey,
        recipients: &BTreeMap<String, MemberPublicKey>,
    ) -> Result<Self, CryptoError> {
        if let Err(error) = validate_scope_name(scope) {
            return Err(error);
        }
        if let Err(error) = validate_generation(generation) {
            return Err(error);
        }
        if recipients.is_empty() {
            return Err(CryptoError::NoRecipients);
        }
        let payload =
            build_bound_payload(WRAPPED_KEY_DOMAIN, scope, generation, data_key.as_bytes());
        let wrapped = match wrap_payload_for_recipients(&payload, recipients) {
            Ok(wrapped) => wrapped,
            Err(error) => return Err(error),
        };
        Ok(Self {
            version: FILE_FORMAT_VERSION,
            scope: scope.to_owned(),
            generation,
            recipients: wrapped,
        })
    }

    /// Recovers the data key with `identity`, checking that this file and the
    /// encrypted payload are both bound to `expected_scope` and this file's
    /// generation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unauthorized`] when no recipient entry matches
    /// the identity's public key or `age` decryption fails, and
    /// [`CryptoError::WrappedKeyMismatch`] when the decrypted payload belongs
    /// to another scope or generation. Version, scope and generation problems
    /// in the file itself are reported before any decryption.
    pub fn unwrap_key(
        &self,
        expected_scope: &str,
        identity: &MemberIdentity,
    ) -> Result<ScopeDataKey, CryptoError> {
        if let Err(error) = validate_version(self.version) {
            return Err(error);
        }
        if self.scope != expected_scope {
            return Err(CryptoError::ScopeMismatch {
                expected: expected_scope.to_owned(),
                found: self.scope.clone(),
            });
        }
        if let Err(error) = validate_generation(self.generation) {
            return Err(error);
        }
        let payload = match decrypt_recipient_payload(
            &self.recipients,
            identity,
            MAX_WRAPPED_PAYLOAD_BYTES,
        ) {
            Ok(payload) => payload,
            Err(error) => return Err(error),
        };
        let Some(key_bytes) = strip_bound_payload(
            &payload,
            WRAPPED_KEY_DOMAIN,
            expected_scope,
            self.generation,
        ) else {
            return Err(CryptoError::WrappedKeyMismatch);
        };
        let mut key = Zeroizing::new([0_u8; DATA_KEY_BYTES]);
        if key_bytes.len() != key.len() {
            return Err(CryptoError::WrappedKeyMismatch);
        }
        key.copy_from_slice(key_bytes);
        Ok(ScopeDataKey(key))
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

    /// Parses and validates a keys file.
    ///
    /// Checks the version, scope name, generation, that recipients exist and
    /// have unique member names, that every public key is canonical `age1...`
    /// and every wrapped key is valid base64. Recipients are returned sorted
    /// by member name.
    ///
    /// # Errors
    ///
    /// Returns the [`CryptoError`] for the first problem found.
    pub fn from_toml_str(input: &str) -> Result<Self, CryptoError> {
        let mut file: Self = match toml::from_str(input) {
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
        match sort_and_validate_recipients(&mut file.recipients) {
            Ok(()) => Ok(file),
            Err(error) => Err(error),
        }
    }

    /// Returns each member's parsed public key, for re-wrapping a new key to
    /// the same recipients during rotation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPublicKey`] or
    /// [`CryptoError::DuplicateMember`] for a malformed recipient list.
    pub fn recipient_public_keys(&self) -> Result<BTreeMap<String, MemberPublicKey>, CryptoError> {
        parse_recipient_public_keys(&self.recipients)
    }
}

/// Builds the domain-bound plaintext that `age` wraps for each recipient:
/// `domain || name || "\n" || generation (decimal) || "\n" || key`.
pub(crate) fn build_bound_payload(
    domain: &[u8],
    name: &str,
    generation: u64,
    key: &[u8],
) -> Zeroizing<Vec<u8>> {
    let generation_text = generation.to_string();
    let mut payload = Zeroizing::new(Vec::with_capacity(
        domain.len() + name.len() + 1 + generation_text.len() + 1 + key.len(),
    ));
    payload.extend_from_slice(domain);
    payload.extend_from_slice(name.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(generation_text.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(key);
    payload
}

/// Checks the domain, name and generation of a decrypted payload built by
/// [`build_bound_payload`] and returns the trailing key bytes, or `None` if
/// any part does not match.
pub(crate) fn strip_bound_payload<'payload>(
    payload: &'payload [u8],
    domain: &[u8],
    expected_name: &str,
    expected_generation: u64,
) -> Option<&'payload [u8]> {
    let Some(rest) = payload.strip_prefix(domain) else {
        return None;
    };
    let Some(rest) = rest.strip_prefix(expected_name.as_bytes()) else {
        return None;
    };
    let Some(rest) = rest.strip_prefix(b"\n") else {
        return None;
    };
    let Some(rest) = rest.strip_prefix(expected_generation.to_string().as_bytes()) else {
        return None;
    };
    rest.strip_prefix(b"\n")
}

/// Encrypts `payload` with `age` to every recipient, in member-name order.
pub(crate) fn wrap_payload_for_recipients(
    payload: &[u8],
    recipients: &BTreeMap<String, MemberPublicKey>,
) -> Result<Vec<WrappedRecipientKey>, CryptoError> {
    let mut wrapped = Vec::with_capacity(recipients.len());
    for (member, public_key) in recipients {
        let ciphertext = match age::encrypt(public_key.as_age_recipient(), payload) {
            Ok(ciphertext) => ciphertext,
            Err(error) => return Err(CryptoError::Encryption(error.to_string())),
        };
        wrapped.push(WrappedRecipientKey {
            member: member.clone(),
            public_key: public_key.as_str().to_owned(),
            wrapped_key: BASE64.encode(ciphertext),
        });
    }
    Ok(wrapped)
}

/// Finds the entry wrapped to `identity`'s public key and decrypts it,
/// reading at most `max_payload_bytes + 1` bytes.
///
/// Returns [`CryptoError::Unauthorized`] when no entry matches or the entry
/// does not decrypt.
pub(crate) fn decrypt_recipient_payload(
    recipients: &[WrappedRecipientKey],
    identity: &MemberIdentity,
    max_payload_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let public_key = identity.public_key();
    let Some(entry) = recipients
        .iter()
        .find(|entry| entry.public_key == public_key.as_str())
    else {
        return Err(CryptoError::Unauthorized);
    };
    let ciphertext = match BASE64.decode(&entry.wrapped_key) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(CryptoError::Unauthorized),
    };
    match decrypt_wrapped_payload(&ciphertext, identity, max_payload_bytes) {
        Some(payload) => Ok(payload),
        None => Err(CryptoError::Unauthorized),
    }
}

/// Validates a parsed recipient list in place: non-empty, sorted by member
/// name with no duplicates, canonical `age1...` keys and base64 wrapped keys.
pub(crate) fn sort_and_validate_recipients(
    recipients: &mut [WrappedRecipientKey],
) -> Result<(), CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    recipients.sort_by(|left, right| left.member.cmp(&right.member));
    for pair in recipients.windows(2) {
        if let [left, right] = pair
            && left.member == right.member
        {
            return Err(CryptoError::DuplicateMember {
                member: right.member.clone(),
            });
        }
    }
    for entry in recipients.iter() {
        if let Err(error) = MemberPublicKey::parse(&entry.public_key) {
            return Err(error);
        }
        if BASE64.decode(&entry.wrapped_key).is_err() {
            return Err(CryptoError::InvalidEncoding {
                field: "wrapped_key",
            });
        }
    }
    Ok(())
}

/// Parses each recipient's public key, rejecting duplicate member names.
pub(crate) fn parse_recipient_public_keys(
    recipients: &[WrappedRecipientKey],
) -> Result<BTreeMap<String, MemberPublicKey>, CryptoError> {
    let mut keys = BTreeMap::new();
    for entry in recipients {
        let public_key = match MemberPublicKey::parse(&entry.public_key) {
            Ok(public_key) => public_key,
            Err(error) => return Err(error),
        };
        if keys.insert(entry.member.clone(), public_key).is_some() {
            return Err(CryptoError::DuplicateMember {
                member: entry.member.clone(),
            });
        }
    }
    Ok(keys)
}

/// Decrypts an `age` ciphertext into a pre-sized zeroizing buffer, returning
/// `None` on any failure (the caller reports it as unauthorized).
fn decrypt_wrapped_payload(
    ciphertext: &[u8],
    identity: &MemberIdentity,
    max_payload_bytes: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    let decryptor = match age::Decryptor::new(ciphertext) {
        Ok(decryptor) => decryptor,
        Err(_) => return None,
    };
    let age_identity: &dyn age::Identity = identity.as_age_identity();
    let reader = match decryptor.decrypt(iter::once(age_identity)) {
        Ok(reader) => reader,
        Err(_) => return None,
    };
    // Sized so `read_to_end` never reallocates, which would leave unzeroized
    // copies of the key in freed memory.
    let limit = max_payload_bytes + 1;
    let mut payload = Zeroizing::new(Vec::with_capacity(limit + 1));
    match reader.take(limit as u64).read_to_end(&mut payload) {
        Ok(_) => Some(payload),
        Err(_) => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Predicate recognising the expected error in table-driven tests.
    pub(crate) type ErrorCheck = fn(&CryptoError) -> bool;

    pub(crate) fn data_key() -> ScopeDataKey {
        match ScopeDataKey::generate() {
            Ok(key) => key,
            Err(error) => panic!("key generation should succeed: {error}"),
        }
    }

    pub(crate) fn recipients(
        members: &[(&str, &MemberIdentity)],
    ) -> BTreeMap<String, MemberPublicKey> {
        members
            .iter()
            .map(|(name, identity)| ((*name).to_owned(), identity.public_key()))
            .collect()
    }

    pub(crate) fn wrap(
        scope: &str,
        generation: u64,
        key: &ScopeDataKey,
        members: &[(&str, &MemberIdentity)],
    ) -> ScopeKeysFile {
        match ScopeKeysFile::wrap_for_recipients(scope, generation, key, &recipients(members)) {
            Ok(file) => file,
            Err(error) => panic!("wrapping should succeed: {error}"),
        }
    }

    fn unwrap_bytes(file: &ScopeKeysFile, scope: &str, identity: &MemberIdentity) -> [u8; 32] {
        match file.unwrap_key(scope, identity) {
            Ok(key) => *key.as_bytes(),
            Err(error) => panic!("unwrap should succeed: {error}"),
        }
    }

    #[test]
    fn data_key_debug_is_redacted() {
        let key = data_key();
        let debug = format!("{key:?}");
        assert_eq!(debug, "ScopeDataKey([REDACTED])");
        assert!(!debug.contains(&format!("{:?}", key.as_bytes())));
    }

    #[test]
    fn wrap_and_unwrap_round_trip_for_every_recipient() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let key = data_key();
        let file = wrap("dev", 1, &key, &[("bob", &bob), ("alice", &alice)]);
        let members: Vec<&str> = file.recipients.iter().map(|r| r.member.as_str()).collect();
        assert_eq!(members, ["alice", "bob"]);
        assert_eq!(unwrap_bytes(&file, "dev", &alice), *key.as_bytes());
        assert_eq!(unwrap_bytes(&file, "dev", &bob), *key.as_bytes());
    }

    #[test]
    fn non_recipient_is_unauthorized() {
        let alice = MemberIdentity::generate();
        let mallory = MemberIdentity::generate();
        let file = wrap("dev", 1, &data_key(), &[("alice", &alice)]);
        match file.unwrap_key("dev", &mallory) {
            Err(CryptoError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn swapped_public_key_entry_is_unauthorized() {
        // Mallory lists her public key next to Alice's wrapped blob; age
        // decryption must still fail.
        let alice = MemberIdentity::generate();
        let mallory = MemberIdentity::generate();
        let mut file = wrap("dev", 1, &data_key(), &[("alice", &alice)]);
        if let Some(entry) = file.recipients.first_mut() {
            entry.public_key = mallory.public_key().as_str().to_owned();
        }
        match file.unwrap_key("dev", &mallory) {
            Err(CryptoError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn wrapped_key_copied_across_scopes_is_rejected() {
        let alice = MemberIdentity::generate();
        let dev = wrap("dev", 1, &data_key(), &[("alice", &alice)]);
        let mut prod = wrap("prod", 1, &data_key(), &[("alice", &alice)]);
        prod.recipients = dev.recipients.clone();
        match prod.unwrap_key("prod", &alice) {
            Err(CryptoError::WrappedKeyMismatch) => {}
            other => panic!("expected WrappedKeyMismatch, got {other:?}"),
        }
        // Relabelling the whole dev file as prod is caught too.
        let mut relabelled = dev.clone();
        relabelled.scope = "prod".to_owned();
        match relabelled.unwrap_key("prod", &alice) {
            Err(CryptoError::WrappedKeyMismatch) => {}
            other => panic!("expected WrappedKeyMismatch, got {other:?}"),
        }
        match dev.unwrap_key("prod", &alice) {
            Err(CryptoError::ScopeMismatch { .. }) => {}
            other => panic!("expected ScopeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrapped_key_with_edited_generation_is_rejected() {
        let alice = MemberIdentity::generate();
        let mut file = wrap("dev", 3, &data_key(), &[("alice", &alice)]);
        for generation in [2, 4] {
            file.generation = generation;
            match file.unwrap_key("dev", &alice) {
                Err(CryptoError::WrappedKeyMismatch) => {}
                other => panic!("expected WrappedKeyMismatch, got {other:?}"),
            }
        }
        file.generation = 0;
        match file.unwrap_key("dev", &alice) {
            Err(CryptoError::InvalidGeneration) => {}
            other => panic!("expected InvalidGeneration, got {other:?}"),
        }
    }

    #[test]
    fn bit_flipped_wrapped_key_is_unauthorized() {
        let alice = MemberIdentity::generate();
        let mut file = wrap("dev", 1, &data_key(), &[("alice", &alice)]);
        let Some(entry) = file.recipients.first_mut() else {
            panic!("file should have a recipient");
        };
        let mut bytes = match BASE64.decode(&entry.wrapped_key) {
            Ok(bytes) => bytes,
            Err(error) => panic!("wrapped key should be base64: {error}"),
        };
        if let Some(last) = bytes.last_mut() {
            *last ^= 0x01;
        }
        entry.wrapped_key = BASE64.encode(bytes);
        match file.unwrap_key("dev", &alice) {
            Err(CryptoError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn wrap_rejects_bad_inputs() {
        let alice = MemberIdentity::generate();
        let key = data_key();
        let members = recipients(&[("alice", &alice)]);
        match ScopeKeysFile::wrap_for_recipients("dev", 1, &key, &BTreeMap::new()) {
            Err(CryptoError::NoRecipients) => {}
            other => panic!("expected NoRecipients, got {other:?}"),
        }
        match ScopeKeysFile::wrap_for_recipients("dev", 0, &key, &members) {
            Err(CryptoError::InvalidGeneration) => {}
            other => panic!("expected InvalidGeneration, got {other:?}"),
        }
        match ScopeKeysFile::wrap_for_recipients("../prod", 1, &key, &members) {
            Err(CryptoError::InvalidScopeName { .. }) => {}
            other => panic!("expected InvalidScopeName, got {other:?}"),
        }
    }

    #[test]
    fn toml_round_trip_preserves_file() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let key = data_key();
        let file = wrap("dev", 7, &key, &[("alice", &alice), ("bob", &bob)]);
        let text = match file.to_toml_string() {
            Ok(text) => text,
            Err(error) => panic!("serialization should succeed: {error}"),
        };
        let parsed = match ScopeKeysFile::from_toml_str(&text) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parsing should succeed: {error}"),
        };
        assert_eq!(parsed, file);
        assert_eq!(unwrap_bytes(&parsed, "dev", &bob), *key.as_bytes());
        match parsed.recipient_public_keys() {
            Ok(keys) => assert_eq!(keys, recipients(&[("alice", &alice), ("bob", &bob)])),
            Err(error) => panic!("public keys should parse: {error}"),
        }
    }

    #[test]
    fn from_toml_sorts_recipients_and_rejects_invalid_files() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let file = wrap("dev", 1, &data_key(), &[("alice", &alice), ("bob", &bob)]);

        let mut reversed = file.clone();
        reversed.recipients.reverse();
        let reversed_text = match reversed.to_toml_string() {
            Ok(text) => text,
            Err(error) => panic!("serialization should succeed: {error}"),
        };
        match ScopeKeysFile::from_toml_str(&reversed_text) {
            Ok(parsed) => assert_eq!(parsed, file),
            Err(error) => panic!("unsorted file should still parse: {error}"),
        }

        let mut duplicate = file.clone();
        if let Some(entry) = duplicate.recipients.get_mut(1) {
            entry.member = "alice".to_owned();
        }
        let mut bad_version = file.clone();
        bad_version.version = 2;
        let mut bad_scope = file.clone();
        bad_scope.scope = "../prod".to_owned();
        let mut bad_generation = file.clone();
        bad_generation.generation = 0;
        let mut bad_public_key = file.clone();
        if let Some(entry) = bad_public_key.recipients.first_mut() {
            entry.public_key = entry.public_key.to_uppercase();
        }
        let mut bad_base64 = file.clone();
        if let Some(entry) = bad_base64.recipients.first_mut() {
            entry.wrapped_key = "not base64!".to_owned();
        }
        let mut empty = file.clone();
        empty.recipients.clear();

        let cases: [(ScopeKeysFile, ErrorCheck); 7] = [
            (duplicate, |e| {
                matches!(e, CryptoError::DuplicateMember { .. })
            }),
            (bad_version, |e| {
                matches!(e, CryptoError::UnsupportedVersion { found: 2 })
            }),
            (bad_scope, |e| {
                matches!(e, CryptoError::InvalidScopeName { .. })
            }),
            (bad_generation, |e| {
                matches!(e, CryptoError::InvalidGeneration)
            }),
            (bad_public_key, |e| {
                matches!(e, CryptoError::InvalidPublicKey { .. })
            }),
            (bad_base64, |e| {
                matches!(e, CryptoError::InvalidEncoding { .. })
            }),
            (empty, |e| {
                matches!(e, CryptoError::NoRecipients | CryptoError::InvalidToml(_))
            }),
        ];
        for (case, is_expected) in cases {
            let text = match case.to_toml_string() {
                Ok(text) => text,
                Err(error) => panic!("serialization should succeed: {error}"),
            };
            match ScopeKeysFile::from_toml_str(&text) {
                Err(error) if is_expected(&error) => {}
                other => panic!("unexpected result for {case:?}: {other:?}"),
            }
        }

        let unknown_field =
            "version = 1\nscope = \"dev\"\ngeneration = 1\nextra = true\nrecipients = []\n";
        match ScopeKeysFile::from_toml_str(unknown_field) {
            Err(CryptoError::InvalidToml(_)) => {}
            other => panic!("expected InvalidToml, got {other:?}"),
        }
    }
}
