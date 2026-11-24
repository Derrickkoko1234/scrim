//! Per-group private-file data keys and their per-member wrapping in
//! `.scrim/group-keys/<group>.toml`.
//!
//! The `age` plaintext for each recipient is a domain-bound payload whose
//! domain differs from scope keys, so a wrapped group key can never be
//! accepted as a scope key or vice versa:
//!
//! ```text
//! "scrim-group-key-v1\n" || group || "\n" || generation (decimal) || "\n" || key[64]
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::scope_key::{
    build_bound_payload, decrypt_recipient_payload, parse_recipient_public_keys,
    sort_and_validate_recipients, strip_bound_payload, wrap_payload_for_recipients,
};
use crate::validation::{validate_generation, validate_version};
use crate::{
    CryptoError, FILE_FORMAT_VERSION, MAX_GROUP_NAME_BYTES, MemberIdentity, MemberPublicKey,
    WrappedRecipientKey, validate_group_name,
};

/// Length of a group data key, in bytes: AES-256-SIV takes two 256-bit keys.
const GROUP_KEY_BYTES: usize = 64;

/// Domain-separation prefix of every wrapped group-key payload.
const GROUP_KEY_DOMAIN: &[u8] = b"scrim-group-key-v1\n";

/// Upper bound on a well-formed wrapped group-key payload: domain, longest
/// group, newline, the 20 digits of `u64::MAX`, newline and the key itself.
const MAX_GROUP_PAYLOAD_BYTES: usize =
    GROUP_KEY_DOMAIN.len() + MAX_GROUP_NAME_BYTES + 1 + 20 + 1 + GROUP_KEY_BYTES;

/// A random 512-bit AES-256-SIV key that encrypts one group's private files
/// for one generation.
///
/// The bytes are zeroized on drop and never appear in `Debug` output.
pub struct GroupDataKey(Zeroizing<[u8; GROUP_KEY_BYTES]>);

impl GroupDataKey {
    /// Generates a fresh key from the operating system's RNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Random`] if the RNG fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Zeroizing::new([0_u8; GROUP_KEY_BYTES]);
        match getrandom::fill(key.as_mut_slice()) {
            Ok(()) => Ok(Self(key)),
            Err(error) => Err(CryptoError::Random(error.to_string())),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8; GROUP_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for GroupDataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GroupDataKey([REDACTED])")
    }
}

/// Contents of `.scrim/group-keys/<group>.toml`: one group data key wrapped
/// for every member of the group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupKeysFile {
    /// File format version; must be [`FILE_FORMAT_VERSION`].
    pub version: u32,
    /// Group the key belongs to.
    pub group: String,
    /// Key generation, starting at 1 and incremented on every rotation.
    pub generation: u64,
    /// Wrapped copies of the key, sorted by member name for stable diffs.
    pub recipients: Vec<WrappedRecipientKey>,
}

impl GroupKeysFile {
    /// Wraps `data_key` for each recipient, bound to `group` and `generation`.
    ///
    /// Recipients come out sorted by member name (the `BTreeMap` order).
    ///
    /// # Errors
    ///
    /// Fails on an invalid group, generation 0, an empty recipient map, or an
    /// `age` encryption error.
    pub fn wrap_for_recipients(
        group: &str,
        generation: u64,
        data_key: &GroupDataKey,
        recipients: &BTreeMap<String, MemberPublicKey>,
    ) -> Result<Self, CryptoError> {
        if let Err(error) = validate_group_name(group) {
            return Err(error);
        }
        if let Err(error) = validate_generation(generation) {
            return Err(error);
        }
        if recipients.is_empty() {
            return Err(CryptoError::NoRecipients);
        }
        let payload = build_bound_payload(GROUP_KEY_DOMAIN, group, generation, data_key.as_bytes());
        let wrapped = match wrap_payload_for_recipients(&payload, recipients) {
            Ok(wrapped) => wrapped,
            Err(error) => return Err(error),
        };
        Ok(Self {
            version: FILE_FORMAT_VERSION,
            group: group.to_owned(),
            generation,
            recipients: wrapped,
        })
    }

    /// Recovers the data key with `identity`, checking that this file and the
    /// encrypted payload are both bound to `expected_group` and this file's
    /// generation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unauthorized`] when no recipient entry matches
    /// the identity's public key or `age` decryption fails, and
    /// [`CryptoError::WrappedKeyMismatch`] when the decrypted payload belongs
    /// to another group, generation or key kind. Version, group and
    /// generation problems in the file itself are reported before any
    /// decryption.
    pub fn unwrap_key(
        &self,
        expected_group: &str,
        identity: &MemberIdentity,
    ) -> Result<GroupDataKey, CryptoError> {
        if let Err(error) = validate_version(self.version) {
            return Err(error);
        }
        if self.group != expected_group {
            return Err(CryptoError::GroupMismatch {
                expected: expected_group.to_owned(),
                found: self.group.clone(),
            });
        }
        if let Err(error) = validate_generation(self.generation) {
            return Err(error);
        }
        let payload =
            match decrypt_recipient_payload(&self.recipients, identity, MAX_GROUP_PAYLOAD_BYTES) {
                Ok(payload) => payload,
                Err(error) => return Err(error),
            };
        let Some(key_bytes) =
            strip_bound_payload(&payload, GROUP_KEY_DOMAIN, expected_group, self.generation)
        else {
            return Err(CryptoError::WrappedKeyMismatch);
        };
        let mut key = Zeroizing::new([0_u8; GROUP_KEY_BYTES]);
        if key_bytes.len() != key.len() {
            return Err(CryptoError::WrappedKeyMismatch);
        }
        key.copy_from_slice(key_bytes);
        Ok(GroupDataKey(key))
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

    /// Parses and validates a group keys file.
    ///
    /// Checks the version, group name, generation, that recipients exist and
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
        if let Err(error) = validate_group_name(&file.group) {
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

/// The new group key produced by [`rotate_group_key`].
#[derive(Debug)]
pub struct RotatedGroupKey {
    /// The new key wrapped for the new recipients at the next generation,
    /// ready to write to `.scrim/group-keys/<group>.toml`.
    pub keys_file: GroupKeysFile,
    /// The new key itself, for re-encrypting the group's private files.
    pub data_key: GroupDataKey,
}

/// Rotates `group` to a brand-new data key wrapped for `new_recipients` at
/// the next generation.
///
/// `actor` must be able to unwrap `current_keys`, so only a current member
/// can produce a rotation. Members missing from `new_recipients` cannot
/// unwrap the new key; callers must re-encrypt the group's files with
/// [`RotatedGroupKey::data_key`] for that to protect file contents.
///
/// # Errors
///
/// Fails if the actor cannot unwrap the current key, the generation would
/// overflow, `new_recipients` is empty, or key generation or wrapping fails.
pub fn rotate_group_key(
    group: &str,
    current_keys: &GroupKeysFile,
    actor: &MemberIdentity,
    new_recipients: &BTreeMap<String, MemberPublicKey>,
) -> Result<RotatedGroupKey, CryptoError> {
    // The current key is only unwrapped to prove membership; it is dropped
    // (and zeroized) immediately.
    if let Err(error) = current_keys.unwrap_key(group, actor) {
        return Err(error);
    }
    let Some(next_generation) = current_keys.generation.checked_add(1) else {
        return Err(CryptoError::GenerationOverflow);
    };
    let data_key = match GroupDataKey::generate() {
        Ok(key) => key,
        Err(error) => return Err(error),
    };
    match GroupKeysFile::wrap_for_recipients(group, next_generation, &data_key, new_recipients) {
        Ok(keys_file) => Ok(RotatedGroupKey {
            keys_file,
            data_key,
        }),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ScopeKeysFile;
    use crate::scope_key::tests::{ErrorCheck, data_key as scope_data_key, recipients};

    pub(crate) fn group_key() -> GroupDataKey {
        match GroupDataKey::generate() {
            Ok(key) => key,
            Err(error) => panic!("key generation should succeed: {error}"),
        }
    }

    fn wrap(
        group: &str,
        generation: u64,
        key: &GroupDataKey,
        members: &[(&str, &MemberIdentity)],
    ) -> GroupKeysFile {
        match GroupKeysFile::wrap_for_recipients(group, generation, key, &recipients(members)) {
            Ok(file) => file,
            Err(error) => panic!("wrapping should succeed: {error}"),
        }
    }

    fn unwrap_bytes(file: &GroupKeysFile, group: &str, identity: &MemberIdentity) -> [u8; 64] {
        match file.unwrap_key(group, identity) {
            Ok(key) => *key.as_bytes(),
            Err(error) => panic!("unwrap should succeed: {error}"),
        }
    }

    fn expect_error(
        result: Result<GroupDataKey, CryptoError>,
        is_expected: fn(&CryptoError) -> bool,
    ) {
        match result {
            Err(error) if is_expected(&error) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn generated_keys_are_random_and_redacted() {
        let first = group_key();
        let second = group_key();
        assert_ne!(first.as_bytes(), second.as_bytes());
        let debug = format!("{first:?}");
        assert_eq!(debug, "GroupDataKey([REDACTED])");
        assert!(!debug.contains(&format!("{:?}", first.as_bytes())));
    }

    #[test]
    fn wrap_and_unwrap_round_trip_for_every_recipient() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let key = group_key();
        let file = wrap("backend", 1, &key, &[("bob", &bob), ("alice", &alice)]);
        let members: Vec<&str> = file.recipients.iter().map(|r| r.member.as_str()).collect();
        assert_eq!(members, ["alice", "bob"]);
        assert_eq!(unwrap_bytes(&file, "backend", &alice), *key.as_bytes());
        assert_eq!(unwrap_bytes(&file, "backend", &bob), *key.as_bytes());
    }

    #[test]
    fn non_recipient_and_swapped_public_key_are_unauthorized() {
        let alice = MemberIdentity::generate();
        let mallory = MemberIdentity::generate();
        let mut file = wrap("backend", 1, &group_key(), &[("alice", &alice)]);
        expect_error(file.unwrap_key("backend", &mallory), |e| {
            matches!(e, CryptoError::Unauthorized)
        });
        // Mallory lists her public key next to Alice's wrapped blob; age
        // decryption must still fail.
        if let Some(entry) = file.recipients.first_mut() {
            entry.public_key = mallory.public_key().as_str().to_owned();
        }
        expect_error(file.unwrap_key("backend", &mallory), |e| {
            matches!(e, CryptoError::Unauthorized)
        });
    }

    #[test]
    fn wrapped_key_copied_across_groups_is_rejected() {
        let alice = MemberIdentity::generate();
        let backend = wrap("backend", 1, &group_key(), &[("alice", &alice)]);
        let mut finance = wrap("finance", 1, &group_key(), &[("alice", &alice)]);
        finance.recipients = backend.recipients.clone();
        expect_error(finance.unwrap_key("finance", &alice), |e| {
            matches!(e, CryptoError::WrappedKeyMismatch)
        });
        let mut relabelled = backend.clone();
        relabelled.group = "finance".to_owned();
        expect_error(relabelled.unwrap_key("finance", &alice), |e| {
            matches!(e, CryptoError::WrappedKeyMismatch)
        });
        expect_error(backend.unwrap_key("finance", &alice), |e| {
            matches!(e, CryptoError::GroupMismatch { .. })
        });
    }

    #[test]
    fn scope_and_group_wrapped_keys_cannot_be_interchanged() {
        let alice = MemberIdentity::generate();
        let scope_file = match ScopeKeysFile::wrap_for_recipients(
            "shared",
            1,
            &scope_data_key(),
            &recipients(&[("alice", &alice)]),
        ) {
            Ok(file) => file,
            Err(error) => panic!("wrapping should succeed: {error}"),
        };
        let group_file = wrap("shared", 1, &group_key(), &[("alice", &alice)]);

        let mut group_from_scope = group_file.clone();
        group_from_scope.recipients = scope_file.recipients.clone();
        expect_error(group_from_scope.unwrap_key("shared", &alice), |e| {
            matches!(e, CryptoError::WrappedKeyMismatch)
        });

        let mut scope_from_group = scope_file.clone();
        scope_from_group.recipients = group_file.recipients.clone();
        match scope_from_group.unwrap_key("shared", &alice) {
            Err(CryptoError::WrappedKeyMismatch) => {}
            other => panic!("expected WrappedKeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrapped_key_with_edited_generation_is_rejected() {
        let alice = MemberIdentity::generate();
        let mut file = wrap("backend", 3, &group_key(), &[("alice", &alice)]);
        for generation in [2, 4] {
            file.generation = generation;
            expect_error(file.unwrap_key("backend", &alice), |e| {
                matches!(e, CryptoError::WrappedKeyMismatch)
            });
        }
        file.generation = 0;
        expect_error(file.unwrap_key("backend", &alice), |e| {
            matches!(e, CryptoError::InvalidGeneration)
        });
    }

    #[test]
    fn wrap_rejects_bad_inputs() {
        let alice = MemberIdentity::generate();
        let key = group_key();
        let members = recipients(&[("alice", &alice)]);
        match GroupKeysFile::wrap_for_recipients("backend", 1, &key, &BTreeMap::new()) {
            Err(CryptoError::NoRecipients) => {}
            other => panic!("expected NoRecipients, got {other:?}"),
        }
        match GroupKeysFile::wrap_for_recipients("backend", 0, &key, &members) {
            Err(CryptoError::InvalidGeneration) => {}
            other => panic!("expected InvalidGeneration, got {other:?}"),
        }
        match GroupKeysFile::wrap_for_recipients("../finance", 1, &key, &members) {
            Err(CryptoError::InvalidGroupName { .. }) => {}
            other => panic!("expected InvalidGroupName, got {other:?}"),
        }
    }

    #[test]
    fn toml_round_trip_preserves_file_and_rejects_invalid_files() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let key = group_key();
        let file = wrap("backend", 7, &key, &[("alice", &alice), ("bob", &bob)]);
        let mut reversed = file.clone();
        reversed.recipients.reverse();
        let text = match reversed.to_toml_string() {
            Ok(text) => text,
            Err(error) => panic!("serialization should succeed: {error}"),
        };
        let parsed = match GroupKeysFile::from_toml_str(&text) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parsing should succeed: {error}"),
        };
        assert_eq!(parsed, file);
        assert_eq!(unwrap_bytes(&parsed, "backend", &bob), *key.as_bytes());
        match parsed.recipient_public_keys() {
            Ok(keys) => assert_eq!(keys, recipients(&[("alice", &alice), ("bob", &bob)])),
            Err(error) => panic!("public keys should parse: {error}"),
        }

        let mut bad_group = file.clone();
        bad_group.group = ".hidden".to_owned();
        let mut bad_version = file.clone();
        bad_version.version = 2;
        let mut duplicate = file.clone();
        if let Some(entry) = duplicate.recipients.get_mut(1) {
            entry.member = "alice".to_owned();
        }
        let cases: [(GroupKeysFile, ErrorCheck); 3] = [
            (bad_group, |e| {
                matches!(e, CryptoError::InvalidGroupName { .. })
            }),
            (bad_version, |e| {
                matches!(e, CryptoError::UnsupportedVersion { found: 2 })
            }),
            (duplicate, |e| {
                matches!(e, CryptoError::DuplicateMember { .. })
            }),
        ];
        for (case, is_expected) in cases {
            let text = match case.to_toml_string() {
                Ok(text) => text,
                Err(error) => panic!("serialization should succeed: {error}"),
            };
            match GroupKeysFile::from_toml_str(&text) {
                Err(error) if is_expected(&error) => {}
                other => panic!("unexpected result for {case:?}: {other:?}"),
            }
        }
        // A scope keys file is not a group keys file.
        let scope_text = "version = 1\nscope = \"dev\"\ngeneration = 1\nrecipients = []\n";
        match GroupKeysFile::from_toml_str(scope_text) {
            Err(CryptoError::InvalidToml(_)) => {}
            other => panic!("expected InvalidToml, got {other:?}"),
        }
    }

    #[test]
    fn authorized_rotation_issues_a_new_key_for_new_members() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let carol = MemberIdentity::generate();
        let old_key = group_key();
        let current = wrap("backend", 4, &old_key, &[("alice", &alice), ("bob", &bob)]);
        let new_recipients = recipients(&[("alice", &alice), ("carol", &carol)]);
        let rotated = match rotate_group_key("backend", &current, &alice, &new_recipients) {
            Ok(rotated) => rotated,
            Err(error) => panic!("rotation should succeed: {error}"),
        };
        assert_eq!(rotated.keys_file.generation, 5);
        assert_ne!(rotated.data_key.as_bytes(), old_key.as_bytes());
        for member in [&alice, &carol] {
            assert_eq!(
                unwrap_bytes(&rotated.keys_file, "backend", member),
                *rotated.data_key.as_bytes()
            );
        }
        expect_error(rotated.keys_file.unwrap_key("backend", &bob), |e| {
            matches!(e, CryptoError::Unauthorized)
        });
        assert!(!format!("{rotated:?}").contains(&format!("{:?}", rotated.data_key.as_bytes())));
    }

    #[test]
    fn rotation_rejects_unauthorized_actor_and_overflow() {
        let alice = MemberIdentity::generate();
        let mallory = MemberIdentity::generate();
        let current = wrap("backend", 1, &group_key(), &[("alice", &alice)]);
        let takeover = recipients(&[("mallory", &mallory)]);
        match rotate_group_key("backend", &current, &mallory, &takeover) {
            Err(CryptoError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
        match rotate_group_key("finance", &current, &alice, &takeover) {
            Err(CryptoError::GroupMismatch { .. }) => {}
            other => panic!("expected GroupMismatch, got {other:?}"),
        }
        let exhausted = wrap("backend", u64::MAX, &group_key(), &[("alice", &alice)]);
        match rotate_group_key("backend", &exhausted, &alice, &takeover) {
            Err(CryptoError::GenerationOverflow) => {}
            other => panic!("expected GenerationOverflow, got {other:?}"),
        }
    }

    #[test]
    fn rewrapping_same_group_key_at_existing_generation_preserves_generation_and_domain() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let key = group_key();
        let original = wrap("finance", 4, &key, &[("alice", &alice)]);

        let recovered = match original.unwrap_key("finance", &alice) {
            Ok(k) => k,
            Err(error) => panic!("alice should unwrap gen 4: {error}"),
        };
        let mut updated_recipients = match original.recipient_public_keys() {
            Ok(map) => map,
            Err(error) => panic!("recipient keys should parse: {error}"),
        };
        updated_recipients.insert("bob".to_owned(), bob.public_key());

        let rewrapped = match GroupKeysFile::wrap_for_recipients(
            "finance",
            original.generation,
            &recovered,
            &updated_recipients,
        ) {
            Ok(file) => file,
            Err(error) => panic!("rewrapping at gen 4 should succeed: {error}"),
        };
        assert_eq!(rewrapped.generation, 4);
        assert_eq!(unwrap_bytes(&rewrapped, "finance", &alice), *key.as_bytes());
        assert_eq!(unwrap_bytes(&rewrapped, "finance", &bob), *key.as_bytes());

        // Domain and generation binding remain enforced on Bob's newly wrapped copy.
        let mut wrong_gen = rewrapped.clone();
        wrong_gen.generation = 3;
        expect_error(wrong_gen.unwrap_key("finance", &bob), |e| {
            matches!(e, CryptoError::WrappedKeyMismatch)
        });
        let mut wrong_group = rewrapped;
        wrong_group.group = "backend".to_owned();
        expect_error(wrong_group.unwrap_key("backend", &bob), |e| {
            matches!(e, CryptoError::WrappedKeyMismatch)
        });
    }
}
