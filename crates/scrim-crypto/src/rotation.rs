//! Scope key rotation: new data key, new recipients, re-encrypted secrets.

use std::collections::BTreeMap;

use crate::{
    CryptoError, EncryptedSecretsFile, MemberIdentity, MemberPublicKey, ScopeDataKey, ScopeKeysFile,
};

/// The files produced by [`rotate_scope`], ready to write back to `.scrim/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedScope {
    /// The new key wrapped for the new recipients at the next generation.
    pub keys_file: ScopeKeysFile,
    /// The secrets re-encrypted under the new key, if there were any.
    pub secrets_file: Option<EncryptedSecretsFile>,
    /// Names of the re-encrypted secrets, sorted. Rotation hides future
    /// values from removed members, but they may already know these, so
    /// callers should prompt for the underlying credentials to be changed.
    pub rotated_secret_keys: Vec<String>,
}

/// Rotates `scope` to a brand-new data key wrapped for `new_recipients`.
///
/// `actor_identity` must be a current recipient: it unwraps the current key,
/// which decrypts `secrets_file` (when given) at the current generation. A new
/// random key is then wrapped at the next generation and the secrets are
/// re-encrypted under it with a fresh nonce. Members missing from
/// `new_recipients` can decrypt neither the new key nor the new secrets.
///
/// # Errors
///
/// Fails if the actor cannot unwrap the current key, the secrets do not match
/// the keys file's scope and generation, the generation would overflow,
/// `new_recipients` is empty, or any encryption step fails.
pub fn rotate_scope(
    scope: &str,
    keys_file: &ScopeKeysFile,
    secrets_file: Option<&EncryptedSecretsFile>,
    actor_identity: &MemberIdentity,
    new_recipients: &BTreeMap<String, MemberPublicKey>,
) -> Result<RotatedScope, CryptoError> {
    let current_key = match keys_file.unwrap_key(scope, actor_identity) {
        Ok(key) => key,
        Err(error) => return Err(error),
    };
    let secrets = match secrets_file {
        Some(file) => match file.decrypt(scope, keys_file.generation, &current_key) {
            Ok(secrets) => Some(secrets),
            Err(error) => return Err(error),
        },
        None => None,
    };
    let Some(next_generation) = keys_file.generation.checked_add(1) else {
        return Err(CryptoError::GenerationOverflow);
    };
    let new_key = match ScopeDataKey::generate() {
        Ok(key) => key,
        Err(error) => return Err(error),
    };
    let new_keys_file = match ScopeKeysFile::wrap_for_recipients(
        scope,
        next_generation,
        &new_key,
        new_recipients,
    ) {
        Ok(file) => file,
        Err(error) => return Err(error),
    };
    let (new_secrets_file, rotated_secret_keys) = match secrets {
        Some(secrets) => {
            match EncryptedSecretsFile::encrypt(scope, next_generation, &new_key, &secrets) {
                Ok(file) => (Some(file), secrets.keys().map(str::to_owned).collect()),
                Err(error) => return Err(error),
            }
        }
        None => (None, Vec::new()),
    };
    Ok(RotatedScope {
        keys_file: new_keys_file,
        secrets_file: new_secrets_file,
        rotated_secret_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_key::tests::{data_key, recipients, wrap};
    use crate::secrets::tests::{bundle, exposed};

    #[test]
    fn rotation_replaces_key_and_drops_removed_members() {
        let alice = MemberIdentity::generate();
        let bob = MemberIdentity::generate();
        let carol = MemberIdentity::generate();
        let key = data_key();
        let keys_file = wrap("prod", 4, &key, &[("alice", &alice), ("bob", &bob)]);
        let secrets = bundle(&[("ZETA", "z"), ("ALPHA", "a"), ("MIDDLE", "m")]);
        let secrets_file = match EncryptedSecretsFile::encrypt("prod", 4, &key, &secrets) {
            Ok(file) => file,
            Err(error) => panic!("encryption should succeed: {error}"),
        };

        // Alice rotates, removing Bob and adding Carol.
        let new_recipients = recipients(&[("alice", &alice), ("carol", &carol)]);
        let rotated = match rotate_scope(
            "prod",
            &keys_file,
            Some(&secrets_file),
            &alice,
            &new_recipients,
        ) {
            Ok(rotated) => rotated,
            Err(error) => panic!("rotation should succeed: {error}"),
        };
        assert_eq!(rotated.keys_file.generation, 5);
        assert_eq!(rotated.rotated_secret_keys, ["ALPHA", "MIDDLE", "ZETA"]);
        let Some(new_secrets_file) = rotated.secrets_file.as_ref() else {
            panic!("secrets should be re-encrypted");
        };
        assert_eq!(new_secrets_file.generation, 5);

        for member in [&alice, &carol] {
            let new_key = match rotated.keys_file.unwrap_key("prod", member) {
                Ok(new_key) => new_key,
                Err(error) => panic!("new recipient should unwrap: {error}"),
            };
            assert_ne!(new_key.as_bytes(), key.as_bytes());
            match new_secrets_file.decrypt("prod", 5, &new_key) {
                Ok(decrypted) => assert_eq!(exposed(&decrypted), exposed(&secrets)),
                Err(error) => panic!("new recipient should decrypt: {error}"),
            }
        }

        // Bob is gone from the new keys file, and his old key does not open
        // the new ciphertext.
        match rotated.keys_file.unwrap_key("prod", &bob) {
            Err(CryptoError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
        let bobs_old_key = match keys_file.unwrap_key("prod", &bob) {
            Ok(old_key) => old_key,
            Err(error) => panic!("bob could read the old generation: {error}"),
        };
        match new_secrets_file.decrypt("prod", 5, &bobs_old_key) {
            Err(CryptoError::DecryptionFailed) => {}
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    #[test]
    fn rotation_without_secrets_only_rewraps() {
        let alice = MemberIdentity::generate();
        let keys_file = wrap("dev", 1, &data_key(), &[("alice", &alice)]);
        let new_recipients = recipients(&[("alice", &alice)]);
        match rotate_scope("dev", &keys_file, None, &alice, &new_recipients) {
            Ok(rotated) => {
                assert_eq!(rotated.keys_file.generation, 2);
                assert!(rotated.secrets_file.is_none());
                assert!(rotated.rotated_secret_keys.is_empty());
            }
            Err(error) => panic!("rotation should succeed: {error}"),
        }
    }

    #[test]
    fn rotation_requires_an_authorized_actor_and_matching_files() {
        let alice = MemberIdentity::generate();
        let mallory = MemberIdentity::generate();
        let key = data_key();
        let keys_file = wrap("dev", 1, &key, &[("alice", &alice)]);
        let new_recipients = recipients(&[("mallory", &mallory)]);
        match rotate_scope("dev", &keys_file, None, &mallory, &new_recipients) {
            Err(CryptoError::Unauthorized) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }

        let stale_secrets = match EncryptedSecretsFile::encrypt("dev", 2, &key, &bundle(&[])) {
            Ok(file) => file,
            Err(error) => panic!("encryption should succeed: {error}"),
        };
        match rotate_scope(
            "dev",
            &keys_file,
            Some(&stale_secrets),
            &alice,
            &new_recipients,
        ) {
            Err(CryptoError::GenerationMismatch { .. }) => {}
            other => panic!("expected GenerationMismatch, got {other:?}"),
        }

        match rotate_scope("dev", &keys_file, None, &alice, &BTreeMap::new()) {
            Err(CryptoError::NoRecipients) => {}
            other => panic!("expected NoRecipients, got {other:?}"),
        }
    }

    #[test]
    fn rotation_reports_generation_overflow() {
        let alice = MemberIdentity::generate();
        let keys_file = wrap("dev", u64::MAX, &data_key(), &[("alice", &alice)]);
        let new_recipients = recipients(&[("alice", &alice)]);
        match rotate_scope("dev", &keys_file, None, &alice, &new_recipients) {
            Err(CryptoError::GenerationOverflow) => {}
            other => panic!("expected GenerationOverflow, got {other:?}"),
        }
    }
}
