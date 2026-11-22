//! Fuzzes every envelope `scrim-crypto` parses from a repository: encrypted
//! private file blobs, placeholders, and the group-key, scope-key and
//! encrypted-secrets TOML files, including authenticated decryption with
//! fixed keys so header parsing, `age` unwrapping and AEAD checks all run.

#![no_main]
// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use scrim_crypto::{
    EncryptedSecretsFile, GroupDataKey, GroupKeysFile, MemberIdentity, ScopeDataKey, ScopeKeysFile,
    decrypt_file, extract_placeholder, extract_placeholder_blob, is_encrypted_file, is_placeholder,
    parse_encrypted_file_header,
};

/// Keys fixed for the life of the fuzzing process.
struct FixedKeys {
    group_key: GroupDataKey,
    scope_key: ScopeDataKey,
    identity: MemberIdentity,
}

/// Returns the process-wide keys, or `None` if the RNG failed.
fn fixed_keys() -> Option<&'static FixedKeys> {
    static KEYS: OnceLock<Option<FixedKeys>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let group_key = match GroupDataKey::generate() {
            Ok(key) => key,
            Err(_) => return None,
        };
        let scope_key = match ScopeDataKey::generate() {
            Ok(key) => key,
            Err(_) => return None,
        };
        Some(FixedKeys {
            group_key,
            scope_key,
            identity: MemberIdentity::generate(),
        })
    })
    .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some(keys) = fixed_keys() else {
        return;
    };

    let _ = is_encrypted_file(data);
    let _ = decrypt_file("finance", 1, "config/app.env", &keys.group_key, data);
    // Decrypt with the blob's own group and generation so fuzzed inputs reach
    // the AES-SIV authentication check instead of stopping at a mismatch.
    if let Ok(header) = parse_encrypted_file_header(data) {
        let _ = decrypt_file(
            &header.group,
            header.generation,
            "config/app.env",
            &keys.group_key,
            data,
        );
    }

    let _ = is_placeholder(data);
    let _ = extract_placeholder_blob(data);
    if let Ok(extracted) = extract_placeholder(data) {
        let _ = decrypt_file(
            &extracted.header.group,
            extracted.header.generation,
            &extracted.path,
            &keys.group_key,
            &extracted.blob,
        );
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(file) = GroupKeysFile::from_toml_str(text) {
        let _ = file.recipient_public_keys();
        let _ = file.unwrap_key(&file.group, &keys.identity);
        let _ = file.to_toml_string();
    }
    if let Ok(file) = ScopeKeysFile::from_toml_str(text) {
        let _ = file.recipient_public_keys();
        let _ = file.unwrap_key(&file.scope, &keys.identity);
        let _ = file.to_toml_string();
    }
    if let Ok(file) = EncryptedSecretsFile::from_toml_str(text) {
        let _ = file.decrypt(&file.scope, file.generation, &keys.scope_key);
        let _ = file.to_toml_string();
    }
});
