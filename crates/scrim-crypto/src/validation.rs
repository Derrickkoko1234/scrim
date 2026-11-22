//! Name and size limits for scopes and secrets.

use crate::CryptoError;

/// Longest accepted scope name, in bytes.
pub const MAX_SCOPE_NAME_BYTES: usize = 64;
/// Longest accepted secret key name, in bytes.
pub const MAX_SECRET_KEY_BYTES: usize = 128;
/// Largest accepted secret value, in bytes (256 KiB).
pub const MAX_SECRET_VALUE_BYTES: usize = 256 * 1024;
/// Most secrets a single scope may hold.
pub const MAX_SECRETS_PER_SCOPE: usize = 4096;

/// Checks that `scope` is safe to use as a file stem for
/// `.scrim/keys/<scope>.toml` and `.scrim/secrets/<scope>.enc`.
///
/// A valid scope is 1 to [`MAX_SCOPE_NAME_BYTES`] ASCII bytes, starts with
/// `[A-Za-z0-9]`, and otherwise contains only `[A-Za-z0-9._-]`. This rules out
/// path separators, a leading `.` (hidden files, `..` traversal) and empty
/// names.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidScopeName`] naming the broken rule.
pub fn validate_scope_name(scope: &str) -> Result<(), CryptoError> {
    let reject = |reason| {
        Err(CryptoError::InvalidScopeName {
            scope: scope.to_owned(),
            reason,
        })
    };
    let bytes = scope.as_bytes();
    let Some(first) = bytes.first() else {
        return reject("scope name must not be empty");
    };
    if bytes.len() > MAX_SCOPE_NAME_BYTES {
        return reject("scope name is longer than 64 bytes");
    }
    if !first.is_ascii_alphanumeric() {
        return reject("scope name must start with an ASCII letter or digit");
    }
    let is_allowed = |byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
    if !bytes.iter().all(is_allowed) {
        return reject("scope name may only contain ASCII letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// Checks that `key` is a valid POSIX environment variable name, so it can be
/// exported by `scrim run` and in dotenv output.
///
/// A valid key is 1 to [`MAX_SECRET_KEY_BYTES`] ASCII bytes, starts with
/// `[A-Za-z_]`, and otherwise contains only `[A-Za-z0-9_]`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSecretKey`] naming the broken rule.
pub fn validate_secret_key(key: &str) -> Result<(), CryptoError> {
    let reject = |reason| {
        Err(CryptoError::InvalidSecretKey {
            key: key.to_owned(),
            reason,
        })
    };
    let bytes = key.as_bytes();
    let Some(first) = bytes.first() else {
        return reject("secret key must not be empty");
    };
    if bytes.len() > MAX_SECRET_KEY_BYTES {
        return reject("secret key is longer than 128 bytes");
    }
    if !(first.is_ascii_alphabetic() || *first == b'_') {
        return reject("secret key must start with an ASCII letter or '_'");
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return reject("secret key may only contain ASCII letters, digits and '_'");
    }
    Ok(())
}

/// Rejects generation 0; generations start at 1.
pub(crate) fn validate_generation(generation: u64) -> Result<(), CryptoError> {
    if generation == 0 {
        return Err(CryptoError::InvalidGeneration);
    }
    Ok(())
}

/// Rejects any file format version other than [`crate::FILE_FORMAT_VERSION`].
pub(crate) fn validate_version(version: u32) -> Result<(), CryptoError> {
    if version != crate::FILE_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion { found: version });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_scope_names() {
        let long = "a".repeat(MAX_SCOPE_NAME_BYTES);
        for scope in ["dev", "prod", "Staging-2", "eu.west_1", "0", long.as_str()] {
            if let Err(error) = validate_scope_name(scope) {
                panic!("{scope:?} should be valid: {error}");
            }
        }
    }

    #[test]
    fn rejects_unsafe_scope_names() {
        let too_long = "a".repeat(MAX_SCOPE_NAME_BYTES + 1);
        for scope in [
            "",
            ".",
            "..",
            ".hidden",
            "../prod",
            "dev/../prod",
            "a/b",
            "a\\b",
            "-dev",
            "_dev",
            "dev prod",
            "dev\0",
            "dév",
            too_long.as_str(),
        ] {
            match validate_scope_name(scope) {
                Err(CryptoError::InvalidScopeName { .. }) => {}
                other => panic!("{scope:?} should be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn accepts_valid_secret_keys() {
        let long = "K".repeat(MAX_SECRET_KEY_BYTES);
        for key in ["DATABASE_URL", "_PRIVATE", "a", "api_key_2", long.as_str()] {
            if let Err(error) = validate_secret_key(key) {
                panic!("{key:?} should be valid: {error}");
            }
        }
    }

    #[test]
    fn rejects_invalid_secret_keys() {
        let too_long = "K".repeat(MAX_SECRET_KEY_BYTES + 1);
        for key in [
            "",
            "1PASSWORD",
            "API-KEY",
            "API.KEY",
            "API KEY",
            "KEY=VALUE",
            "KÉY",
            too_long.as_str(),
        ] {
            match validate_secret_key(key) {
                Err(CryptoError::InvalidSecretKey { .. }) => {}
                other => panic!("{key:?} should be rejected, got {other:?}"),
            }
        }
    }
}
