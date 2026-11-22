//! Client-side secret encryption for Scrim for Git.
//!
//! Each secret scope (such as `dev` or `prod`) has a random 32-byte
//! [`ScopeDataKey`]. The data key encrypts the scope's secrets with
//! XChaCha20-Poly1305 into `.scrim/secrets/<scope>.enc`
//! ([`EncryptedSecretsFile`]), and is itself wrapped with `age` X25519 for
//! every member allowed to read the scope in `.scrim/keys/<scope>.toml`
//! ([`ScopeKeysFile`]).
//!
//! Both files bind their scope name and key generation cryptographically: the
//! wrapped key payload embeds them inside the `age` ciphertext, and the secrets
//! ciphertext authenticates them as associated data. A blob copied from one
//! scope or generation into another therefore fails to decrypt instead of
//! silently yielding the wrong secrets. [`rotate_scope`] replaces the data key,
//! re-wraps it for a new recipient set and re-encrypts the secrets, so removed
//! members lose access to everything written afterwards.
//!
//! This crate implements no cryptographic primitives itself; it only composes
//! the audited `age` and `chacha20poly1305` crates.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod dotenv;
mod identity;
mod rotation;
mod scope_key;
mod secrets;
mod validation;

pub use dotenv::format_dotenv;
pub use identity::{MemberIdentity, MemberPublicKey};
pub use rotation::{RotatedScope, rotate_scope};
pub use scope_key::{ScopeDataKey, ScopeKeysFile, WrappedRecipientKey};
pub use secrecy::{ExposeSecret, SecretString};
pub use secrets::{EncryptedSecretsFile, SecretBundle};
pub use validation::{
    MAX_SCOPE_NAME_BYTES, MAX_SECRET_KEY_BYTES, MAX_SECRET_VALUE_BYTES, MAX_SECRETS_PER_SCOPE,
    validate_scope_name, validate_secret_key,
};

/// The only on-disk format version of both `.scrim/keys/<scope>.toml` and
/// `.scrim/secrets/<scope>.enc` this crate reads or writes.
pub const FILE_FORMAT_VERSION: u32 = 1;

/// Errors produced while validating, encrypting or decrypting scope keys and
/// secrets.
///
/// No variant ever carries secret key material or secret values.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The scope name breaks a naming rule (see [`validate_scope_name`]).
    #[error("invalid scope name {scope:?}: {reason}")]
    InvalidScopeName {
        /// The rejected scope name.
        scope: String,
        /// Human-readable description of the broken rule.
        reason: &'static str,
    },
    /// The secret key breaks a naming rule (see [`validate_secret_key`]).
    #[error("invalid secret key {key:?}: {reason}")]
    InvalidSecretKey {
        /// The rejected key name.
        key: String,
        /// Human-readable description of the broken rule.
        reason: &'static str,
    },
    /// A secret value exceeds [`MAX_SECRET_VALUE_BYTES`].
    #[error("secret {key:?} is larger than the {max_bytes}-byte limit")]
    SecretValueTooLarge {
        /// Name of the oversized secret.
        key: String,
        /// The enforced limit.
        max_bytes: usize,
    },
    /// A scope would hold more than [`MAX_SECRETS_PER_SCOPE`] secrets.
    #[error("a scope may hold at most {max} secrets")]
    TooManySecrets {
        /// The enforced limit.
        max: usize,
    },
    /// The text is not a valid `AGE-SECRET-KEY-1...` identity. The input is
    /// deliberately not echoed because it may be secret.
    #[error("invalid age identity")]
    InvalidIdentity,
    /// The text is not a canonical `age1...` X25519 public key. The input is
    /// not echoed, in case a secret identity was pasted by mistake.
    #[error("invalid age public key: {reason}")]
    InvalidPublicKey {
        /// Human-readable description of the problem.
        reason: &'static str,
    },
    /// A file declares a format version other than [`FILE_FORMAT_VERSION`].
    #[error("unsupported file format version {found} (expected {FILE_FORMAT_VERSION})")]
    UnsupportedVersion {
        /// The version found in the file.
        found: u32,
    },
    /// Key generations start at 1; 0 is never valid.
    #[error("key generation must be at least 1")]
    InvalidGeneration,
    /// The key generation cannot be incremented any further.
    #[error("key generation overflowed")]
    GenerationOverflow,
    /// A file belongs to a different scope than the caller expected.
    #[error("file is for scope {found:?}, expected {expected:?}")]
    ScopeMismatch {
        /// The scope the caller asked for.
        expected: String,
        /// The scope recorded in the file.
        found: String,
    },
    /// A file belongs to a different key generation than the caller expected.
    #[error("file is for key generation {found}, expected {expected}")]
    GenerationMismatch {
        /// The generation the caller asked for.
        expected: u64,
        /// The generation recorded in the file.
        found: u64,
    },
    /// A data key must be wrapped for at least one recipient.
    #[error("at least one recipient is required")]
    NoRecipients,
    /// The same member appears more than once in a keys file.
    #[error("member {member:?} is listed more than once")]
    DuplicateMember {
        /// The repeated member name.
        member: String,
    },
    /// The identity is not a recipient of this scope's data key, or its
    /// wrapped key could not be decrypted.
    #[error("identity is not authorized to decrypt this scope")]
    Unauthorized,
    /// The wrapped key decrypted, but was bound to a different scope or
    /// generation (a substituted or rolled-back blob) or was malformed.
    #[error("wrapped key is not bound to this scope and generation")]
    WrappedKeyMismatch,
    /// Authenticated decryption of the secrets failed: wrong key, or the
    /// ciphertext, nonce, scope or generation was tampered with.
    #[error("secrets failed authenticated decryption")]
    DecryptionFailed,
    /// The decrypted secrets payload is not a JSON object of strings. Parser
    /// details are deliberately dropped because they may quote secret values.
    #[error("decrypted secrets payload is malformed")]
    MalformedSecretsPayload,
    /// A base64 field is malformed or decodes to the wrong length.
    #[error("invalid encoding in field {field}")]
    InvalidEncoding {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A TOML file could not be parsed.
    #[error("invalid TOML: {0}")]
    InvalidToml(String),
    /// A value could not be serialized to TOML or JSON.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// Encryption failed inside `age` or the AEAD.
    #[error("encryption failed: {0}")]
    Encryption(String),
    /// The operating system's random number generator failed.
    #[error("random number generation failed: {0}")]
    Random(String),
}
