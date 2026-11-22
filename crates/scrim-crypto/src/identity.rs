//! Member X25519 identities and public keys, backed by `age::x25519`.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use secrecy::SecretString;

use crate::CryptoError;

/// A member's private `age` X25519 identity (`AGE-SECRET-KEY-1...`).
///
/// Its `Debug` output is always `MemberIdentity([REDACTED])`.
#[derive(Clone)]
pub struct MemberIdentity(age::x25519::Identity);

impl MemberIdentity {
    /// Generates a fresh identity from the operating system's RNG.
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    /// Parses an `AGE-SECRET-KEY-1...` identity, ignoring surrounding
    /// whitespace (such as a trailing newline in a key file).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidIdentity`] without echoing the input.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        match input.trim().parse::<age::x25519::Identity>() {
            Ok(identity) => Ok(Self(identity)),
            Err(_) => Err(CryptoError::InvalidIdentity),
        }
    }

    /// Serializes the identity as `AGE-SECRET-KEY-1...`.
    pub fn to_secret_string(&self) -> SecretString {
        self.0.to_string()
    }

    /// Returns the public key other members wrap scope keys to.
    pub fn public_key(&self) -> MemberPublicKey {
        MemberPublicKey::from_recipient(self.0.to_public())
    }

    pub(crate) fn as_age_identity(&self) -> &age::x25519::Identity {
        &self.0
    }
}

impl fmt::Debug for MemberIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemberIdentity([REDACTED])")
    }
}

/// A member's public `age` X25519 recipient key (`age1...`).
///
/// Equality and ordering compare the canonical `age1...` string.
#[derive(Clone)]
pub struct MemberPublicKey {
    recipient: age::x25519::Recipient,
    canonical: String,
}

impl MemberPublicKey {
    /// Parses a canonical `age1...` X25519 public key.
    ///
    /// Parsing is strict: the input must be exactly the canonical lowercase
    /// encoding, with no surrounding whitespace, so each key has one spelling
    /// in `.scrim/keys/*.toml`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPublicKey`] for anything else.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        let recipient = match input.parse::<age::x25519::Recipient>() {
            Ok(recipient) => recipient,
            Err(reason) => {
                return Err(CryptoError::InvalidPublicKey { reason });
            }
        };
        let key = Self::from_recipient(recipient);
        if key.canonical != input {
            return Err(CryptoError::InvalidPublicKey {
                reason: "not the canonical lowercase age1 encoding",
            });
        }
        Ok(key)
    }

    /// Returns the canonical `age1...` string.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    fn from_recipient(recipient: age::x25519::Recipient) -> Self {
        let canonical = recipient.to_string();
        Self {
            recipient,
            canonical,
        }
    }

    pub(crate) fn as_age_recipient(&self) -> &age::x25519::Recipient {
        &self.recipient
    }
}

impl PartialEq for MemberPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for MemberPublicKey {}

impl PartialOrd for MemberPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemberPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for MemberPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl fmt::Debug for MemberPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MemberPublicKey({})", self.canonical)
    }
}

impl fmt::Display for MemberPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn identity_round_trips_through_its_string_form() {
        let identity = MemberIdentity::generate();
        let secret = identity.to_secret_string();
        assert!(secret.expose_secret().starts_with("AGE-SECRET-KEY-1"));
        let padded = format!("  {}\n", secret.expose_secret());
        match MemberIdentity::parse(&padded) {
            Ok(parsed) => assert_eq!(parsed.public_key(), identity.public_key()),
            Err(error) => panic!("identity should parse: {error}"),
        }
    }

    #[test]
    fn identity_debug_is_redacted() {
        let identity = MemberIdentity::generate();
        let secret = identity.to_secret_string();
        let debug = format!("{identity:?}");
        assert_eq!(debug, "MemberIdentity([REDACTED])");
        assert!(!debug.contains(secret.expose_secret()));
    }

    #[test]
    fn invalid_identity_is_not_echoed() {
        match MemberIdentity::parse("AGE-SECRET-KEY-1NOTREALLY") {
            Err(error) => assert!(!error.to_string().contains("NOTREALLY")),
            Ok(_) => panic!("garbage identity should be rejected"),
        }
        let public = MemberIdentity::generate().public_key();
        if MemberIdentity::parse(public.as_str()).is_ok() {
            panic!("a public key is not an identity");
        }
    }

    #[test]
    fn public_key_parses_only_canonical_form() {
        let public = MemberIdentity::generate().public_key();
        assert!(public.as_str().starts_with("age1"));
        assert_eq!(public.to_string(), public.as_str());
        match MemberPublicKey::parse(public.as_str()) {
            Ok(parsed) => assert_eq!(parsed, public),
            Err(error) => panic!("canonical key should parse: {error}"),
        }
        let upper = public.as_str().to_uppercase();
        let spaced = format!(" {public}");
        let newline = format!("{public}\n");
        let identity_secret = MemberIdentity::generate().to_secret_string();
        for input in [
            upper.as_str(),
            spaced.as_str(),
            newline.as_str(),
            "",
            "age1",
            identity_secret.expose_secret(),
        ] {
            match MemberPublicKey::parse(input) {
                Err(CryptoError::InvalidPublicKey { .. }) => {}
                other => panic!("{input:?} should be rejected, got {other:?}"),
            }
        }
    }
}
