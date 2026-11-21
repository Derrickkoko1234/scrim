//! Constant-time token authentication for Git smart-HTTP requests.
//!
//! Configured tokens are hashed with SHA-256 at startup so plaintext secrets are
//! not retained in memory. Incoming `Authorization` headers (`Bearer` or
//! `Basic`) are parsed, the candidate token is hashed, and the hash is looked up
//! in the [`PolicyStore`] before decompression or repository path resolution.

use std::{fmt, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::policy_store::PolicyStore;

/// Maximum accepted byte length for a configured authentication token.
pub const MAX_TOKEN_BYTES: usize = 1024;

/// Maximum accepted byte length for an incoming `Authorization` header value.
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;

/// Challenge header value returned on `401 Unauthorized` responses so `git`
/// prompts or consults configured credential helpers.
const WWW_AUTHENTICATE_VALUE: &str = "Basic realm=\"Scrim\"";

/// Errors returned when validating a configured authentication token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthConfigError {
    /// The configured token is empty.
    EmptyToken,
    /// The configured token exceeds [`MAX_TOKEN_BYTES`].
    TokenTooLong {
        /// Maximum allowed byte length.
        max_bytes: usize,
    },
    /// The configured token contains whitespace, control bytes, or non-ASCII characters.
    InvalidTokenCharacter,
}

impl fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyToken => f.write_str("token must not be empty"),
            Self::TokenTooLong { max_bytes } => {
                write!(f, "token exceeds maximum length of {max_bytes} bytes")
            }
            Self::InvalidTokenCharacter => {
                f.write_str("token must contain only printable ASCII characters without spaces")
            }
        }
    }
}

impl std::error::Error for AuthConfigError {}

/// Verifier for the server's configured authentication token.
///
/// Stores only the SHA-256 digest of the token in zeroized memory and compares
/// incoming candidate tokens in constant time.
#[derive(Clone)]
pub struct TokenAuth {
    digest: Arc<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for TokenAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never include the digest or any token-derived material in debug output.
        f.debug_struct("TokenAuth").finish_non_exhaustive()
    }
}

impl TokenAuth {
    /// Validates `token` and hashes it into a [`TokenAuth`] verifier.
    ///
    /// Returns an [`AuthConfigError`] if the token is empty, longer than
    /// 1024 bytes, or contains any byte outside printable non-space ASCII
    /// (`0x21..=0x7E`).
    pub fn new(token: SecretString) -> Result<Self, AuthConfigError> {
        let secret = token.expose_secret();
        if secret.is_empty() {
            return Err(AuthConfigError::EmptyToken);
        }
        if secret.len() > MAX_TOKEN_BYTES {
            return Err(AuthConfigError::TokenTooLong {
                max_bytes: MAX_TOKEN_BYTES,
            });
        }
        if !secret.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(AuthConfigError::InvalidTokenCharacter);
        }

        let digest = sha256_zeroizing(secret.as_bytes());
        Ok(Self {
            digest: Arc::new(digest),
        })
    }

    /// Returns whether `candidate` matches the configured token.
    ///
    /// Rejects empty or oversized candidates before hashing, and compares the
    /// resulting 32-byte SHA-256 digests in constant time.
    pub fn verify(&self, candidate: &[u8]) -> bool {
        if candidate.is_empty() || candidate.len() > MAX_TOKEN_BYTES {
            return false;
        }
        let candidate_digest = sha256_zeroizing(candidate);
        self.verify_hash(&candidate_digest)
    }

    /// Returns whether `candidate_digest` is the SHA-256 digest of the
    /// configured token, compared in constant time.
    pub(crate) fn verify_hash(&self, candidate_digest: &[u8; 32]) -> bool {
        bool::from(self.digest.as_slice().ct_eq(candidate_digest.as_slice()))
    }
}

/// Computes the SHA-256 digest of `input` directly into a zeroizing buffer.
///
/// With `sha2`'s `zeroize` feature enabled, `Sha256` wipes its internal block
/// buffer and chaining state on drop, and `finalize_into` writes straight into
/// the zeroizing output array without an unzeroized stack copy.
pub(crate) fn sha256_zeroizing(input: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut digest = Zeroizing::new([0u8; 32]);
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize_into((&mut *digest).into());
    digest
}

/// Axum middleware that requires a single valid `Authorization` header on
/// every incoming request.
///
/// The candidate token's SHA-256 hash is looked up in `policy_store`. A match
/// inserts the [`AuthenticatedMember`](crate::AuthenticatedMember) into the
/// request extensions; no match yields `401`; a store failure yields `500` so
/// an unreachable database never lets a request through.
pub(crate) async fn require_auth(
    State(policy_store): State<Arc<dyn PolicyStore>>,
    mut request: Request,
    next: Next,
) -> Response {
    let mut auth_headers = request.headers().get_all(header::AUTHORIZATION).iter();
    let Some(header_value) = auth_headers.next() else {
        return unauthorized_response();
    };
    // Reject duplicate Authorization headers to avoid proxy/parser ambiguity.
    if auth_headers.next().is_some() {
        return unauthorized_response();
    }
    if header_value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return unauthorized_response();
    }
    let Ok(header_str) = header_value.to_str() else {
        return unauthorized_response();
    };
    let Some(token_hash) = candidate_token_hash(header_str) else {
        return unauthorized_response();
    };

    let member = match policy_store.authenticate_token_hash(&token_hash).await {
        Ok(Some(member)) => member,
        Ok(None) => return unauthorized_response(),
        Err(error) => {
            // The error describes the store failure only; it never contains
            // the token or its hash.
            tracing::error!(%error, "failed to authenticate request");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Strip the credential once verified so downstream handlers cannot log or forward it.
    request.headers_mut().remove(header::AUTHORIZATION);
    request.extensions_mut().insert(member);
    next.run(request).await
}

/// Parses a single `Authorization` header value (`Bearer` or `Basic`) and
/// returns the SHA-256 hash of the candidate token it carries.
///
/// Returns `None` for an unknown scheme, malformed credentials, or a candidate
/// that is empty or longer than [`MAX_TOKEN_BYTES`] (no configured token can be
/// either, so those are rejected before hashing).
fn candidate_token_hash(header_value: &str) -> Option<Zeroizing<[u8; 32]>> {
    let Some((scheme, remainder)) = header_value.split_once(' ') else {
        return None;
    };
    // RFC 9110 allows one or more SP octets between auth-scheme and token68.
    let credentials = remainder.trim_start_matches(' ');
    if credentials.is_empty() || credentials.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }

    if scheme.eq_ignore_ascii_case("bearer") {
        return hash_candidate(credentials.as_bytes());
    }

    if scheme.eq_ignore_ascii_case("basic") {
        // Pre-allocate the full upper bound so decoding never reallocates and
        // leaves credential prefixes in freed heap memory.
        let max_decoded_len = (credentials.len() / 4).saturating_add(1).saturating_mul(3);
        let mut decoded = Zeroizing::new(Vec::with_capacity(max_decoded_len));
        if STANDARD.decode_vec(credentials, &mut decoded).is_err() {
            return None;
        }
        let Some(colon_index) = decoded.iter().position(|&byte| byte == b':') else {
            return None;
        };
        let username = &decoded[..colon_index];
        let password = &decoded[colon_index + 1..];

        // Support `user:token`, `:token`, and `token:` (e.g. `https://TOKEN@host`).
        // When a non-empty password is supplied, never fall back to username.
        if !password.is_empty() {
            return hash_candidate(password);
        }
        if !username.is_empty() {
            return hash_candidate(username);
        }
        return None;
    }

    None
}

/// Hashes `candidate` unless it is empty or longer than [`MAX_TOKEN_BYTES`].
fn hash_candidate(candidate: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if candidate.is_empty() || candidate.len() > MAX_TOKEN_BYTES {
        return None;
    }
    Some(sha256_zeroizing(candidate))
}

/// Builds a non-cacheable `401 Unauthorized` response with a Basic challenge.
fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, WWW_AUTHENTICATE_VALUE),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "Fri, 01 Jan 1980 00:00:00 GMT"),
        ],
        "unauthorized",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{HeaderValue, Request, StatusCode, header},
        middleware,
        routing::get,
    };
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    };
    use std::sync::Arc;

    use http_body_util::BodyExt;
    use secrecy::SecretString;
    use tower::ServiceExt;

    use super::{
        AuthConfigError, MAX_AUTHORIZATION_HEADER_BYTES, MAX_TOKEN_BYTES, TokenAuth,
        WWW_AUTHENTICATE_VALUE, candidate_token_hash, require_auth,
    };
    use crate::policy_store::{
        AuthenticatedMember, MemberRepoPolicy, PolicyStore, PolicyStoreError, PolicyStoreFuture,
        StaticPolicyStore,
    };

    /// Returns whether `header_value` carries the token `auth` was built from,
    /// following the same parsing path as the middleware.
    fn authorize_header_value(auth: &TokenAuth, header_value: &str) -> bool {
        match candidate_token_hash(header_value) {
            Some(token_hash) => auth.verify_hash(&token_hash),
            None => false,
        }
    }

    /// A store whose every lookup fails, as if the database were unreachable.
    struct FailingPolicyStore;

    impl PolicyStore for FailingPolicyStore {
        fn authenticate_token_hash<'a>(
            &'a self,
            _token_hash: &'a [u8; 32],
        ) -> PolicyStoreFuture<'a, Option<AuthenticatedMember>> {
            Box::pin(async { Err(PolicyStoreError::Internal("store offline".to_owned())) })
        }

        fn load_member_repo_policy<'a>(
            &'a self,
            _member_id: i64,
            _repo_key: &'a str,
        ) -> PolicyStoreFuture<'a, MemberRepoPolicy> {
            Box::pin(async { Err(PolicyStoreError::Internal("store offline".to_owned())) })
        }
    }

    fn make_auth(token: &str) -> TokenAuth {
        match TokenAuth::new(SecretString::from(token.to_owned())) {
            Ok(auth) => auth,
            Err(error) => panic!("failed to construct test TokenAuth: {error}"),
        }
    }

    fn basic_header(credentials: &[u8]) -> String {
        format!("Basic {}", STANDARD.encode(credentials))
    }

    fn test_router(auth: TokenAuth) -> Router {
        router_with_store(Arc::new(StaticPolicyStore::new(auth)))
    }

    fn router_with_store(policy_store: Arc<dyn PolicyStore>) -> Router {
        Router::new()
            .route(
                "/",
                get(|request: Request<Body>| async move {
                    // Downstream handlers must never see the raw Authorization header.
                    assert!(request.headers().get(header::AUTHORIZATION).is_none());
                    // ...but must see who was authenticated.
                    assert!(request.extensions().get::<AuthenticatedMember>().is_some());
                    "ok"
                }),
            )
            .layer(middleware::from_fn_with_state(policy_store, require_auth))
    }

    async fn assert_unauthorized(response: axum::response::Response) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(WWW_AUTHENTICATE_VALUE)
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert_eq!(
            response
                .headers()
                .get(header::EXPIRES)
                .and_then(|value| value.to_str().ok()),
            Some("Fri, 01 Jan 1980 00:00:00 GMT")
        );
        let body = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => panic!("failed to read response body: {error}"),
        };
        assert_eq!(body.as_ref(), b"unauthorized");
    }

    #[test]
    fn validates_configured_token() {
        assert_eq!(
            TokenAuth::new(SecretString::from(String::new())).err(),
            Some(AuthConfigError::EmptyToken)
        );

        let max_len_token = "a".repeat(MAX_TOKEN_BYTES);
        assert!(TokenAuth::new(SecretString::from(max_len_token)).is_ok());

        let too_long_token = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert_eq!(
            TokenAuth::new(SecretString::from(too_long_token)).err(),
            Some(AuthConfigError::TokenTooLong {
                max_bytes: MAX_TOKEN_BYTES,
            })
        );

        for invalid in [
            "has space",
            "has\nnewline",
            "has\ttab",
            "nonascii-\u{e9}",
            "\x00",
        ] {
            assert_eq!(
                TokenAuth::new(SecretString::from(invalid.to_owned())).err(),
                Some(AuthConfigError::InvalidTokenCharacter),
                "expected InvalidTokenCharacter for {invalid:?}"
            );
        }
    }

    #[test]
    fn debug_does_not_leak_token_or_digest() {
        let token = "super-secret-token-value-1234";
        let auth = make_auth(token);
        let debug_output = format!("{auth:?}");
        assert!(!debug_output.contains(token));
        assert!(debug_output.contains("TokenAuth"));
    }

    #[test]
    fn verify_checks_exact_token_and_bounds() {
        let auth = make_auth("correct-token");
        assert!(auth.verify(b"correct-token"));
        assert!(!auth.verify(b""));
        assert!(!auth.verify(b"wrong-token"));
        assert!(!auth.verify(b"correct-token-extra"));
        let oversized = vec![b'a'; MAX_TOKEN_BYTES + 1];
        assert!(!auth.verify(&oversized));
    }

    #[test]
    fn authorizes_bearer_headers() {
        let auth = make_auth("secret-bearer-token");

        assert!(authorize_header_value(&auth, "Bearer secret-bearer-token"));
        assert!(authorize_header_value(&auth, "bearer secret-bearer-token"));
        assert!(authorize_header_value(
            &auth,
            "BEARER   secret-bearer-token"
        ));

        assert!(!authorize_header_value(&auth, "Bearer"));
        assert!(!authorize_header_value(&auth, "Bearer "));
        assert!(!authorize_header_value(&auth, "Bearer wrong-token"));
        assert!(!authorize_header_value(
            &auth,
            "Bearer secret-bearer-token "
        ));
        assert!(!authorize_header_value(&auth, "Bearer secret\ttoken"));
        assert!(!authorize_header_value(
            &auth,
            "Bearer\tsecret-bearer-token"
        ));
    }

    #[test]
    fn authorizes_basic_headers_and_enforces_precedence() {
        let colon_auth = make_auth("my:secret");

        // Colons inside the password are preserved because we split on the first `:`.
        assert!(authorize_header_value(
            &colon_auth,
            &basic_header(b"alice:my:secret")
        ));
        assert!(authorize_header_value(
            &colon_auth,
            &basic_header(b":my:secret")
        ));
        assert!(!authorize_header_value(
            &colon_auth,
            &basic_header(b"my:secret:wrong")
        ));
        assert!(!authorize_header_value(
            &colon_auth,
            &basic_header(b"alice:wrong")
        ));

        let auth = make_auth("plainsecret");
        assert!(authorize_header_value(
            &auth,
            &basic_header(b"user:plainsecret")
        ));
        assert!(authorize_header_value(
            &auth,
            &basic_header(b":plainsecret")
        ));
        assert!(authorize_header_value(
            &auth,
            &basic_header(b"plainsecret:")
        ));

        // Do not fall back to username when password is non-empty.
        assert!(!authorize_header_value(
            &auth,
            &basic_header(b"plainsecret:wrong")
        ));
        assert!(!authorize_header_value(&auth, &basic_header(b":")));
        assert!(!authorize_header_value(
            &auth,
            &basic_header(b"plainsecret")
        ));

        // Invalid or unpadded base64 must be rejected.
        assert!(!authorize_header_value(&auth, "Basic !!!not-base64!!!"));
        let unpadded = STANDARD_NO_PAD.encode(b"user:plainsecret");
        assert!(!authorize_header_value(&auth, &format!("Basic {unpadded}")));
    }

    #[test]
    fn rejects_unknown_schemes_and_oversized_headers() {
        let auth = make_auth("secret-token");
        assert!(!authorize_header_value(&auth, "Token secret-token"));
        assert!(!authorize_header_value(&auth, "Digest username=\"a\""));
        assert!(!authorize_header_value(&auth, "secret-token"));

        let oversized = format!("Bearer {}", "a".repeat(MAX_AUTHORIZATION_HEADER_BYTES));
        assert!(oversized.len() > MAX_AUTHORIZATION_HEADER_BYTES);
        assert!(!authorize_header_value(&auth, &oversized));
    }

    #[tokio::test]
    async fn middleware_enforces_header_rules_and_returns_challenge() {
        let auth = make_auth("secret-token");

        // Missing Authorization header.
        let missing = match Request::builder().uri("/").body(Body::empty()) {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };
        let response = match test_router(auth.clone()).oneshot(missing).await {
            Ok(response) => response,
            Err(error) => panic!("router call failed: {error}"),
        };
        assert_unauthorized(response).await;

        // Duplicate Authorization headers (even if both are valid).
        let duplicate = match Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer secret-token")
            .header(header::AUTHORIZATION, "Bearer secret-token")
            .body(Body::empty())
        {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };
        let response = match test_router(auth.clone()).oneshot(duplicate).await {
            Ok(response) => response,
            Err(error) => panic!("router call failed: {error}"),
        };
        assert_unauthorized(response).await;

        // Oversized Authorization header (> MAX_AUTHORIZATION_HEADER_BYTES).
        let oversized_value = format!(
            "Bearer {}",
            "a".repeat(MAX_AUTHORIZATION_HEADER_BYTES - "Bearer ".len() + 1)
        );
        assert!(oversized_value.len() > MAX_AUTHORIZATION_HEADER_BYTES);
        let oversized = match Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, oversized_value)
            .body(Body::empty())
        {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };
        let response = match test_router(auth.clone()).oneshot(oversized).await {
            Ok(response) => response,
            Err(error) => panic!("router call failed: {error}"),
        };
        assert_unauthorized(response).await;

        // Non-UTF-8 Authorization header.
        let non_utf8_value = match HeaderValue::from_bytes(b"Bearer \xff\xfe") {
            Ok(value) => value,
            Err(error) => panic!("failed to build HeaderValue: {error}"),
        };
        let non_utf8 = match Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, non_utf8_value)
            .body(Body::empty())
        {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };
        let response = match test_router(auth.clone()).oneshot(non_utf8).await {
            Ok(response) => response,
            Err(error) => panic!("router call failed: {error}"),
        };
        assert_unauthorized(response).await;

        // Valid Authorization header passes through.
        let valid = match Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer secret-token")
            .body(Body::empty())
        {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };
        let response = match test_router(auth).oneshot(valid).await {
            Ok(response) => response,
            Err(error) => panic!("router call failed: {error}"),
        };
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn store_failure_fails_closed_with_internal_server_error() {
        let request = match Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer any-token")
            .body(Body::empty())
        {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };
        let response = match router_with_store(Arc::new(FailingPolicyStore))
            .oneshot(request)
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("router call failed: {error}"),
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
