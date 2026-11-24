//! Backups of the bare repositories and PostgreSQL to Cloudflare R2.
//!
//! [`run_backup`] snapshots every bare repository under the repository root
//! (an isolated `git clone --mirror`, so concurrent pushes cannot tear the
//! copy), archives each as a `.tar.gz` into a staging file on disk while
//! computing its SHA-256 and byte length in a single pass, streams each
//! archive from disk with O(1) memory, optionally runs `pg_dump` to a staging
//! file and streams it from disk, and finally writes a [`BackupManifest`] plus
//! a [`LatestBackupPointer`]. Each per-repo staging archive is deleted right
//! after its upload so staging disk usage stays bounded to one repository at
//! a time. [`run_restore`] reverses that, verifying every object's exact
//! SHA-256 digest before it is decompressed or handed to `pg_restore`, and
//! refusing any archive entry other than plain files and directories at safe
//! relative paths.
//!
//! [`list_backups`] enumerates and validates backups stored under the
//! configured prefix, and [`prune_backups`] enforces a retention count while
//! keeping `latest.json` protected.
//!
//! R2 is spoken to through its S3-compatible API with path-style URLs and
//! AWS Signature Version 4 (see [`sign_s3_request`]). Database credentials only
//! ever reach `pg_dump`/`pg_restore` through `PG*` environment variables, never
//! their arguments, and child processes start from a cleared environment so
//! no other secret is inherited.
//!
//! Large objects (repository archives and database dumps) stream both to and
//! from disk (R2 accepts at most [`MAX_BACKUP_OBJECT_BYTES`] per single PUT);
//! only small JSON payloads (`manifest.json` and `latest.json`) and XML
//! `ListObjectsV2` responses are held in memory.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow, bail};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::{
    policy_store::{format_unix_seconds_utc, validate_repository_path},
    pre_receive::{encode_hex, generate_random_hex},
    repo_path::{is_valid_repo_path, resolve_bare_repo},
};

/// The only [`BackupManifest::version`] this server writes and restores.
pub const BACKUP_MANIFEST_VERSION: u32 = 1;

/// Key prefix used when none is configured.
pub const DEFAULT_R2_PREFIX: &str = "scrim-backups";

/// Largest object uploaded or downloaded: R2's single-PUT limit (5 GiB).
pub const MAX_BACKUP_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Largest manifest or `latest.json` pointer accepted.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Largest `ListObjectsV2` XML response page accepted.
const MAX_LIST_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Most `ListObjectsV2` pages followed per listing request.
const MAX_LIST_PAGES: usize = 10_000;

/// Most object keys accumulated across `ListObjectsV2` pages.
const MAX_LIST_OBJECTS: usize = 1_000_000;

/// Most bytes one repository archive may expand to, against gzip bombs.
const MAX_EXTRACTED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Most entries one repository archive may hold.
const MAX_ARCHIVE_ENTRIES: u64 = 10_000_000;

/// Most bytes of an error response body quoted in an error message.
const MAX_ERROR_BODY_BYTES: usize = 1024;

/// Most bytes of a child process's stderr quoted in an error message.
const MAX_STDERR_QUOTE_BYTES: usize = 2048;

/// R2's SigV4 region.
const R2_REGION: &str = "auto";

/// SigV4 service name of the S3 API.
const S3_SERVICE: &str = "s3";

/// SHA-256 of the empty payload, sent with every body-less request.
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Whole-request timeout, generous enough for a maximal object.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Where backups are stored: an S3-compatible bucket such as Cloudflare R2.
#[derive(Clone, Debug)]
pub struct R2Config {
    /// Endpoint origin, e.g. `https://<account>.r2.cloudflarestorage.com`.
    /// Must be `https`, except for loopback hosts (tests and local mocks).
    pub endpoint: String,
    /// Bucket name (3 to 63 lowercase letters, digits, `.` or `-`).
    pub bucket: String,
    /// Access key ID of an R2 API token.
    pub access_key_id: String,
    /// Secret access key of that token.
    pub secret_access_key: SecretString,
    /// Key prefix of every object, `/`-separated safe segments (surrounding
    /// slashes are ignored); see [`DEFAULT_R2_PREFIX`].
    pub prefix: String,
}

/// Input of [`run_backup`].
#[derive(Clone, Debug)]
pub struct BackupConfig {
    /// Directory holding the bare repositories.
    pub repo_root: PathBuf,
    /// PostgreSQL URL to dump, if any (`postgres://user:password@host/db`).
    pub database_url: Option<SecretString>,
    /// Destination bucket.
    pub r2: R2Config,
    /// `pg_dump` executable (looked up on `PATH` if not a path).
    pub pg_dump_bin: PathBuf,
    /// Optional retention count: when `Some(n)`, prunes older backups after
    /// `latest.json` is published, keeping at least `n` newest valid backups
    /// plus the `latest.json` target.
    pub keep: Option<usize>,
}

/// Summary of one backup stored in R2, returned by [`list_backups`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSummary {
    /// Unique backup ID.
    pub backup_id: String,
    /// RFC 3339 UTC timestamp recorded in the backup manifest.
    pub created_at_utc: String,
    /// Number of repository archives in the backup.
    pub repo_count: usize,
    /// Whether a PostgreSQL database dump is included.
    pub has_database: bool,
    /// Total byte size of all artifacts recorded in the manifest.
    pub total_size_bytes: u64,
    /// Whether `<prefix>/latest.json` currently points at this backup.
    pub is_latest: bool,
}

/// Input of [`prune_backups`].
#[derive(Clone, Debug)]
pub struct PruneConfig {
    /// Bucket containing the backups.
    pub r2: R2Config,
    /// Number of newest valid backups to retain (must be at least 1).
    pub keep: usize,
    /// When `true`, compute which backups would be pruned without deleting any
    /// objects from R2.
    pub dry_run: bool,
}

/// Outcome of [`prune_backups`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    /// Backup IDs retained (the `keep` newest plus the `latest.json` target, if any).
    pub kept: Vec<String>,
    /// Backup IDs deleted (or selected for deletion when `dry_run` is `true`).
    pub pruned: Vec<String>,
    /// Number of R2 objects deleted (always `0` when `dry_run` is `true`).
    pub deleted_objects: usize,
    /// Whether this run was a dry run.
    pub dry_run: bool,
}

/// Input of [`run_restore`].
#[derive(Clone, Debug)]
pub struct RestoreConfig {
    /// Directory to restore the bare repositories into; it is created if
    /// missing and must be empty unless `force` is set.
    pub repo_root: PathBuf,
    /// PostgreSQL URL to restore into; the database dump is skipped if `None`.
    pub database_url: Option<SecretString>,
    /// Source bucket.
    pub r2: R2Config,
    /// Backup to restore; `None` or `"latest"` follows `latest.json`.
    pub backup_id: Option<String>,
    /// Restore into a non-empty repository root, replacing any repository at
    /// the same path.
    pub force: bool,
    /// `pg_restore` executable (looked up on `PATH` if not a path).
    pub pg_restore_bin: PathBuf,
}

/// One uploaded object and the digest it must match on restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupArtifact {
    /// Full object key, starting with the configured prefix.
    pub object_key: String,
    /// Lowercase hex SHA-256 of the object's bytes.
    pub sha256: String,
    /// Exact byte length of the object.
    pub size_bytes: u64,
}

/// One repository archive in a [`BackupManifest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRepoEntry {
    /// Canonical repository key, e.g. `team/app.git`.
    pub repo_key: String,
    /// Full object key of the `.tar.gz` archive.
    pub object_key: String,
    /// Lowercase hex SHA-256 of the archive.
    pub sha256: String,
    /// Exact byte length of the archive.
    pub size_bytes: u64,
}

/// Everything one backup contains, stored at `{prefix}/{backup_id}/manifest.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Always [`BACKUP_MANIFEST_VERSION`].
    pub version: u32,
    /// Unique ID, e.g. `20261122T101500Z-1a2b3c4d`.
    pub backup_id: String,
    /// RFC 3339 UTC time the backup started.
    pub created_at_utc: String,
    /// Repository archives, sorted by key.
    pub repos: Vec<BackupRepoEntry>,
    /// The database dump (`pg_dump --format=custom`), if one was taken.
    pub database: Option<BackupArtifact>,
}

/// The pointer at `{prefix}/latest.json` to the newest complete backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestBackupPointer {
    /// ID of the newest backup.
    pub backup_id: String,
    /// Key of its manifest.
    pub manifest_key: String,
    /// When it was taken.
    pub created_at_utc: String,
}

/// One request to sign with [`sign_s3_request`].
#[derive(Clone, Copy, Debug)]
pub struct S3SigningRequest<'a> {
    /// HTTP method, e.g. `PUT`.
    pub method: &'a str,
    /// Absolute request path, already URI-encoded (e.g. `/bucket/a%24b`).
    pub canonical_uri: &'a str,
    /// Query parameters, not yet encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// Every header to sign, including `host`, `x-amz-content-sha256` and
    /// `x-amz-date`; names in any case.
    pub headers: &'a [(&'a str, &'a str)],
    /// Lowercase hex SHA-256 of the payload (the `x-amz-content-sha256` value).
    pub payload_sha256: &'a str,
    /// Request time as `YYYYMMDDTHHMMSSZ` (the `x-amz-date` value).
    pub amz_date: &'a str,
    /// Region, `auto` for R2.
    pub region: &'a str,
    /// Service, `s3`.
    pub service: &'a str,
    /// Access key ID.
    pub access_key_id: &'a str,
    /// Secret access key.
    pub secret_access_key: &'a str,
}

/// Computes the AWS Signature Version 4 (`AWS4-HMAC-SHA256`) `Authorization`
/// header value for `request`.
///
/// # Errors
///
/// Fails if `amz_date` is not `YYYYMMDDTHHMMSSZ` or a header name is empty.
pub fn sign_s3_request(request: &S3SigningRequest<'_>) -> Result<String, String> {
    if !is_valid_amz_date(request.amz_date) {
        return Err("x-amz-date must be formatted as YYYYMMDDTHHMMSSZ".to_owned());
    }
    let mut headers: Vec<(String, String)> = Vec::with_capacity(request.headers.len());
    for (name, value) in request.headers {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err("cannot sign an empty header name".to_owned());
        }
        headers.push((name, collapse_header_whitespace(value)));
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_query = canonical_query_string(request.query);

    let canonical_request = format!(
        "{}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{}",
        request.method, request.canonical_uri, request.payload_sha256
    );
    let date = &request.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", request.region, request.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        request.amz_date,
        sha256_hex(canonical_request.as_bytes())
    );

    let mut secret_key = Zeroizing::new(Vec::with_capacity(4 + request.secret_access_key.len()));
    secret_key.extend_from_slice(b"AWS4");
    secret_key.extend_from_slice(request.secret_access_key.as_bytes());
    let mut signing_key = secret_key;
    for part in [date, request.region, request.service, "aws4_request"] {
        signing_key = match hmac_sha256(&signing_key, part.as_bytes()) {
            Ok(key) => key,
            Err(error) => return Err(error),
        };
    }
    let signature = match hmac_sha256(&signing_key, string_to_sign.as_bytes()) {
        Ok(signature) => encode_hex(&signature),
        Err(error) => return Err(error),
    };
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        request.access_key_id,
        signature.as_str()
    ))
}

/// HMAC-SHA256 of `data` under `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut mac = match <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return Err("cannot initialize HMAC-SHA256".to_owned()),
    };
    mac.update(data);
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

/// Whether `value` is `YYYYMMDDTHHMMSSZ`.
fn is_valid_amz_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 16
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..15].iter().all(u8::is_ascii_digit)
}

/// Trims `value` and collapses runs of spaces, as SigV4 canonical headers require.
fn collapse_header_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Builds a SigV4 canonical query string: RFC 3986 URI-encodes each name and
/// value, then sorts by encoded name and then encoded value.
fn canonical_query_string(params: &[(&str, &str)]) -> String {
    let mut query: Vec<(String, String)> = params
        .iter()
        .map(|(name, value)| (uri_encode(name, true), uri_encode(value, true)))
        .collect();
    query.sort();
    query
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encodes every byte of `value` except RFC 3986 unreserved
/// characters (and `/` unless `encode_slash`), with uppercase hex.
fn uri_encode(value: &str, encode_slash: bool) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (byte == b'/' && !encode_slash)
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

/// Lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    encode_hex(digest.as_slice()).as_str().to_owned()
}

/// Returns the current UTC time as `(RFC 3339, YYYYMMDDTHHMMSSZ)`.
fn current_timestamps() -> (String, String) {
    let mut unix_seconds = 0;
    if let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH)
        && let Ok(seconds) = i64::try_from(elapsed.as_secs())
    {
        unix_seconds = seconds;
    }
    let rfc3339 = format_unix_seconds_utc(unix_seconds);
    let amz_date = rfc3339.replace(['-', ':'], "");
    (rfc3339, amz_date)
}

/// A minimal S3 client for path-style object PUT, GET, DELETE and ListObjectsV2.
struct S3Client {
    http: reqwest::Client,
    /// `scheme://host[:port]`.
    origin: String,
    /// The `Host` header reqwest sends: host plus any non-default port.
    host: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: SecretString,
}

impl S3Client {
    /// Validates `config` and builds a client that never follows redirects.
    fn new(config: &R2Config) -> anyhow::Result<Self> {
        let endpoint = match reqwest::Url::parse(config.endpoint.trim()) {
            Ok(endpoint) => endpoint,
            Err(_) => bail!("the R2 endpoint is not a valid URL"),
        };
        let Some(host_name) = endpoint.host_str() else {
            bail!("the R2 endpoint has no host");
        };
        let is_loopback = matches!(host_name, "localhost" | "127.0.0.1" | "[::1]");
        match endpoint.scheme() {
            "https" => {}
            "http" if is_loopback => {}
            _ => bail!("the R2 endpoint must use https"),
        }
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || !matches!(endpoint.path(), "" | "/")
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!(
                "the R2 endpoint must be a bare origin such as https://<account>.r2.cloudflarestorage.com"
            );
        }
        if !is_valid_bucket_name(&config.bucket) {
            bail!("invalid R2 bucket name: use 3 to 63 lowercase letters, digits, '.' or '-'");
        }
        if config.access_key_id.is_empty()
            || !config
                .access_key_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'/')
        {
            bail!("the R2 access key ID is empty or malformed");
        }
        if config.secret_access_key.expose_secret().is_empty() {
            bail!("the R2 secret access key is empty");
        }
        let host = match endpoint.port() {
            Some(port) => format!("{host_name}:{port}"),
            None => host_name.to_owned(),
        };
        let http = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
        {
            Ok(http) => http,
            Err(error) => return Err(anyhow!("cannot build the HTTP client: {error}")),
        };
        Ok(Self {
            http,
            origin: format!("{}://{host}", endpoint.scheme()),
            host,
            bucket: config.bucket.clone(),
            access_key_id: config.access_key_id.clone(),
            secret_access_key: config.secret_access_key.clone(),
        })
    }

    /// Sends a signed S3 request and returns the raw HTTP response.
    async fn send_signed_raw(
        &self,
        method: &reqwest::Method,
        raw_path: &str,
        query: &[(&str, &str)],
        display_target: &str,
        payload_sha256: &str,
        body: Option<(reqwest::Body, u64)>,
    ) -> anyhow::Result<reqwest::Response> {
        let canonical_uri = uri_encode(raw_path, false);
        let (_, amz_date) = current_timestamps();
        let headers = [
            ("host", self.host.as_str()),
            ("x-amz-content-sha256", payload_sha256),
            ("x-amz-date", amz_date.as_str()),
        ];
        let authorization = match sign_s3_request(&S3SigningRequest {
            method: method.as_str(),
            canonical_uri: &canonical_uri,
            query,
            headers: &headers,
            payload_sha256,
            amz_date: &amz_date,
            region: R2_REGION,
            service: S3_SERVICE,
            access_key_id: &self.access_key_id,
            secret_access_key: self.secret_access_key.expose_secret(),
        }) {
            Ok(authorization) => authorization,
            Err(error) => bail!("cannot sign the request for {display_target}: {error}"),
        };
        let url = if query.is_empty() {
            format!("{}{canonical_uri}", self.origin)
        } else {
            let encoded_query = canonical_query_string(query);
            format!("{}{canonical_uri}?{encoded_query}", self.origin)
        };
        let mut request = self
            .http
            .request(method.clone(), url)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_sha256)
            .header(reqwest::header::AUTHORIZATION, authorization);
        if let Some((body, content_length)) = body {
            request = request
                .header(reqwest::header::CONTENT_LENGTH, content_length)
                .body(body);
        }
        match request.send().await {
            Ok(response) => Ok(response),
            Err(error) => bail!("{method} {display_target} failed: {error}"),
        }
    }

    /// Sends a signed S3 request, failing with a quoted error body on non-2xx.
    async fn send_signed(
        &self,
        method: reqwest::Method,
        raw_path: &str,
        query: &[(&str, &str)],
        display_target: &str,
        payload_sha256: &str,
        body: Option<(reqwest::Body, u64)>,
    ) -> anyhow::Result<reqwest::Response> {
        let response = match self
            .send_signed_raw(
                &method,
                raw_path,
                query,
                display_target,
                payload_sha256,
                body,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => return Err(error),
        };
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let quoted_body = read_error_body(response).await;
        bail!("{method} {display_target} failed with HTTP {status}: {quoted_body}")
    }

    /// Uploads a small in-memory `body` (such as JSON metadata) to `key`.
    async fn put_object(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        let payload_sha256 = sha256_hex(&body);
        let size_bytes = body.len() as u64;
        match self
            .send_signed(
                reqwest::Method::PUT,
                &format!("/{}/{key}", self.bucket),
                &[],
                key,
                &payload_sha256,
                Some((reqwest::Body::from(body), size_bytes)),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Streams a staged file at `path` to `key` with precomputed
    /// `payload_sha256` and exact `size_bytes` (`Content-Length`).
    async fn put_file_object(
        &self,
        key: &str,
        path: &Path,
        payload_sha256: &str,
        size_bytes: u64,
    ) -> anyhow::Result<()> {
        if size_bytes > MAX_BACKUP_OBJECT_BYTES {
            bail!("{key} exceeds maximum object size of {MAX_BACKUP_OBJECT_BYTES} bytes");
        }
        if !is_sha256_hex(payload_sha256) {
            bail!("invalid SHA-256 digest for {key}");
        }
        let file = match tokio::fs::File::open(path)
            .await
            .with_context(|| format!("cannot open staged object {}", path.display()))
        {
            Ok(file) => file,
            Err(error) => return Err(error),
        };
        let metadata = match file
            .metadata()
            .await
            .with_context(|| format!("cannot inspect staged object {}", path.display()))
        {
            Ok(metadata) => metadata,
            Err(error) => return Err(error),
        };
        if metadata.len() != size_bytes {
            bail!(
                "staged object {} changed size on disk (expected {size_bytes} bytes, found {})",
                path.display(),
                metadata.len()
            );
        }
        let body = reqwest::Body::from(file);
        match self
            .send_signed(
                reqwest::Method::PUT,
                &format!("/{}/{key}", self.bucket),
                &[],
                key,
                payload_sha256,
                Some((body, size_bytes)),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Downloads `key` into memory, failing beyond `max_bytes`.
    async fn get_object_bytes(&self, key: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        let mut response = match self
            .send_signed(
                reqwest::Method::GET,
                &format!("/{}/{key}", self.bucket),
                &[],
                key,
                EMPTY_PAYLOAD_SHA256,
                None,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => return Err(error),
        };
        read_bounded_bytes(&mut response, max_bytes, key).await
    }

    /// Downloads `key` into memory if it exists, returning `Ok(None)` on 404.
    async fn get_optional_object_bytes(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let method = reqwest::Method::GET;
        let mut response = match self
            .send_signed_raw(
                &method,
                &format!("/{}/{key}", self.bucket),
                &[],
                key,
                EMPTY_PAYLOAD_SHA256,
                None,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => return Err(error),
        };
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let quoted_body = read_error_body(response).await;
            bail!("{method} {key} failed with HTTP {status}: {quoted_body}");
        }
        match read_bounded_bytes(&mut response, max_bytes, key).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) => Err(error),
        }
    }

    /// Streams `key` into a new file at `path`, failing unless it is exactly
    /// `expected_size_bytes` long, and returns its lowercase hex SHA-256.
    async fn get_object_to_file(
        &self,
        key: &str,
        expected_size_bytes: u64,
        path: &Path,
    ) -> anyhow::Result<String> {
        let mut response = match self
            .send_signed(
                reqwest::Method::GET,
                &format!("/{}/{key}", self.bucket),
                &[],
                key,
                EMPTY_PAYLOAD_SHA256,
                None,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => return Err(error),
        };
        let mut file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
            .with_context(|| format!("cannot create {}", path.display()))
        {
            Ok(file) => file,
            Err(error) => return Err(error),
        };
        let mut hasher = Sha256::new();
        let mut received_bytes: u64 = 0;
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(error) => bail!("cannot read {key}: {error}"),
            };
            received_bytes = received_bytes.saturating_add(chunk.len() as u64);
            if received_bytes > expected_size_bytes {
                bail!("{key} is larger than the {expected_size_bytes} bytes the manifest records");
            }
            hasher.update(&chunk);
            if let Err(error) = file.write_all(&chunk).await {
                return Err(anyhow::Error::new(error))
                    .with_context(|| format!("cannot write {}", path.display()));
            }
        }
        if received_bytes != expected_size_bytes {
            bail!(
                "{key} is {received_bytes} bytes, but the manifest records {expected_size_bytes}"
            );
        }
        if let Err(error) = file.flush().await {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot write {}", path.display()));
        }
        Ok(encode_hex(hasher.finalize().as_slice()).as_str().to_owned())
    }

    /// Lists all object keys starting with `key_prefix` via S3
    /// `ListObjectsV2`, following `NextContinuationToken` within bounded page
    /// and object limits.
    async fn list_objects(&self, key_prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;
        let raw_bucket_path = format!("/{}", self.bucket);
        for _page in 0..MAX_LIST_PAGES {
            let mut query: Vec<(&str, &str)> = vec![("list-type", "2"), ("prefix", key_prefix)];
            if let Some(token) = continuation_token.as_deref() {
                query.push(("continuation-token", token));
            }
            let mut response = match self
                .send_signed(
                    reqwest::Method::GET,
                    &raw_bucket_path,
                    &query,
                    &format!("list {key_prefix}"),
                    EMPTY_PAYLOAD_SHA256,
                    None,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => return Err(error),
            };
            let body = match read_bounded_bytes(&mut response, MAX_LIST_RESPONSE_BYTES, key_prefix)
                .await
            {
                Ok(body) => body,
                Err(error) => return Err(error),
            };
            let page = match parse_list_objects_v2_xml(&body) {
                Ok(page) => page,
                Err(error) => return Err(error),
            };
            if keys.len().saturating_add(page.keys.len()) > MAX_LIST_OBJECTS {
                bail!("listing {key_prefix} exceeded the maximum of {MAX_LIST_OBJECTS} objects");
            }
            keys.extend(page.keys);
            if !page.is_truncated {
                return Ok(keys);
            }
            let Some(next_token) = page.next_continuation_token else {
                bail!("truncated ListObjectsV2 response did not include NextContinuationToken");
            };
            if next_token.is_empty() || continuation_token.as_deref() == Some(next_token.as_str()) {
                bail!("truncated ListObjectsV2 response returned an invalid continuation token");
            }
            continuation_token = Some(next_token);
        }
        bail!("listing {key_prefix} exceeded the maximum of {MAX_LIST_PAGES} pages")
    }

    /// Deletes `key` from the bucket.
    async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        match self
            .send_signed(
                reqwest::Method::DELETE,
                &format!("/{}/{key}", self.bucket),
                &[],
                key,
                EMPTY_PAYLOAD_SHA256,
                None,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Reads an HTTP response body into memory, failing if it exceeds `max_bytes`.
async fn read_bounded_bytes(
    response: &mut reqwest::Response,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if (bytes.len() as u64).saturating_add(chunk.len() as u64) > max_bytes {
                    bail!("{label} is larger than {max_bytes} bytes");
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(bytes),
            Err(error) => bail!("cannot read {label}: {error}"),
        }
    }
}

/// Parsed page from an S3 `ListObjectsV2` XML response.
struct ListObjectsPage {
    keys: Vec<String>,
    is_truncated: bool,
    next_continuation_token: Option<String>,
}

/// Parses an S3 `ListObjectsV2` `<ListBucketResult>` XML response without a
/// general-purpose XML dependency.
fn parse_list_objects_v2_xml(bytes: &[u8]) -> anyhow::Result<ListObjectsPage> {
    let xml = match std::str::from_utf8(bytes) {
        Ok(xml) => xml,
        Err(_) => bail!("ListObjectsV2 response is not valid UTF-8"),
    };
    let mut keys = Vec::new();
    let mut is_truncated = false;
    let mut next_continuation_token: Option<String> = None;
    let mut stack: Vec<&str> = Vec::new();
    let mut saw_root = false;
    let mut current_key: Option<String> = None;
    let mut text_buf = String::new();
    let mut pos = 0;

    while pos < xml.len() {
        let rest = &xml[pos..];
        let Some(lt_offset) = rest.find('<') else {
            let trailing = rest.trim();
            if !trailing.is_empty() && stack.is_empty() {
                bail!("unexpected trailing text in ListObjectsV2 XML");
            }
            text_buf.push_str(rest);
            break;
        };
        if lt_offset > 0 {
            let segment = &rest[..lt_offset];
            if !stack.is_empty() {
                text_buf.push_str(segment);
            } else if !segment.trim().is_empty() {
                bail!("unexpected text outside XML root element");
            }
            pos += lt_offset;
        }

        let tag_rest = &xml[pos..];
        if let Some(comment_rest) = tag_rest.strip_prefix("<!--") {
            let Some(end_offset) = comment_rest.find("-->") else {
                bail!("unclosed XML comment in ListObjectsV2 response");
            };
            pos += 4 + end_offset + 3;
            continue;
        }
        if let Some(pi_rest) = tag_rest.strip_prefix("<?") {
            let Some(end_offset) = pi_rest.find("?>") else {
                bail!("unclosed XML processing instruction in ListObjectsV2 response");
            };
            pos += 2 + end_offset + 2;
            continue;
        }
        if let Some(cdata_rest) = tag_rest.strip_prefix("<![CDATA[") {
            let Some(end_offset) = cdata_rest.find("]]>") else {
                bail!("unclosed XML CDATA section in ListObjectsV2 response");
            };
            if !stack.is_empty() {
                text_buf.push_str(&cdata_rest[..end_offset]);
            }
            pos += 9 + end_offset + 3;
            continue;
        }

        let Some(gt_offset) = tag_rest.find('>') else {
            bail!("unclosed XML tag in ListObjectsV2 response");
        };
        let inside = tag_rest[1..gt_offset].trim();
        pos += gt_offset + 1;

        if inside.is_empty() {
            bail!("empty XML tag in ListObjectsV2 response");
        }
        if let Some(closing) = inside.strip_prefix('/') {
            let tag_name = xml_local_name(closing.trim());
            if tag_name.is_empty() {
                bail!("empty closing XML tag in ListObjectsV2 response");
            }
            let Some(expected) = stack.pop() else {
                bail!("unexpected closing XML tag </{tag_name}>");
            };
            if expected != tag_name {
                bail!("mismatched closing XML tag </{tag_name}> (expected </{expected}>)");
            }
            if stack.as_slice() == ["ListBucketResult", "Contents"] && tag_name == "Key" {
                let decoded = match decode_xml_entities(&text_buf) {
                    Ok(decoded) => decoded,
                    Err(error) => return Err(error),
                };
                if decoded.is_empty() {
                    bail!("ListObjectsV2 XML contains an empty <Key>");
                }
                current_key = Some(decoded);
            } else if stack.as_slice() == ["ListBucketResult"] {
                match tag_name {
                    "Contents" => {
                        let Some(key) = current_key.take() else {
                            bail!("ListObjectsV2 <Contents> entry is missing <Key>");
                        };
                        keys.push(key);
                    }
                    "IsTruncated" => {
                        let flag = match decode_xml_entities(&text_buf) {
                            Ok(flag) => flag,
                            Err(error) => return Err(error),
                        };
                        match flag.trim() {
                            "true" => is_truncated = true,
                            "false" => is_truncated = false,
                            other => {
                                bail!("invalid <IsTruncated> value {other:?} in ListObjectsV2 XML");
                            }
                        }
                    }
                    "NextContinuationToken" => {
                        let token = match decode_xml_entities(&text_buf) {
                            Ok(token) => token,
                            Err(error) => return Err(error),
                        };
                        next_continuation_token = Some(token);
                    }
                    _ => {}
                }
            }
            text_buf.clear();
        } else {
            let (body, self_closing) = match inside.strip_suffix('/') {
                Some(stripped) => (stripped.trim_end(), true),
                None => (inside, false),
            };
            let raw_name = match body.split(|ch: char| ch.is_ascii_whitespace()).next() {
                Some(name) if !name.is_empty() => name,
                _ => bail!("malformed opening XML tag in ListObjectsV2 response"),
            };
            let tag_name = xml_local_name(raw_name);
            if stack.is_empty() {
                if tag_name != "ListBucketResult" {
                    bail!("unexpected ListObjectsV2 root element <{tag_name}>");
                }
                saw_root = true;
            }
            text_buf.clear();
            if !self_closing {
                if stack.as_slice() == ["ListBucketResult"] && tag_name == "Contents" {
                    current_key = None;
                }
                stack.push(tag_name);
            } else if stack.as_slice() == ["ListBucketResult"] && tag_name == "Contents" {
                bail!("ListObjectsV2 <Contents/> entry is missing <Key>");
            }
        }
    }

    if !saw_root || !stack.is_empty() {
        bail!("incomplete ListObjectsV2 XML response");
    }
    Ok(ListObjectsPage {
        keys,
        is_truncated,
        next_continuation_token,
    })
}

/// Strips any XML namespace prefix (`ns:Tag` -> `Tag`).
fn xml_local_name(name: &str) -> &str {
    match name.rsplit_once(':') {
        Some((_, local)) => local,
        None => name,
    }
}

/// Decodes standard XML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`,
/// and numeric character references) in `raw`.
fn decode_xml_entities(raw: &str) -> anyhow::Result<String> {
    if !raw.contains('&') {
        return Ok(raw.to_owned());
    }
    let mut decoded = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp_idx) = rest.find('&') {
        decoded.push_str(&rest[..amp_idx]);
        let after_amp = &rest[amp_idx + 1..];
        let Some(semi_idx) = after_amp.find(';') else {
            bail!("unterminated XML entity in ListObjectsV2 response");
        };
        let entity = &after_amp[..semi_idx];
        match entity {
            "amp" => decoded.push('&'),
            "lt" => decoded.push('<'),
            "gt" => decoded.push('>'),
            "quot" => decoded.push('"'),
            "apos" => decoded.push('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let hex = &entity[2..];
                let Ok(code) = u32::from_str_radix(hex, 16) else {
                    bail!("invalid hexadecimal XML entity &#x{hex};");
                };
                let Some(ch) = char::from_u32(code).filter(|ch| *ch != '\0') else {
                    bail!("invalid XML character reference &#x{hex};");
                };
                decoded.push(ch);
            }
            _ if entity.starts_with('#') => {
                let dec = &entity[1..];
                let Ok(code) = dec.parse::<u32>() else {
                    bail!("invalid decimal XML entity &#{dec};");
                };
                let Some(ch) = char::from_u32(code).filter(|ch| *ch != '\0') else {
                    bail!("invalid XML character reference &#{dec};");
                };
                decoded.push(ch);
            }
            other => bail!("unsupported XML entity &{other}; in ListObjectsV2 response"),
        }
        rest = &after_amp[semi_idx + 1..];
    }
    decoded.push_str(rest);
    Ok(decoded)
}

/// Reads at most [`MAX_ERROR_BODY_BYTES`] of an error response for quoting.
async fn read_error_body(mut response: reqwest::Response) -> String {
    let mut bytes = Vec::new();
    while bytes.len() < MAX_ERROR_BODY_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) | Err(_) => break,
        }
    }
    bytes.truncate(MAX_ERROR_BODY_BYTES);
    String::from_utf8_lossy(&bytes).trim().to_owned()
}

/// Whether `bucket` is a valid S3 bucket name.
fn is_valid_bucket_name(bucket: &str) -> bool {
    let bytes = bucket.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
}

/// Returns `prefix` without surrounding slashes, after checking it is made of
/// safe segments.
fn normalize_prefix(prefix: &str) -> anyhow::Result<String> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.len() > 256 || !is_valid_repo_path(trimmed) {
        bail!(
            "invalid R2 prefix: use '/'-separated segments of ASCII letters, digits, '.', '_' \
             or '-', none starting with '.'"
        );
    }
    Ok(trimmed.to_owned())
}

/// Whether `backup_id` is 1 to 128 ASCII letters, digits, `.`, `_` or `-`,
/// starting with a letter or digit (so never `.` or `..`).
fn is_valid_backup_id(backup_id: &str) -> bool {
    let bytes = backup_id.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Checks that `key` lies under `{prefix}/` and is made of safe segments.
fn validate_object_key(prefix: &str, key: &str) -> anyhow::Result<()> {
    let Some(rest) = key
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
    else {
        bail!("object key {key:?} is outside the prefix {prefix:?}");
    };
    let is_safe = !rest.is_empty()
        && key.len() <= 1024
        && rest.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        });
    if is_safe {
        Ok(())
    } else {
        bail!("object key {key:?} is not a safe key")
    }
}

/// Whether `value` is a lowercase hex SHA-256.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Checks one manifest artifact's key, digest and size.
fn validate_artifact(prefix: &str, key: &str, sha256: &str, size_bytes: u64) -> anyhow::Result<()> {
    if let Err(error) = validate_object_key(prefix, key) {
        return Err(error);
    }
    if !is_sha256_hex(sha256) {
        bail!("the manifest records an invalid SHA-256 for {key}");
    }
    if size_bytes > MAX_BACKUP_OBJECT_BYTES {
        bail!("the manifest records an oversized object {key}");
    }
    Ok(())
}

/// Checks everything [`run_restore`] relies on before it writes anything.
fn validate_manifest(manifest: &BackupManifest, prefix: &str) -> anyhow::Result<()> {
    if manifest.version != BACKUP_MANIFEST_VERSION {
        bail!(
            "unsupported backup manifest version {} (expected {BACKUP_MANIFEST_VERSION})",
            manifest.version
        );
    }
    if !is_valid_backup_id(&manifest.backup_id) {
        bail!("the manifest has an invalid backup ID");
    }
    let mut repo_keys = BTreeSet::new();
    for repo in &manifest.repos {
        if validate_repository_path(&repo.repo_key).is_err() {
            bail!(
                "the manifest has an invalid repository key {:?}",
                repo.repo_key
            );
        }
        if !repo_keys.insert(repo.repo_key.as_str()) {
            bail!("the manifest lists repository {:?} twice", repo.repo_key);
        }
        if let Err(error) =
            validate_artifact(prefix, &repo.object_key, &repo.sha256, repo.size_bytes)
        {
            return Err(error);
        }
    }
    // A repository nested inside another would be restored into its files.
    for key in &repo_keys {
        let nested_prefix = format!("{key}/");
        if repo_keys
            .iter()
            .any(|other| other.starts_with(&nested_prefix))
        {
            bail!("the manifest nests a repository inside {key:?}");
        }
    }
    if let Some(database) = &manifest.database
        && let Err(error) = validate_artifact(
            prefix,
            &database.object_key,
            &database.sha256,
            database.size_bytes,
        )
    {
        return Err(error);
    }
    Ok(())
}

/// Uploads a backup of `config.repo_root` (and the database, if configured)
/// and returns its manifest.
///
/// Repository archives and `pg_dump` outputs are staged to temporary files on
/// disk and streamed to R2 with O(1) memory; each per-repository staging file
/// is deleted immediately after its upload. `latest.json` is only updated after
/// every object and the manifest are uploaded, so it always points at a
/// complete backup. When `config.keep` is `Some(n)`, older backups are pruned
/// after `latest.json` is published.
///
/// # Errors
///
/// Fails on invalid configuration, any snapshot, `pg_dump` or upload failure,
/// or retention pruning failure. No error message contains the database password
/// or R2 secret.
pub async fn run_backup(config: BackupConfig) -> anyhow::Result<BackupManifest> {
    if config.keep == Some(0) {
        bail!("keep must be at least 1");
    }
    let prefix = match normalize_prefix(&config.r2.prefix) {
        Ok(prefix) => prefix,
        Err(error) => return Err(error),
    };
    let client = match S3Client::new(&config.r2) {
        Ok(client) => client,
        Err(error) => return Err(error),
    };
    let pg_env = match config
        .database_url
        .as_ref()
        .map(|url| parse_database_url(url.expose_secret()))
    {
        Some(Ok(pg_env)) => Some(pg_env),
        Some(Err(error)) => return Err(error),
        None => None,
    };
    let repo_root = match tokio::fs::canonicalize(&config.repo_root)
        .await
        .with_context(|| format!("cannot resolve repo root {}", config.repo_root.display()))
    {
        Ok(repo_root) => repo_root,
        Err(error) => return Err(error),
    };
    let staging_dir = match tempfile::Builder::new()
        .prefix(".scrim-backup-")
        .tempdir()
        .context("cannot create the backup staging directory")
    {
        Ok(dir) => dir,
        Err(error) => return Err(error),
    };

    let (created_at_utc, amz_date) = current_timestamps();
    let random_suffix = match generate_random_hex(4) {
        Ok(suffix) => suffix,
        Err(error) => return Err(anyhow::Error::new(error)),
    };
    let backup_id = format!("{amz_date}-{}", random_suffix.as_str());
    let backup_prefix = format!("{prefix}/{backup_id}");
    tracing::info!(%backup_id, repo_root = %repo_root.display(), "starting backup");

    let repositories = match discover_bare_repositories(&repo_root).await {
        Ok(repositories) => repositories,
        Err(error) => return Err(error),
    };
    let mut repos = Vec::with_capacity(repositories.len());
    for (repo_key, repo_dir) in repositories {
        let staged = match snapshot_and_archive(&repo_dir, staging_dir.path()).await {
            Ok(staged) => staged,
            Err(error) => return Err(error.context(format!("cannot back up {repo_key}"))),
        };
        let object_key = format!("{backup_prefix}/repos/{repo_key}.tar.gz");
        if let Err(error) = validate_object_key(&prefix, &object_key) {
            return Err(error);
        }
        let sha256 = staged.sha256.clone();
        let size_bytes = staged.size_bytes;
        if let Err(error) = client
            .put_file_object(&object_key, &staged.path, &sha256, size_bytes)
            .await
        {
            return Err(error);
        }
        // Delete each per-repo staging archive immediately after uploading so
        // local staging disk usage remains bounded to one repository at a time.
        staged.cleanup().await;
        tracing::info!(%repo_key, size_bytes, "uploaded repository");
        repos.push(BackupRepoEntry {
            repo_key,
            object_key,
            sha256,
            size_bytes,
        });
    }

    let database = match pg_env {
        Some(pg_env) => {
            let staged = match run_pg_dump(&config.pg_dump_bin, &pg_env, staging_dir.path()).await {
                Ok(staged) => staged,
                Err(error) => return Err(error),
            };
            let object_key = format!("{backup_prefix}/database.dump");
            let artifact = BackupArtifact {
                object_key: object_key.clone(),
                sha256: staged.sha256.clone(),
                size_bytes: staged.size_bytes,
            };
            if let Err(error) = client
                .put_file_object(
                    &object_key,
                    &staged.path,
                    &artifact.sha256,
                    artifact.size_bytes,
                )
                .await
            {
                return Err(error);
            }
            staged.cleanup().await;
            tracing::info!(size_bytes = artifact.size_bytes, "uploaded database dump");
            Some(artifact)
        }
        None => None,
    };

    let manifest = BackupManifest {
        version: BACKUP_MANIFEST_VERSION,
        backup_id: backup_id.clone(),
        created_at_utc: created_at_utc.clone(),
        repos,
        database,
    };
    let manifest_key = format!("{backup_prefix}/manifest.json");
    let latest = LatestBackupPointer {
        backup_id,
        manifest_key: manifest_key.clone(),
        created_at_utc,
    };
    for (key, json) in [
        (manifest_key, serde_json::to_vec_pretty(&manifest)),
        (
            format!("{prefix}/latest.json"),
            serde_json::to_vec_pretty(&latest),
        ),
    ] {
        let json = match json {
            Ok(json) => json,
            Err(error) => return Err(anyhow!("cannot serialize {key}: {error}")),
        };
        if let Err(error) = client.put_object(&key, json).await {
            return Err(error);
        }
    }
    if let Some(keep) = config.keep {
        let report = match prune_backups_with_client(&client, &prefix, keep, false).await {
            Ok(report) => report,
            Err(error) => return Err(error),
        };
        tracing::info!(
            kept = report.kept.len(),
            pruned = report.pruned.len(),
            deleted_objects = report.deleted_objects,
            "pruned older backups"
        );
    }
    tracing::info!(backup_id = %manifest.backup_id, "backup complete");
    Ok(manifest)
}

/// One discovered backup and all object keys under its `<prefix>/<backup_id>/`.
struct DiscoveredBackup {
    manifest: BackupManifest,
    manifest_key: String,
    object_keys: Vec<String>,
    is_latest: bool,
}

/// Result of scanning `<prefix>/` for valid backups and `latest.json`.
struct DiscoveredBackups {
    /// Sorted newest-first (`created_at_utc` desc, then `backup_id` desc).
    backups: Vec<DiscoveredBackup>,
    latest_backup_id: Option<String>,
}

/// Discovers and validates every backup under `prefix/`, reading `latest.json`
/// if present, and returns them sorted newest-first.
async fn discover_backups(client: &S3Client, prefix: &str) -> anyhow::Result<DiscoveredBackups> {
    let list_prefix = format!("{prefix}/");
    let all_keys = match client.list_objects(&list_prefix).await {
        Ok(keys) => keys,
        Err(error) => return Err(error),
    };

    let latest_key = format!("{prefix}/latest.json");
    let latest_backup_id = match client
        .get_optional_object_bytes(&latest_key, MAX_MANIFEST_BYTES)
        .await
    {
        Ok(Some(bytes)) => {
            let latest: LatestBackupPointer = match serde_json::from_slice(&bytes) {
                Ok(latest) => latest,
                Err(error) => bail!("cannot parse {latest_key}: {error}"),
            };
            if !is_valid_backup_id(&latest.backup_id)
                || latest.manifest_key != format!("{prefix}/{}/manifest.json", latest.backup_id)
            {
                bail!("{latest_key} points at an invalid backup");
            }
            Some(latest.backup_id)
        }
        Ok(None) => None,
        Err(error) => return Err(error),
    };

    let mut manifest_ids: Vec<(String, String)> = Vec::new();
    let mut objects_by_backup: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for key in all_keys {
        let Some(rest) = key.strip_prefix(&list_prefix) else {
            continue;
        };
        let Some((backup_id, inner)) = rest.split_once('/') else {
            continue;
        };
        if !is_valid_backup_id(backup_id) || inner.is_empty() {
            continue;
        }
        if validate_object_key(prefix, &key).is_err() {
            continue;
        }
        objects_by_backup
            .entry(backup_id.to_owned())
            .or_default()
            .push(key.clone());
        if inner == "manifest.json" {
            manifest_ids.push((backup_id.to_owned(), key));
        }
    }

    let mut backups = Vec::with_capacity(manifest_ids.len());
    for (backup_id, manifest_key) in manifest_ids {
        let bytes = match client
            .get_object_bytes(&manifest_key, MAX_MANIFEST_BYTES)
            .await
        {
            Ok(bytes) => bytes,
            Err(error) => return Err(error),
        };
        let manifest: BackupManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(error) => bail!("cannot parse {manifest_key}: {error}"),
        };
        if manifest.backup_id != backup_id {
            bail!("{manifest_key} describes a different backup");
        }
        if let Err(error) = validate_manifest(&manifest, prefix) {
            return Err(error);
        }
        let is_latest = latest_backup_id.as_deref() == Some(backup_id.as_str());
        let object_keys = match objects_by_backup.remove(&backup_id) {
            Some(keys) => keys,
            None => vec![manifest_key.clone()],
        };
        backups.push(DiscoveredBackup {
            manifest,
            manifest_key,
            object_keys,
            is_latest,
        });
    }

    backups.sort_by(|a, b| {
        (
            b.manifest.created_at_utc.as_str(),
            b.manifest.backup_id.as_str(),
        )
            .cmp(&(
                a.manifest.created_at_utc.as_str(),
                a.manifest.backup_id.as_str(),
            ))
    });

    Ok(DiscoveredBackups {
        backups,
        latest_backup_id,
    })
}

/// Lists and validates every backup stored under `r2.prefix`, sorted newest
/// first (`created_at_utc` descending, then `backup_id` descending).
///
/// # Errors
///
/// Fails on invalid R2 configuration, S3 listing/fetch failures, or an invalid
/// manifest or `latest.json` pointer.
pub async fn list_backups(r2: &R2Config) -> anyhow::Result<Vec<BackupSummary>> {
    let prefix = match normalize_prefix(&r2.prefix) {
        Ok(prefix) => prefix,
        Err(error) => return Err(error),
    };
    let client = match S3Client::new(r2) {
        Ok(client) => client,
        Err(error) => return Err(error),
    };
    let discovered = match discover_backups(&client, &prefix).await {
        Ok(discovered) => discovered,
        Err(error) => return Err(error),
    };
    let summaries = discovered
        .backups
        .into_iter()
        .map(|entry| {
            let repo_bytes: u64 = entry
                .manifest
                .repos
                .iter()
                .map(|repo| repo.size_bytes)
                .sum();
            let db_bytes = entry
                .manifest
                .database
                .as_ref()
                .map_or(0, |db| db.size_bytes);
            BackupSummary {
                backup_id: entry.manifest.backup_id,
                created_at_utc: entry.manifest.created_at_utc,
                repo_count: entry.manifest.repos.len(),
                has_database: entry.manifest.database.is_some(),
                total_size_bytes: repo_bytes.saturating_add(db_bytes),
                is_latest: entry.is_latest,
            }
        })
        .collect();
    Ok(summaries)
}

/// Prunes older backups stored under `config.r2.prefix`, retaining the
/// `config.keep` newest valid backups and unconditionally protecting whichever
/// backup `latest.json` points at.
///
/// # Errors
///
/// Rejects `config.keep == 0` so all backups cannot be wiped accidentally, and
/// fails on invalid R2 configuration, listing/manifest errors, or S3 deletion
/// errors.
pub async fn prune_backups(config: PruneConfig) -> anyhow::Result<PruneReport> {
    if config.keep == 0 {
        bail!("keep must be at least 1");
    }
    let prefix = match normalize_prefix(&config.r2.prefix) {
        Ok(prefix) => prefix,
        Err(error) => return Err(error),
    };
    let client = match S3Client::new(&config.r2) {
        Ok(client) => client,
        Err(error) => return Err(error),
    };
    prune_backups_with_client(&client, &prefix, config.keep, config.dry_run).await
}

async fn prune_backups_with_client(
    client: &S3Client,
    prefix: &str,
    keep: usize,
    dry_run: bool,
) -> anyhow::Result<PruneReport> {
    if keep == 0 {
        bail!("keep must be at least 1");
    }
    let discovered = match discover_backups(client, prefix).await {
        Ok(discovered) => discovered,
        Err(error) => return Err(error),
    };

    let mut kept = Vec::new();
    let mut to_prune = Vec::new();
    for (index, entry) in discovered.backups.into_iter().enumerate() {
        let is_protected_latest =
            discovered.latest_backup_id.as_deref() == Some(entry.manifest.backup_id.as_str());
        if index < keep || is_protected_latest {
            kept.push(entry.manifest.backup_id);
        } else {
            to_prune.push(entry);
        }
    }

    let mut pruned = Vec::with_capacity(to_prune.len());
    let mut deleted_objects = 0usize;
    for entry in to_prune {
        let backup_id = entry.manifest.backup_id;
        if !dry_run {
            // Delete every data/archive object under `<prefix>/<backup_id>/`
            // BEFORE deleting `manifest.json`. That way, if pruning fails or
            // is interrupted halfway through a backup, `manifest.json` remains
            // present so a subsequent `prune_backups` run still discovers that
            // backup and cleans up any remaining objects.
            let mut data_keys: Vec<&str> = entry
                .object_keys
                .iter()
                .map(String::as_str)
                .filter(|key| *key != entry.manifest_key)
                .collect();
            data_keys.sort_unstable();
            for key in data_keys {
                if let Err(error) = client.delete_object(key).await {
                    return Err(error);
                }
                deleted_objects += 1;
            }
            if let Err(error) = client.delete_object(&entry.manifest_key).await {
                return Err(error);
            }
            deleted_objects += 1;
        }
        pruned.push(backup_id);
    }

    Ok(PruneReport {
        kept,
        pruned,
        deleted_objects,
        dry_run,
    })
}

/// Downloads the backup selected by `config.backup_id` and restores its
/// repositories (and, with `config.database_url`, its database dump).
///
/// Every object's size and SHA-256 are checked against the manifest before
/// it is used, and nothing is written until the manifest and the repository
/// root have been validated.
///
/// # Errors
///
/// Fails on an invalid manifest, a non-empty repository root without
/// `force`, a digest mismatch, an unsafe archive entry, an extracted
/// directory that is not a bare repository, or a failing `pg_restore`.
pub async fn run_restore(config: RestoreConfig) -> anyhow::Result<BackupManifest> {
    let prefix = match normalize_prefix(&config.r2.prefix) {
        Ok(prefix) => prefix,
        Err(error) => return Err(error),
    };
    let client = match S3Client::new(&config.r2) {
        Ok(client) => client,
        Err(error) => return Err(error),
    };
    let pg_env = match config
        .database_url
        .as_ref()
        .map(|url| parse_database_url(url.expose_secret()))
    {
        Some(Ok(pg_env)) => Some(pg_env),
        Some(Err(error)) => return Err(error),
        None => None,
    };

    let manifest = match fetch_manifest(&client, &prefix, config.backup_id.as_deref()).await {
        Ok(manifest) => manifest,
        Err(error) => return Err(error),
    };
    if let Err(error) = validate_manifest(&manifest, &prefix) {
        return Err(error);
    }

    match is_directory_empty(&config.repo_root).await {
        Ok(true) => {}
        Ok(false) if config.force => {
            tracing::warn!(repo_root = %config.repo_root.display(), "restoring into a non-empty repo root (--force)");
        }
        Ok(false) => bail!(
            "repo root {} is not empty; restore into an empty directory or pass --force",
            config.repo_root.display()
        ),
        Err(error) => return Err(error),
    }
    if let Err(error) = tokio::fs::create_dir_all(&config.repo_root).await {
        return Err(anyhow::Error::new(error))
            .with_context(|| format!("cannot create repo root {}", config.repo_root.display()));
    }
    let repo_root = match tokio::fs::canonicalize(&config.repo_root)
        .await
        .with_context(|| format!("cannot resolve repo root {}", config.repo_root.display()))
    {
        Ok(repo_root) => repo_root,
        Err(error) => return Err(error),
    };
    tracing::info!(backup_id = %manifest.backup_id, repo_root = %repo_root.display(), "starting restore");

    for repo in &manifest.repos {
        if let Err(error) = restore_repository(&client, &repo_root, repo, config.force).await {
            return Err(error.context(format!("cannot restore {}", repo.repo_key)));
        }
        tracing::info!(repo_key = %repo.repo_key, "restored repository");
    }

    match (&manifest.database, pg_env) {
        (Some(database), Some(pg_env)) => {
            if let Err(error) =
                restore_database(&client, database, &config.pg_restore_bin, &pg_env).await
            {
                return Err(error);
            }
            tracing::info!("restored database");
        }
        (Some(_), None) => {
            tracing::warn!(
                "the backup has a database dump, but no database URL is set; skipping it"
            );
        }
        (None, Some(_)) => tracing::warn!("the backup has no database dump"),
        (None, None) => {}
    }
    tracing::info!(backup_id = %manifest.backup_id, "restore complete");
    Ok(manifest)
}

/// Loads the manifest of `backup_id`, following `latest.json` for `None` or
/// `"latest"`.
async fn fetch_manifest(
    client: &S3Client,
    prefix: &str,
    backup_id: Option<&str>,
) -> anyhow::Result<BackupManifest> {
    let expected_backup_id = match backup_id {
        None | Some("latest") => {
            let latest_key = format!("{prefix}/latest.json");
            let bytes = match client
                .get_object_bytes(&latest_key, MAX_MANIFEST_BYTES)
                .await
            {
                Ok(bytes) => bytes,
                Err(error) => return Err(error),
            };
            let latest: LatestBackupPointer = match serde_json::from_slice(&bytes) {
                Ok(latest) => latest,
                Err(error) => bail!("cannot parse {latest_key}: {error}"),
            };
            if !is_valid_backup_id(&latest.backup_id)
                || latest.manifest_key != format!("{prefix}/{}/manifest.json", latest.backup_id)
            {
                bail!("{latest_key} points at an invalid backup");
            }
            latest.backup_id
        }
        Some(backup_id) => {
            if !is_valid_backup_id(backup_id) {
                bail!("invalid backup ID: use ASCII letters, digits, '.', '_' or '-'");
            }
            backup_id.to_owned()
        }
    };
    let manifest_key = format!("{prefix}/{expected_backup_id}/manifest.json");
    let bytes = match client
        .get_object_bytes(&manifest_key, MAX_MANIFEST_BYTES)
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => return Err(error),
    };
    let manifest: BackupManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(error) => bail!("cannot parse {manifest_key}: {error}"),
    };
    if manifest.backup_id != expected_backup_id {
        bail!("{manifest_key} describes a different backup");
    }
    Ok(manifest)
}

/// Whether `path` is missing or an empty directory.
async fn is_directory_empty(path: &Path) -> anyhow::Result<bool> {
    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot read repo root {}", path.display()));
        }
    };
    match entries.next_entry().await {
        Ok(entry) => Ok(entry.is_none()),
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("cannot read repo root {}", path.display())),
    }
}

/// Lists every bare repository under `canonical_root` as `(key, directory)`,
/// sorted by key.
///
/// Hidden entries, names that are not valid repository path segments and
/// symlinks are skipped (a symlinked repository would be an alias or point
/// outside the root), and directories that are repositories are not searched.
async fn discover_bare_repositories(
    canonical_root: &Path,
) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut repositories = Vec::new();
    let mut pending: Vec<(String, PathBuf)> = vec![(String::new(), canonical_root.to_path_buf())];
    while let Some((parent_key, directory)) = pending.pop() {
        let mut entries = match tokio::fs::read_dir(&directory)
            .await
            .with_context(|| format!("cannot read {}", directory.display()))
        {
            Ok(entries) => entries,
            Err(error) => return Err(error),
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot read {}", directory.display()));
                }
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.contains('/') || !is_valid_repo_path(&name) {
                continue;
            }
            let path = entry.path();
            let file_type = match tokio::fs::symlink_metadata(&path).await {
                Ok(metadata) => metadata.file_type(),
                Err(error) => {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot inspect {}", path.display()));
                }
            };
            if file_type.is_symlink() {
                tracing::warn!(path = %path.display(), "skipping symlink in repo root");
                continue;
            }
            if !file_type.is_dir() {
                continue;
            }
            let key = if parent_key.is_empty() {
                name
            } else {
                format!("{parent_key}/{name}")
            };
            if key.len() > crate::policy_store::MAX_REPOSITORY_PATH_BYTES {
                continue;
            }
            match resolve_bare_repo(canonical_root, &key).await {
                Some(resolved) if resolved.canonical_key == key => {
                    if validate_repository_path(&key).is_ok() {
                        repositories.push((key, resolved.dir));
                    } else {
                        tracing::warn!(repo_key = %key, "skipping repository at a reserved path");
                    }
                }
                Some(_) => {}
                None => pending.push((key, path)),
            }
        }
    }
    repositories.sort();
    Ok(repositories)
}

/// Builds the environment for a git child: nothing inherited but `PATH`, and
/// no system or user configuration.
fn isolated_git_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("git");
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

/// Runs `command`, failing with a quote of its stderr if it does not succeed.
async fn run_checked(mut command: tokio::process::Command, what: &str) -> anyhow::Result<()> {
    let output = match command.output().await {
        Ok(output) => output,
        Err(error) => {
            return Err(anyhow::Error::new(error)).with_context(|| format!("cannot run {what}"));
        }
    };
    if output.status.success() {
        return Ok(());
    }
    let mut stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.len() > MAX_STDERR_QUOTE_BYTES {
        let mut cut = MAX_STDERR_QUOTE_BYTES;
        while !stderr.is_char_boundary(cut) {
            cut -= 1;
        }
        stderr.truncate(cut);
    }
    bail!("{what} exited with {}: {stderr}", output.status)
}

/// An [`io::Write`] adapter that hashes every written byte with SHA-256 and
/// enforces an upper bound of `max_bytes`.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    bytes_written: u64,
    max_bytes: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
            max_bytes,
        }
    }

    fn finish(mut self) -> io::Result<(W, String, u64)>
    where
        W: Write,
    {
        if let Err(error) = self.inner.flush() {
            return Err(error);
        }
        let sha256 = encode_hex(self.hasher.finalize().as_slice())
            .as_str()
            .to_owned();
        Ok((self.inner, sha256, self.bytes_written))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.max_bytes.saturating_sub(self.bytes_written);
        if remaining == 0 {
            return Err(io::Error::other(format!(
                "backup object exceeds maximum size of {} bytes",
                self.max_bytes
            )));
        }
        let limit = match usize::try_from(remaining) {
            Ok(limit) => buf.len().min(limit),
            Err(_) => buf.len(),
        };
        let written = match self.inner.write(&buf[..limit]) {
            Ok(written) => written,
            Err(error) => return Err(error),
        };
        self.hasher.update(&buf[..written]);
        self.bytes_written = self.bytes_written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A staged backup object written to disk inside its own temporary directory,
/// together with its precomputed SHA-256 digest and exact byte length.
struct StagedArtifact {
    _temp_dir: tempfile::TempDir,
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
}

impl StagedArtifact {
    /// Removes the staged file immediately and drops its temporary directory.
    async fn cleanup(self) {
        if let Err(error) = tokio::fs::remove_file(&self.path).await
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.path.display(), %error, "failed to remove staged backup file");
        }
        drop(self._temp_dir);
    }
}

/// Mirrors the bare repository at `repo_dir` into a temporary directory under
/// `staging_root` and writes it as a gzip-compressed tar archive on disk.
async fn snapshot_and_archive(
    repo_dir: &Path,
    staging_root: &Path,
) -> anyhow::Result<StagedArtifact> {
    let work_dir = match tempfile::Builder::new()
        .prefix("repo-")
        .tempdir_in(staging_root)
        .context("cannot create a temporary directory")
    {
        Ok(work_dir) => work_dir,
        Err(error) => return Err(error),
    };
    let mirror_dir = work_dir.path().join("mirror.git");
    let mut clone = isolated_git_command();
    clone
        .args([
            "-c",
            "init.defaultBranch=main",
            "clone",
            "--mirror",
            "--quiet",
            "--",
        ])
        .arg(repo_dir)
        .arg(&mirror_dir);
    if let Err(error) = run_checked(clone, "git clone --mirror").await {
        return Err(error);
    }
    // The snapshot's `origin` would point at this server's filesystem.
    let mut remove_origin = isolated_git_command();
    remove_origin.arg("--git-dir").arg(&mirror_dir).args([
        "config",
        "--remove-section",
        "remote.origin",
    ]);
    if let Err(error) = run_checked(remove_origin, "git config").await {
        return Err(error);
    }

    let archive_path = work_dir.path().join("archive.tar.gz");
    let archive_path_for_task = archive_path.clone();
    let mirror_dir_for_task = mirror_dir.clone();
    let archived = match tokio::task::spawn_blocking(move || {
        let result = archive_directory(&mirror_dir_for_task, &archive_path_for_task);
        let _ = fs::remove_dir_all(&mirror_dir_for_task);
        result
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(anyhow!("the archiving task failed: {error}")),
    };
    let (sha256, size_bytes) = match archived {
        Ok(info) => info,
        Err(error) => return Err(error),
    };
    Ok(StagedArtifact {
        _temp_dir: work_dir,
        path: archive_path,
        sha256,
        size_bytes,
    })
}

/// Archives the files below `source` (paths relative to it) into `archive_path`
/// as `.tar.gz`, hashing and bounding size in a single streaming pass.
fn archive_directory(source: &Path, archive_path: &Path) -> anyhow::Result<(String, u64)> {
    let file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(archive_path)
        .with_context(|| format!("cannot create {}", archive_path.display()))
    {
        Ok(file) => file,
        Err(error) => return Err(error),
    };
    let writer = HashingWriter::new(io::BufWriter::new(file), MAX_BACKUP_OBJECT_BYTES);
    let mut builder = tar::Builder::new(GzEncoder::new(writer, Compression::default()));
    builder.mode(tar::HeaderMode::Deterministic);
    builder.follow_symlinks(false);
    let mut pending = vec![PathBuf::new()];
    while let Some(relative_dir) = pending.pop() {
        let directory = source.join(&relative_dir);
        let read_dir = match fs::read_dir(&directory)
            .with_context(|| format!("cannot read {}", directory.display()))
        {
            Ok(read_dir) => read_dir,
            Err(error) => return Err(error),
        };
        let mut names = Vec::new();
        for entry in read_dir {
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(error) => {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot read {}", directory.display()));
                }
            }
        }
        names.sort();
        for name in names {
            let path = directory.join(&name);
            let relative = relative_dir.join(&name);
            let file_type = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata.file_type(),
                Err(error) => {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot inspect {}", path.display()));
                }
            };
            let appended = if file_type.is_dir() {
                pending.push(relative.clone());
                builder.append_dir(&relative, &path)
            } else if file_type.is_file() {
                builder.append_path_with_name(&path, &relative)
            } else {
                bail!(
                    "refusing to archive {}: not a regular file or directory",
                    path.display()
                );
            };
            if let Err(error) = appended {
                return Err(anyhow::Error::new(error))
                    .with_context(|| format!("cannot archive {}", path.display()));
            }
        }
    }
    let encoder = match builder
        .into_inner()
        .context("cannot finish the tar archive")
    {
        Ok(encoder) => encoder,
        Err(error) => return Err(error),
    };
    let hashing_writer = match encoder.finish().context("cannot finish the gzip stream") {
        Ok(writer) => writer,
        Err(error) => return Err(error),
    };
    let (_buf_writer, sha256, size_bytes) = match hashing_writer
        .finish()
        .context("cannot flush the backup archive")
    {
        Ok(finished) => finished,
        Err(error) => return Err(error),
    };
    Ok((sha256, size_bytes))
}

/// Downloads, verifies, extracts and installs one repository.
async fn restore_repository(
    client: &S3Client,
    canonical_root: &Path,
    repo: &BackupRepoEntry,
    force: bool,
) -> anyhow::Result<()> {
    // Staged inside the root (hidden, so never served) so the final rename
    // stays on one filesystem.
    let staging = match tempfile::Builder::new()
        .prefix(".scrim-restore-")
        .tempdir_in(canonical_root)
        .context("cannot create a staging directory in the repo root")
    {
        Ok(staging) => staging,
        Err(error) => return Err(error),
    };
    let archive_path = staging.path().join("archive.tar.gz");
    let sha256 = match client
        .get_object_to_file(&repo.object_key, repo.size_bytes, &archive_path)
        .await
    {
        Ok(sha256) => sha256,
        Err(error) => return Err(error),
    };
    if sha256 != repo.sha256 {
        bail!(
            "SHA-256 mismatch for {}: the manifest records {}, the download is {sha256}",
            repo.object_key,
            repo.sha256
        );
    }

    let extracted_dir = staging.path().join("repo");
    let extraction = {
        let archive_path = archive_path.clone();
        let extracted_dir = extracted_dir.clone();
        tokio::task::spawn_blocking(move || extract_repo_archive(&archive_path, &extracted_dir))
            .await
    };
    match extraction {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(error) => bail!("the extraction task failed: {error}"),
    }
    if resolve_bare_repo(staging.path(), "repo").await.is_none() {
        bail!("the archive does not contain a valid bare repository");
    }
    install_restored_repo(canonical_root, &repo.repo_key, &extracted_dir, force).await
}

/// Validates a tar entry path: relative, `/`-separated, no backslashes, and
/// no empty, `.` or `..` segments (one trailing `/` is allowed).
fn safe_archive_path(raw_path: &[u8]) -> anyhow::Result<PathBuf> {
    let Ok(text) = std::str::from_utf8(raw_path) else {
        bail!("refusing a non-UTF-8 archive path");
    };
    let trimmed = match text.strip_suffix('/') {
        Some(trimmed) => trimmed,
        None => text,
    };
    let is_safe = !trimmed.is_empty()
        && !text.starts_with('/')
        && !text.contains(['\\', '\0'])
        && trimmed
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    if !is_safe {
        bail!("refusing unsafe archive path {text:?}");
    }
    Ok(trimmed.split('/').collect())
}

/// Extracts `archive_path` into the new directory `destination`, accepting
/// only regular files and directories at [`safe_archive_path`]s.
fn extract_repo_archive(archive_path: &Path, destination: &Path) -> anyhow::Result<()> {
    let file = match fs::File::open(archive_path)
        .with_context(|| format!("cannot open {}", archive_path.display()))
    {
        Ok(file) => file,
        Err(error) => return Err(error),
    };
    if let Err(error) = fs::create_dir(destination) {
        return Err(anyhow::Error::new(error))
            .with_context(|| format!("cannot create {}", destination.display()));
    }
    let mut archive = tar::Archive::new(GzDecoder::new(io::BufReader::new(file)));
    let entries = match archive.entries().context("cannot read the archive") {
        Ok(entries) => entries,
        Err(error) => return Err(error),
    };
    let mut entry_count: u64 = 0;
    let mut extracted_bytes: u64 = 0;
    for entry in entries {
        let mut entry = match entry.context("cannot read an archive entry") {
            Ok(entry) => entry,
            Err(error) => return Err(error),
        };
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            bail!("the archive has more than {MAX_ARCHIVE_ENTRIES} entries");
        }
        let raw_path = entry.path_bytes().into_owned();
        let relative = match safe_archive_path(&raw_path) {
            Ok(relative) => relative,
            Err(error) => return Err(error),
        };
        let target = destination.join(&relative);
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                if let Err(error) = fs::create_dir_all(&target) {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot create {}", target.display()));
                }
            }
            tar::EntryType::Regular => {
                if let Some(parent) = target.parent()
                    && let Err(error) = fs::create_dir_all(parent)
                {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot create {}", parent.display()));
                }
                let is_executable = matches!(entry.header().mode(), Ok(mode) if mode & 0o111 != 0);
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(if is_executable { 0o755 } else { 0o644 });
                }
                #[cfg(not(unix))]
                let _ = is_executable;
                let mut output = match options
                    .open(&target)
                    .with_context(|| format!("cannot create {}", target.display()))
                {
                    Ok(output) => output,
                    Err(error) => return Err(error),
                };
                let remaining_budget = MAX_EXTRACTED_BYTES - extracted_bytes;
                let copied =
                    match io::copy(&mut (&mut entry).take(remaining_budget + 1), &mut output) {
                        Ok(copied) => copied,
                        Err(error) => {
                            return Err(anyhow::Error::new(error))
                                .with_context(|| format!("cannot extract {}", target.display()));
                        }
                    };
                if copied > remaining_budget {
                    bail!("the archive expands to more than {MAX_EXTRACTED_BYTES} bytes");
                }
                extracted_bytes += copied;
                if let Err(error) = output.flush() {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot write {}", target.display()));
                }
            }
            other => bail!(
                "refusing archive entry {:?} of type {other:?}: only regular files and \
                 directories are allowed",
                String::from_utf8_lossy(&raw_path)
            ),
        }
    }
    Ok(())
}

/// Moves `staged_dir` to `canonical_root/repo_key`, creating plain parent
/// directories (never through a symlink) and, with `force`, replacing
/// whatever is already there.
async fn install_restored_repo(
    canonical_root: &Path,
    repo_key: &str,
    staged_dir: &Path,
    force: bool,
) -> anyhow::Result<()> {
    let segments: Vec<&str> = repo_key.split('/').collect();
    let Some((last, parents)) = segments.split_last() else {
        bail!("empty repository key");
    };
    let mut target = canonical_root.to_path_buf();
    for segment in parents {
        target.push(segment);
        match tokio::fs::symlink_metadata(&target).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => bail!("{} is not a plain directory", target.display()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Err(error) = tokio::fs::create_dir(&target).await {
                    return Err(anyhow::Error::new(error))
                        .with_context(|| format!("cannot create {}", target.display()));
                }
            }
            Err(error) => {
                return Err(anyhow::Error::new(error))
                    .with_context(|| format!("cannot inspect {}", target.display()));
            }
        }
    }
    target.push(last);
    match tokio::fs::symlink_metadata(&target).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(metadata) => {
            if !force {
                bail!(
                    "{} already exists; pass --force to replace it",
                    target.display()
                );
            }
            let removed = if metadata.is_dir() && !metadata.file_type().is_symlink() {
                tokio::fs::remove_dir_all(&target).await
            } else {
                tokio::fs::remove_file(&target).await
            };
            if let Err(error) = removed {
                return Err(anyhow::Error::new(error))
                    .with_context(|| format!("cannot replace {}", target.display()));
            }
        }
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot inspect {}", target.display()));
        }
    }
    match tokio::fs::rename(staged_dir, &target).await {
        Ok(()) => Ok(()),
        Err(error) => Err(anyhow::Error::new(error)).with_context(|| {
            format!(
                "cannot move the restored repository to {}",
                target.display()
            )
        }),
    }
}

/// libpq connection settings taken from a `DATABASE_URL`, passed to
/// `pg_dump`/`pg_restore` only as environment variables.
struct PgConnectionEnv {
    /// `(PGHOST, ...)` pairs; values may include the password.
    vars: Vec<(&'static str, Zeroizing<String>)>,
    /// Database name, for `pg_restore --dbname`.
    database: Option<String>,
}

/// Decodes `%XX` escapes in a URL component.
fn percent_decode(component: &str) -> Option<Zeroizing<String>> {
    let bytes = component.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes
                .get(index + 1)
                .and_then(|byte| (*byte as char).to_digit(16));
            let low = bytes
                .get(index + 2)
                .and_then(|byte| (*byte as char).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return None;
            };
            let Ok(byte) = u8::try_from(high * 16 + low) else {
                return None;
            };
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    match String::from_utf8(std::mem::take(&mut *decoded)) {
        Ok(text) => Some(Zeroizing::new(text)),
        Err(error) => {
            let _wiped = Zeroizing::new(error.into_bytes());
            None
        }
    }
}

/// Parses a `postgres://` / `postgresql://` URL into libpq environment
/// variables. Supported query parameters: `sslmode`, `sslrootcert`, `host`.
///
/// Error messages never include the URL or any part of it but parameter names.
fn parse_database_url(database_url: &str) -> anyhow::Result<PgConnectionEnv> {
    let url = match reqwest::Url::parse(database_url) {
        Ok(url) => url,
        Err(_) => bail!("the database URL is not a valid URL"),
    };
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        bail!("the database URL must start with postgres:// or postgresql://");
    }
    let invalid_escape = || anyhow!("the database URL contains an invalid percent-encoding");
    let mut vars: Vec<(&'static str, Zeroizing<String>)> = Vec::new();
    if let Some(host) = url.host_str()
        && !host.is_empty()
    {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        match percent_decode(host) {
            Some(host) => vars.push(("PGHOST", host)),
            None => return Err(invalid_escape()),
        }
    }
    if let Some(port) = url.port() {
        vars.push(("PGPORT", Zeroizing::new(port.to_string())));
    }
    let mut user = None;
    if !url.username().is_empty() {
        match percent_decode(url.username()) {
            Some(decoded) => {
                user = Some(decoded.as_str().to_owned());
                vars.push(("PGUSER", decoded));
            }
            None => return Err(invalid_escape()),
        }
    }
    if let Some(password) = url.password() {
        match percent_decode(password) {
            Some(password) => vars.push(("PGPASSWORD", password)),
            None => return Err(invalid_escape()),
        }
    }
    let mut database = None;
    let path = url.path().trim_start_matches('/');
    if !path.is_empty() {
        match percent_decode(path) {
            Some(name) => {
                database = Some(name.as_str().to_owned());
                vars.push(("PGDATABASE", name));
            }
            None => return Err(invalid_escape()),
        }
    }
    for (name, value) in url.query_pairs() {
        let variable = match name.as_ref() {
            "sslmode" => "PGSSLMODE",
            "sslrootcert" => "PGSSLROOTCERT",
            "host" => "PGHOST",
            other => bail!("unsupported database URL parameter {other:?}"),
        };
        vars.retain(|(existing, _)| *existing != variable);
        vars.push((variable, Zeroizing::new(value.into_owned())));
    }
    // libpq defaults the database name to the user name.
    if database.is_none() {
        database = user;
    }
    Ok(PgConnectionEnv { vars, database })
}

/// Builds a command for a PostgreSQL client tool whose only inherited
/// environment is `PATH` and `HOME`, plus the connection variables.
fn pg_command(program: &Path, pg_env: &PgConnectionEnv) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command.env_clear();
    for inherited in ["PATH", "HOME"] {
        if let Some(value) = std::env::var_os(inherited) {
            command.env(inherited, value);
        }
    }
    for (name, value) in &pg_env.vars {
        command.env(name, value.as_str());
    }
    command.stdin(Stdio::null()).kill_on_drop(true);
    command
}

/// Runs `pg_dump --format=custom` into a staged file and hashes it with O(1) memory.
async fn run_pg_dump(
    pg_dump_bin: &Path,
    pg_env: &PgConnectionEnv,
    staging_root: &Path,
) -> anyhow::Result<StagedArtifact> {
    let work_dir = match tempfile::Builder::new()
        .prefix("pgdump-")
        .tempdir_in(staging_root)
        .context("cannot create a temporary directory")
    {
        Ok(work_dir) => work_dir,
        Err(error) => return Err(error),
    };
    let dump_path = work_dir.path().join("database.dump");
    let mut command = pg_command(pg_dump_bin, pg_env);
    command
        .args(["--format=custom", "--no-owner", "--no-privileges", "--file"])
        .arg(&dump_path);
    if let Err(error) = run_checked(command, "pg_dump").await {
        return Err(error);
    }
    let dump_path_for_task = dump_path.clone();
    let hashed =
        match tokio::task::spawn_blocking(move || hash_file_bounded(&dump_path_for_task)).await {
            Ok(result) => result,
            Err(error) => Err(anyhow!("the database dump hashing task failed: {error}")),
        };
    let (sha256, size_bytes) = match hashed {
        Ok(info) => info,
        Err(error) => return Err(error),
    };
    Ok(StagedArtifact {
        _temp_dir: work_dir,
        path: dump_path,
        sha256,
        size_bytes,
    })
}

/// Computes `(sha256, size_bytes)` of `path` using a bounded streaming read.
fn hash_file_bounded(path: &Path) -> anyhow::Result<(String, u64)> {
    let file = match fs::File::open(path).context("pg_dump did not write a dump") {
        Ok(file) => file,
        Err(error) => return Err(error),
    };
    let metadata = match file.metadata().context("cannot inspect the database dump") {
        Ok(metadata) => metadata,
        Err(error) => return Err(error),
    };
    if metadata.len() > MAX_BACKUP_OBJECT_BYTES {
        bail!("the database dump exceeds {MAX_BACKUP_OBJECT_BYTES} bytes");
    }
    let mut reader = io::BufReader::new(file);
    let mut writer = HashingWriter::new(io::sink(), MAX_BACKUP_OBJECT_BYTES);
    if let Err(error) = io::copy(&mut reader, &mut writer) {
        return Err(anyhow::Error::new(error)).context("cannot read the database dump");
    }
    let (_, sha256, size_bytes) = match writer.finish().context("cannot hash the database dump") {
        Ok(finished) => finished,
        Err(error) => return Err(error),
    };
    Ok((sha256, size_bytes))
}

/// Downloads and verifies the database dump, then runs `pg_restore` on it.
async fn restore_database(
    client: &S3Client,
    database: &BackupArtifact,
    pg_restore_bin: &Path,
    pg_env: &PgConnectionEnv,
) -> anyhow::Result<()> {
    let Some(database_name) = &pg_env.database else {
        bail!("the database URL names no database (or user) to restore into");
    };
    if database_name.contains('=') {
        bail!("the database name must not contain '='");
    }
    let temp_dir = match tempfile::TempDir::new().context("cannot create a temporary directory") {
        Ok(temp_dir) => temp_dir,
        Err(error) => return Err(error),
    };
    let dump_path = temp_dir.path().join("database.dump");
    let sha256 = match client
        .get_object_to_file(&database.object_key, database.size_bytes, &dump_path)
        .await
    {
        Ok(sha256) => sha256,
        Err(error) => return Err(error),
    };
    if sha256 != database.sha256 {
        bail!(
            "SHA-256 mismatch for {}: the manifest records {}, the download is {sha256}",
            database.object_key,
            database.sha256
        );
    }
    let mut command = pg_command(pg_restore_bin, pg_env);
    command
        .args(["--clean", "--if-exists", "--no-owner", "--no-privileges"])
        .arg(format!("--dbname={database_name}"))
        .arg(&dump_path);
    run_checked(command, "pg_restore").await
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWS_EXAMPLE_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const AWS_EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn sign(
        method: &str,
        canonical_uri: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        payload_sha256: &str,
    ) -> String {
        match sign_s3_request(&S3SigningRequest {
            method,
            canonical_uri,
            query,
            headers,
            payload_sha256,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
            service: "s3",
            access_key_id: AWS_EXAMPLE_ACCESS_KEY_ID,
            secret_access_key: AWS_EXAMPLE_SECRET,
        }) {
            Ok(authorization) => authorization,
            Err(error) => panic!("signing should succeed: {error}"),
        }
    }

    /// The examples of the S3 "Signature Calculations for the Authorization
    /// Header" documentation (Signature Version 4).
    #[test]
    fn sigv4_matches_the_aws_s3_examples() {
        let host = ("host", "examplebucket.s3.amazonaws.com");
        let date = ("x-amz-date", "20130524T000000Z");

        let get_object = sign(
            "GET",
            "/test.txt",
            &[],
            &[
                host,
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                date,
            ],
            EMPTY_PAYLOAD_SHA256,
        );
        assert_eq!(
            get_object,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );

        let payload = "Welcome to Amazon S3.";
        let payload_sha256 = sha256_hex(payload.as_bytes());
        assert_eq!(
            payload_sha256,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let put_object = sign(
            "PUT",
            &uri_encode("/test$file.text", false),
            &[],
            &[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                host,
                ("x-amz-content-sha256", &payload_sha256),
                date,
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            &payload_sha256,
        );
        assert!(
            put_object.ends_with(
                "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
                 Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "{put_object}"
        );

        let lifecycle = sign(
            "GET",
            "/",
            &[("lifecycle", "")],
            &[host, ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256), date],
            EMPTY_PAYLOAD_SHA256,
        );
        assert!(
            lifecycle.ends_with(
                "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
            ),
            "{lifecycle}"
        );

        let list_objects = sign(
            "GET",
            "/",
            &[("prefix", "J"), ("max-keys", "2")],
            &[host, ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256), date],
            EMPTY_PAYLOAD_SHA256,
        );
        assert!(
            list_objects.ends_with(
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
            ),
            "{list_objects}"
        );
    }

    #[test]
    fn signing_rejects_malformed_dates() {
        let result = sign_s3_request(&S3SigningRequest {
            method: "GET",
            canonical_uri: "/",
            query: &[],
            headers: &[("host", "example.com")],
            payload_sha256: EMPTY_PAYLOAD_SHA256,
            amz_date: "2013-05-24T00:00:00Z",
            region: "auto",
            service: "s3",
            access_key_id: AWS_EXAMPLE_ACCESS_KEY_ID,
            secret_access_key: AWS_EXAMPLE_SECRET,
        });
        assert!(result.is_err());
    }

    #[test]
    fn uri_encoding_keeps_only_unreserved_characters() {
        assert_eq!(uri_encode("/a b/c~d_e.f-g", false), "/a%20b/c~d_e.f-g");
        assert_eq!(uri_encode("a/b+c=", true), "a%2Fb%2Bc%3D");
        assert_eq!(uri_encode("é", true), "%C3%A9");
        assert_eq!(collapse_header_whitespace("  a   b  "), "a b");
    }

    #[test]
    fn database_urls_become_pg_environment_variables() {
        let env = match parse_database_url(
            "postgres://scrim:p%40ss%3Aw0rd@db.internal:5433/scrim_db?sslmode=verify-full&sslrootcert=/ca.pem",
        ) {
            Ok(env) => env,
            Err(error) => panic!("URL should parse: {error}"),
        };
        let vars: Vec<(&str, &str)> = env
            .vars
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(
            vars,
            [
                ("PGHOST", "db.internal"),
                ("PGPORT", "5433"),
                ("PGUSER", "scrim"),
                ("PGPASSWORD", "p@ss:w0rd"),
                ("PGDATABASE", "scrim_db"),
                ("PGSSLMODE", "verify-full"),
                ("PGSSLROOTCERT", "/ca.pem"),
            ]
        );
        assert_eq!(env.database.as_deref(), Some("scrim_db"));

        match parse_database_url("postgresql://alice@[::1]") {
            Ok(env) => {
                assert_eq!(env.database.as_deref(), Some("alice"));
                assert_eq!(env.vars[0].1.as_str(), "::1");
            }
            Err(error) => panic!("URL should parse: {error}"),
        }

        for invalid in [
            "mysql://root:secret@host/db",
            "postgres://u:secret@host/db?options=-c%20x",
            "postgres://u:bad%zz@host/db",
            "not a url secret",
        ] {
            match parse_database_url(invalid) {
                Ok(_) => panic!("{invalid:?} should be rejected"),
                Err(error) => assert!(!error.to_string().contains("secret")),
            }
        }
    }

    #[test]
    fn keys_ids_and_paths_are_validated() {
        assert!(validate_object_key("p", "p/id/repos/team/app.git.tar.gz").is_ok());
        for invalid in ["q/id/x", "p/../x", "p//x", "p/", "p/./x", "p/a b", "px/y"] {
            assert!(validate_object_key("p", invalid).is_err(), "{invalid}");
        }
        assert!(is_valid_backup_id("20261122T101500Z-1a2b3c4d"));
        for invalid in ["", ".", "..", "../x", "a/b", "-x", "a b"] {
            assert!(!is_valid_backup_id(invalid), "{invalid}");
        }
        assert_eq!(
            match normalize_prefix("/scrim-backups/prod/") {
                Ok(prefix) => prefix,
                Err(error) => panic!("prefix should be valid: {error}"),
            },
            "scrim-backups/prod"
        );
        assert!(normalize_prefix("a/../b").is_err());
        assert!(normalize_prefix("").is_err());
        assert!(is_valid_bucket_name("scrim-backups"));
        assert!(!is_valid_bucket_name("Scrim"));
        assert!(!is_valid_bucket_name("ab"));

        assert!(safe_archive_path(b"objects/pack/x.pack").is_ok());
        assert!(safe_archive_path(b"refs/heads/").is_ok());
        for invalid in [
            &b"../escape"[..],
            b"/etc/passwd",
            b"a/../../b",
            b"a\\b",
            b"./HEAD",
            b"a//b",
            b"",
        ] {
            assert!(
                safe_archive_path(invalid).is_err(),
                "{}",
                String::from_utf8_lossy(invalid)
            );
        }
    }

    #[test]
    fn manifests_are_validated_before_restore() {
        let entry = |repo_key: &str| BackupRepoEntry {
            repo_key: repo_key.to_owned(),
            object_key: format!("p/id/repos/{repo_key}.tar.gz"),
            sha256: "a".repeat(64),
            size_bytes: 10,
        };
        let manifest = BackupManifest {
            version: 1,
            backup_id: "id".to_owned(),
            created_at_utc: "2026-11-22T00:00:00Z".to_owned(),
            repos: vec![entry("team/app.git"), entry("solo.git")],
            database: None,
        };
        assert!(validate_manifest(&manifest, "p").is_ok());

        let mut wrong_version = manifest.clone();
        wrong_version.version = 2;
        let mut bad_repo_key = manifest.clone();
        bad_repo_key.repos.push(entry("../escape.git"));
        let mut nested = manifest.clone();
        nested.repos.push(entry("team/app.git/inner.git"));
        let mut duplicate = manifest.clone();
        duplicate.repos.push(entry("solo.git"));
        let mut bad_digest = manifest.clone();
        bad_digest.repos[0].sha256 = "A".repeat(64);
        let mut outside_prefix = manifest.clone();
        outside_prefix.database = Some(BackupArtifact {
            object_key: "elsewhere/database.dump".to_owned(),
            sha256: "b".repeat(64),
            size_bytes: 1,
        });
        for invalid in [
            wrong_version,
            bad_repo_key,
            nested,
            duplicate,
            bad_digest,
            outside_prefix,
        ] {
            assert!(validate_manifest(&invalid, "p").is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn canonical_query_signing_encodes_and_sorts_parameters() {
        assert_eq!(
            canonical_query_string(&[
                ("prefix", "backups/prod/"),
                ("list-type", "2"),
                ("continuation-token", "abc/def+ghi=1 "),
            ]),
            "continuation-token=abc%2Fdef%2Bghi%3D1%20&list-type=2&prefix=backups%2Fprod%2F"
        );

        let headers = [
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ];
        // Reordering input query pairs must produce the exact same signature.
        let sig_a = sign(
            "GET",
            "/scrim-test",
            &[
                ("prefix", "backups/prod/"),
                ("list-type", "2"),
                ("continuation-token", "tok/1+2="),
            ],
            &headers,
            EMPTY_PAYLOAD_SHA256,
        );
        let sig_b = sign(
            "GET",
            "/scrim-test",
            &[
                ("continuation-token", "tok/1+2="),
                ("list-type", "2"),
                ("prefix", "backups/prod/"),
            ],
            &headers,
            EMPTY_PAYLOAD_SHA256,
        );
        assert_eq!(sig_a, sig_b);

        // Duplicate parameter names sort by encoded value.
        assert_eq!(
            canonical_query_string(&[("k", "z"), ("k", "a"), ("k", "b/c")]),
            "k=a&k=b%2Fc&k=z"
        );
    }

    #[test]
    fn hashing_writer_computes_sha256_and_enforces_limit() {
        let mut writer = HashingWriter::new(Vec::new(), 11);
        if let Err(error) = writer.write_all(b"hello ") {
            panic!("first write should succeed: {error}");
        }
        if let Err(error) = writer.write_all(b"world") {
            panic!("second write at exact limit should succeed: {error}");
        }
        let (buf, digest, len) = match writer.finish() {
            Ok(res) => res,
            Err(error) => panic!("finish should succeed: {error}"),
        };
        assert_eq!(buf, b"hello world");
        assert_eq!(len, 11);
        assert_eq!(digest, sha256_hex(b"hello world"));

        let mut bounded = HashingWriter::new(Vec::new(), 5);
        assert!(bounded.write_all(b"123456").is_err());
    }

    #[test]
    fn list_objects_v2_xml_parses_entities_pagination_and_rejects_malformed() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
        <!-- R2 ListObjectsV2 -->
        <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Name>scrim-test</Name>
          <Prefix>backups/prod/</Prefix>
          <IsTruncated>true</IsTruncated>
          <NextContinuationToken>tok&amp;1+2=&lt;next&gt;</NextContinuationToken>
          <Contents>
            <Key>backups/prod/id1/repos/a&amp;b&apos;c&quot;d.git.tar.gz</Key>
            <Size>123</Size>
          </Contents>
          <Contents>
            <Key><![CDATA[backups/prod/id1/manifest.json]]></Key>
          </Contents>
        </ListBucketResult>"#;
        let page = match parse_list_objects_v2_xml(xml) {
            Ok(page) => page,
            Err(error) => panic!("valid XML should parse: {error}"),
        };
        assert!(page.is_truncated);
        assert_eq!(
            page.next_continuation_token.as_deref(),
            Some("tok&1+2=<next>")
        );
        assert_eq!(
            page.keys,
            [
                "backups/prod/id1/repos/a&b'c\"d.git.tar.gz",
                "backups/prod/id1/manifest.json"
            ]
        );

        let empty_xml = br#"<ListBucketResult><IsTruncated>false</IsTruncated><NextContinuationToken/></ListBucketResult>"#;
        let empty_page = match parse_list_objects_v2_xml(empty_xml) {
            Ok(page) => page,
            Err(error) => panic!("empty XML should parse: {error}"),
        };
        assert!(!empty_page.is_truncated);
        assert!(empty_page.keys.is_empty());

        for bad in [
            b"<WrongRoot/>".as_slice(),
            b"<ListBucketResult><Contents></Contents></ListBucketResult>",
            b"<ListBucketResult><IsTruncated>maybe</IsTruncated></ListBucketResult>",
            b"<ListBucketResult><Contents><Key>a</Key></ListBucketResult>",
            b"<ListBucketResult><Contents><Key>a&unknown;</Key></Contents></ListBucketResult>",
        ] {
            assert!(
                parse_list_objects_v2_xml(bad).is_err(),
                "expected error for {}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
