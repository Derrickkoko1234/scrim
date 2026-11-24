//! Backup and restore against an in-process mock of Cloudflare R2's S3 API
//! that re-verifies every request's SigV4 signature, with stub `pg_dump` and
//! `pg_restore` executables recording how they were invoked.

#![cfg(unix)]
#![allow(clippy::question_mark)]

mod common;

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use common::{GitSandbox, hex};
use flate2::{Compression, write::GzEncoder};
use scrim_server::{
    BackupConfig, BackupManifest, BackupRepoEntry, BackupSummary, LatestBackupPointer, PruneConfig,
    PruneReport, R2Config, RestoreConfig, S3SigningRequest, SecretString, list_backups,
    prune_backups, run_backup, run_restore, sign_s3_request,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const BUCKET: &str = "scrim-test";
const PREFIX: &str = "backups/prod";
const ACCESS_KEY_ID: &str = "test-access-key";
const SECRET_ACCESS_KEY: &str = "test-secret-access-key";
const DATABASE_PASSWORD: &str = "s3cr@t-pw";
const DATABASE_URL: &str = "postgres://scrim:s3cr%40t-pw@db.internal:5433/scrim?sslmode=require";
const FAKE_DUMP: &str = "PGDMP fake custom-format dump\n";

/// Objects stored by the mock, keyed by object key (without the bucket).
#[derive(Clone)]
struct MockR2 {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    rejected_requests: Arc<Mutex<Vec<String>>>,
    request_count: Arc<Mutex<usize>>,
    deleted_keys: Arc<Mutex<Vec<String>>>,
    put_content_lengths: Arc<Mutex<BTreeMap<String, u64>>>,
    max_list_keys: Arc<Mutex<usize>>,
}

impl Default for MockR2 {
    fn default() -> Self {
        Self {
            objects: Arc::default(),
            rejected_requests: Arc::default(),
            request_count: Arc::default(),
            deleted_keys: Arc::default(),
            put_content_lengths: Arc::default(),
            max_list_keys: Arc::new(Mutex::new(1000)),
        }
    }
}

impl MockR2 {
    fn object(&self, key: &str) -> Option<Vec<u8>> {
        match self.objects.lock() {
            Ok(objects) => objects.get(key).cloned(),
            Err(_) => panic!("mock objects mutex is poisoned"),
        }
    }

    fn all_keys(&self) -> Vec<String> {
        match self.objects.lock() {
            Ok(objects) => objects.keys().cloned().collect(),
            Err(_) => panic!("mock objects mutex is poisoned"),
        }
    }

    fn put(&self, key: &str, bytes: Vec<u8>) {
        match self.objects.lock() {
            Ok(mut objects) => {
                objects.insert(key.to_owned(), bytes);
            }
            Err(_) => panic!("mock objects mutex is poisoned"),
        }
    }

    fn delete(&self, key: &str) -> bool {
        let removed = match self.objects.lock() {
            Ok(mut objects) => objects.remove(key).is_some(),
            Err(_) => panic!("mock objects mutex is poisoned"),
        };
        match self.deleted_keys.lock() {
            Ok(mut deleted) => deleted.push(key.to_owned()),
            Err(_) => panic!("mock deleted_keys mutex is poisoned"),
        }
        removed
    }

    fn deleted_keys(&self) -> Vec<String> {
        match self.deleted_keys.lock() {
            Ok(deleted) => deleted.clone(),
            Err(_) => panic!("mock deleted_keys mutex is poisoned"),
        }
    }

    fn record_put_content_length(&self, key: &str, content_length: u64) {
        match self.put_content_lengths.lock() {
            Ok(mut lengths) => {
                lengths.insert(key.to_owned(), content_length);
            }
            Err(_) => panic!("mock put_content_lengths mutex is poisoned"),
        }
    }

    fn put_content_length(&self, key: &str) -> Option<u64> {
        match self.put_content_lengths.lock() {
            Ok(lengths) => lengths.get(key).copied(),
            Err(_) => panic!("mock put_content_lengths mutex is poisoned"),
        }
    }

    fn set_max_list_keys(&self, max_keys: usize) {
        match self.max_list_keys.lock() {
            Ok(mut limit) => *limit = max_keys,
            Err(_) => panic!("mock max_list_keys mutex is poisoned"),
        }
    }

    fn max_list_keys(&self) -> usize {
        match self.max_list_keys.lock() {
            Ok(limit) => *limit,
            Err(_) => panic!("mock max_list_keys mutex is poisoned"),
        }
    }

    fn rejected_requests(&self) -> Vec<String> {
        match self.rejected_requests.lock() {
            Ok(rejected) => rejected.clone(),
            Err(_) => panic!("mock rejection mutex is poisoned"),
        }
    }

    fn request_count(&self) -> usize {
        match self.request_count.lock() {
            Ok(count) => *count,
            Err(_) => panic!("mock counter mutex is poisoned"),
        }
    }

    fn reject(&self, reason: String) -> Response {
        match self.rejected_requests.lock() {
            Ok(mut rejected) => rejected.push(reason.clone()),
            Err(_) => panic!("mock rejection mutex is poisoned"),
        }
        (StatusCode::FORBIDDEN, reason).into_response()
    }
}

fn header_text(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn percent_decode_str(raw: &str) -> Result<String, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hi) = bytes.get(index + 1).and_then(|b| (*b as char).to_digit(16)) else {
                return Err(format!("invalid percent-escape in {raw:?}"));
            };
            let Some(lo) = bytes.get(index + 2).and_then(|b| (*b as char).to_digit(16)) else {
                return Err(format!("invalid percent-escape in {raw:?}"));
            };
            let Ok(byte) = u8::try_from(hi * 16 + lo) else {
                return Err(format!("invalid percent-escape in {raw:?}"));
            };
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    match String::from_utf8(out) {
        Ok(text) => Ok(text),
        Err(_) => Err(format!("non-UTF-8 percent-encoded query {raw:?}")),
    }
}

fn parse_query_pairs(query: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let mut pairs = Vec::new();
    for part in query.split('&') {
        let (name, value) = match part.split_once('=') {
            Some((name, value)) => (name, value),
            None => (part, ""),
        };
        let name = match percent_decode_str(name) {
            Ok(name) => name,
            Err(error) => return Err(error),
        };
        let value = match percent_decode_str(value) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        pairs.push((name, value));
    }
    Ok(pairs)
}

fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Verifies the request's SigV4 signature and serves PUT, GET, DELETE and
/// ListObjectsV2 requests.
async fn handle_mock_request(State(mock): State<MockR2>, request: Request) -> Response {
    match mock.request_count.lock() {
        Ok(mut count) => *count += 1,
        Err(_) => panic!("mock counter mutex is poisoned"),
    }
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let raw_query = request.uri().query().map(str::to_owned);
    let query_pairs = match parse_query_pairs(raw_query.as_deref()) {
        Ok(pairs) => pairs,
        Err(error) => return mock.reject(format!("invalid query on {path}: {error}")),
    };
    let is_bucket_list = method == Method::GET && path == format!("/{BUCKET}");
    if !is_bucket_list && raw_query.is_some() {
        return mock.reject(format!("unexpected query on {path}"));
    }

    let (Some(host), Some(amz_date), Some(content_sha256), Some(authorization)) = (
        header_text(&request, "host"),
        header_text(&request, "x-amz-date"),
        header_text(&request, "x-amz-content-sha256"),
        header_text(&request, "authorization"),
    ) else {
        return mock.reject(format!("missing SigV4 headers on {method} {path}"));
    };
    let content_length_header = header_text(&request, "content-length");
    let body = match to_bytes(request.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(error) => return mock.reject(format!("cannot read body: {error}")),
    };
    if hex(&Sha256::digest(&body)) != content_sha256 {
        return mock.reject(format!("x-amz-content-sha256 mismatch on {path}"));
    }
    if amz_date.len() != 16 || !amz_date.ends_with('Z') {
        return mock.reject(format!("malformed x-amz-date {amz_date:?}"));
    }
    if !authorization.starts_with(&format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS_KEY_ID}/{}/auto/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=",
        &amz_date[..8]
    )) {
        return mock.reject(format!("unexpected Authorization {authorization:?}"));
    }
    let query_refs: Vec<(&str, &str)> = query_pairs
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let expected = sign_s3_request(&S3SigningRequest {
        method: method.as_str(),
        canonical_uri: &path,
        query: &query_refs,
        headers: &[
            ("host", host.as_str()),
            ("x-amz-content-sha256", content_sha256.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ],
        payload_sha256: &content_sha256,
        amz_date: &amz_date,
        region: "auto",
        service: "s3",
        access_key_id: ACCESS_KEY_ID,
        secret_access_key: SECRET_ACCESS_KEY,
    });
    if expected.as_deref() != Ok(authorization.as_str()) {
        return mock.reject(format!("bad signature on {method} {path}"));
    }

    if is_bucket_list {
        let list_type = query_pairs
            .iter()
            .find(|(name, _)| name == "list-type")
            .map(|(_, value)| value.as_str());
        if list_type != Some("2") {
            return mock.reject(format!("expected list-type=2, got {list_type:?}"));
        }
        let mut key_prefix = "";
        if let Some((_, value)) = query_pairs.iter().find(|(name, _)| name == "prefix") {
            key_prefix = value.as_str();
        }
        let continuation_token = query_pairs
            .iter()
            .find(|(name, _)| name == "continuation-token")
            .map(|(_, value)| value.as_str());
        let mut matching: Vec<String> = mock
            .all_keys()
            .into_iter()
            .filter(|key| key.starts_with(key_prefix))
            .collect();
        matching.sort();
        let start_idx = match continuation_token {
            Some(token) => match token.strip_prefix("idx:") {
                Some(num) => match num.parse::<usize>() {
                    Ok(idx) => idx,
                    Err(_) => return mock.reject(format!("bad continuation-token {token:?}")),
                },
                None => return mock.reject(format!("bad continuation-token {token:?}")),
            },
            None => 0,
        };
        let max_keys = mock.max_list_keys().max(1);
        let remaining = match matching.get(start_idx..) {
            Some(slice) => slice,
            None => &[],
        };
        let is_truncated = remaining.len() > max_keys;
        let page_keys = if is_truncated {
            &remaining[..max_keys]
        } else {
            remaining
        };
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
        );
        xml.push_str(&format!("<IsTruncated>{is_truncated}</IsTruncated>"));
        if is_truncated {
            let next_token = format!("idx:{}", start_idx + page_keys.len());
            xml.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                xml_escape(&next_token)
            ));
        }
        for key in page_keys {
            xml.push_str(&format!(
                "<Contents><Key>{}</Key></Contents>",
                xml_escape(key)
            ));
        }
        xml.push_str("</ListBucketResult>");
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/xml")],
            xml,
        )
            .into_response();
    }

    let Some(key) = path.strip_prefix(&format!("/{BUCKET}/")) else {
        return mock.reject(format!("request outside the bucket: {path}"));
    };
    match method {
        Method::PUT => {
            let Some(raw_len) = content_length_header else {
                return mock.reject(format!("missing Content-Length on PUT {key}"));
            };
            let Ok(parsed_len) = raw_len.parse::<u64>() else {
                return mock.reject(format!("invalid Content-Length {raw_len:?} on PUT {key}"));
            };
            if parsed_len != body.len() as u64 {
                return mock.reject(format!(
                    "Content-Length mismatch on PUT {key}: header {parsed_len} != body {}",
                    body.len()
                ));
            }
            mock.record_put_content_length(key, parsed_len);
            mock.put(key, body.to_vec());
            StatusCode::OK.into_response()
        }
        Method::GET => match mock.object(key) {
            Some(bytes) => (StatusCode::OK, Body::from(bytes)).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                "<Error><Code>NoSuchKey</Code></Error>",
            )
                .into_response(),
        },
        Method::DELETE => {
            let _ = mock.delete(key);
            StatusCode::NO_CONTENT.into_response()
        }
        other => mock.reject(format!("unexpected method {other}")),
    }
}

/// Starts the mock and returns it with its endpoint URL.
async fn spawn_mock_r2() -> (MockR2, String) {
    let mock = MockR2::default();
    let router = Router::new()
        .fallback(handle_mock_request)
        .with_state(mock.clone());
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => panic!("mock R2 should bind: {error}"),
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => panic!("mock R2 address: {error}"),
    };
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            panic!("mock R2 failed: {error}");
        }
    });
    (mock, format!("http://{address}"))
}

fn r2_config(endpoint: &str) -> R2Config {
    R2Config {
        endpoint: endpoint.to_owned(),
        bucket: BUCKET.to_owned(),
        access_key_id: ACCESS_KEY_ID.to_owned(),
        secret_access_key: SecretString::from(SECRET_ACCESS_KEY.to_owned()),
        prefix: PREFIX.to_owned(),
    }
}

fn temp_dir() -> TempDir {
    match TempDir::new() {
        Ok(dir) => dir,
        Err(error) => panic!("temp dir: {error}"),
    }
}

fn read_text(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("cannot read {}: {error}", path.display()),
    }
}

fn write_executable(path: &Path, script: &str) {
    if let Err(error) = std::fs::write(path, script) {
        panic!("cannot write {}: {error}", path.display());
    }
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)) {
        panic!("cannot chmod {}: {error}", path.display());
    }
}

/// Writes stub `pg_dump` and `pg_restore` scripts that log their arguments
/// and `PG*` environment into `log_dir`.
fn write_pg_stubs(bin_dir: &Path, log_dir: &Path) -> (PathBuf, PathBuf) {
    let log = log_dir.display();
    let pg_dump = bin_dir.join("pg_dump");
    write_executable(
        &pg_dump,
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{log}/pg_dump.args'\n\
             env | grep '^PG' | sort > '{log}/pg_dump.env'\n\
             env | grep -c 'SCRIM_\\|DATABASE_URL' > '{log}/pg_dump.leaked' || true\n\
             while [ \"$#\" -gt 0 ]; do\n\
               if [ \"$1\" = '--file' ]; then shift; printf '{FAKE_DUMP}' > \"$1\"; fi\n\
               shift\n\
             done\n"
        ),
    );
    let pg_restore = bin_dir.join("pg_restore");
    write_executable(
        &pg_restore,
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{log}/pg_restore.args'\n\
             env | grep '^PG' | sort > '{log}/pg_restore.env'\n\
             for last; do :; done\n\
             cp \"$last\" '{log}/restored.dump'\n"
        ),
    );
    (pg_dump, pg_restore)
}

/// A repository root with `team/app.git` (commits, a private branch and a
/// tag), the empty `solo.git`, plus a hidden repository and a symlink that
/// must both be skipped.
fn seed_repo_root(sandbox: &GitSandbox, root: &Path) {
    let app = root.join("team/app.git");
    sandbox.init_bare_with_commit(&app);
    sandbox.git(
        &app,
        &["update-ref", "refs/heads/private/wip", "refs/heads/main"],
    );
    sandbox.git(&app, &["tag", "v1", "refs/heads/main"]);
    sandbox.init_bare(&root.join("solo.git"));
    sandbox.init_bare(&root.join(".trash/hidden.git"));
    if let Err(error) =
        std::os::unix::fs::symlink(root.join("team/app.git"), root.join("alias.git"))
    {
        panic!("symlink: {error}");
    }
}

fn refs_of(sandbox: &GitSandbox, repo: &Path) -> String {
    let output = sandbox.git(repo, &["for-each-ref", "--format=%(objectname) %(refname)"]);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn directory_names(path: &Path) -> Vec<String> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => panic!("cannot list {}: {error}", path.display()),
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

async fn backup(endpoint: &str, repo_root: &Path, database: Option<&Path>) -> BackupManifest {
    backup_with_keep(endpoint, repo_root, database, None).await
}

async fn backup_with_keep(
    endpoint: &str,
    repo_root: &Path,
    database: Option<&Path>,
    keep: Option<usize>,
) -> BackupManifest {
    let result = run_backup(BackupConfig {
        repo_root: repo_root.to_path_buf(),
        database_url: database.map(|_| SecretString::from(DATABASE_URL.to_owned())),
        r2: r2_config(endpoint),
        pg_dump_bin: match database {
            Some(pg_dump) => pg_dump.to_path_buf(),
            None => PathBuf::from("pg_dump-must-not-run"),
        },
        keep,
    })
    .await;
    match result {
        Ok(manifest) => manifest,
        Err(error) => panic!("backup should succeed: {error:#}"),
    }
}

fn restore_config(endpoint: &str, repo_root: &Path, pg_restore: Option<&Path>) -> RestoreConfig {
    RestoreConfig {
        repo_root: repo_root.to_path_buf(),
        database_url: pg_restore.map(|_| SecretString::from(DATABASE_URL.to_owned())),
        r2: r2_config(endpoint),
        backup_id: None,
        force: false,
        pg_restore_bin: match pg_restore {
            Some(pg_restore) => pg_restore.to_path_buf(),
            None => PathBuf::from("pg_restore-must-not-run"),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_and_restore_round_trip_with_database() {
    let (mock, endpoint) = spawn_mock_r2().await;
    let sandbox = GitSandbox::new();
    let source = temp_dir();
    seed_repo_root(&sandbox, source.path());
    let tools = temp_dir();
    let logs = temp_dir();
    let (pg_dump, pg_restore) = write_pg_stubs(tools.path(), logs.path());

    let manifest = backup(&endpoint, source.path(), Some(&pg_dump)).await;
    assert!(
        mock.rejected_requests().is_empty(),
        "{:?}",
        mock.rejected_requests()
    );
    assert_eq!(manifest.version, 1);
    let repo_keys: Vec<&str> = manifest
        .repos
        .iter()
        .map(|repo| repo.repo_key.as_str())
        .collect();
    assert_eq!(repo_keys, ["solo.git", "team/app.git"]);
    let backup_prefix = format!("{PREFIX}/{}", manifest.backup_id);
    for repo in &manifest.repos {
        assert_eq!(
            repo.object_key,
            format!("{backup_prefix}/repos/{}.tar.gz", repo.repo_key)
        );
        let Some(stored) = mock.object(&repo.object_key) else {
            panic!("{} was not uploaded", repo.object_key);
        };
        assert_eq!(hex(&Sha256::digest(&stored)), repo.sha256);
        assert_eq!(stored.len() as u64, repo.size_bytes);
        assert_eq!(
            mock.put_content_length(&repo.object_key),
            Some(repo.size_bytes)
        );
    }
    let Some(database) = &manifest.database else {
        panic!("the database should be backed up");
    };
    assert_eq!(
        database.object_key,
        format!("{backup_prefix}/database.dump")
    );
    assert_eq!(
        mock.object(&database.object_key).as_deref(),
        Some(FAKE_DUMP.as_bytes())
    );
    assert_eq!(
        mock.put_content_length(&database.object_key),
        Some(database.size_bytes)
    );
    assert_eq!(database.sha256, hex(&Sha256::digest(FAKE_DUMP.as_bytes())));
    let latest: LatestBackupPointer = match mock
        .object(&format!("{PREFIX}/latest.json"))
        .map(|bytes| serde_json::from_slice(&bytes))
    {
        Some(Ok(latest)) => latest,
        other => panic!("latest.json should be valid: {other:?}"),
    };
    assert_eq!(latest.backup_id, manifest.backup_id);
    assert_eq!(
        latest.manifest_key,
        format!("{backup_prefix}/manifest.json")
    );

    // The password only ever reaches pg_dump through PGPASSWORD.
    let dump_args = read_text(&logs.path().join("pg_dump.args"));
    assert!(!dump_args.contains("s3cr"), "{dump_args}");
    for expected in ["--format=custom", "--no-owner", "--no-privileges", "--file"] {
        assert!(
            dump_args.lines().any(|line| line == expected),
            "{dump_args}"
        );
    }
    let dump_env = read_text(&logs.path().join("pg_dump.env"));
    for expected in [
        format!("PGPASSWORD={DATABASE_PASSWORD}"),
        "PGHOST=db.internal".to_owned(),
        "PGPORT=5433".to_owned(),
        "PGUSER=scrim".to_owned(),
        "PGDATABASE=scrim".to_owned(),
        "PGSSLMODE=require".to_owned(),
    ] {
        assert!(dump_env.lines().any(|line| line == expected), "{dump_env}");
    }
    assert_eq!(read_text(&logs.path().join("pg_dump.leaked")).trim(), "0");

    let target_parent = temp_dir();
    let target = target_parent.path().join("restored");
    let restored = match run_restore(restore_config(&endpoint, &target, Some(&pg_restore))).await {
        Ok(restored) => restored,
        Err(error) => panic!("restore should succeed: {error:#}"),
    };
    assert_eq!(restored, manifest);
    assert!(
        mock.rejected_requests().is_empty(),
        "{:?}",
        mock.rejected_requests()
    );
    assert_eq!(directory_names(&target), ["solo.git", "team"]);

    let source_app = source.path().join("team/app.git");
    let restored_app = target.join("team/app.git");
    assert_eq!(
        refs_of(&sandbox, &restored_app),
        refs_of(&sandbox, &source_app)
    );
    sandbox.git(&restored_app, &["fsck", "--no-progress"]);
    let remote = sandbox.try_git(&restored_app, &["config", "--get", "remote.origin.url"]);
    assert!(
        !remote.status.success(),
        "the snapshot's origin must be removed"
    );
    let work = temp_dir();
    let Some(restored_app_text) = restored_app.to_str() else {
        panic!("non-UTF-8 path");
    };
    sandbox.git(
        work.path(),
        &["clone", "--quiet", restored_app_text, "checkout"],
    );
    assert_eq!(
        read_text(&work.path().join("checkout/hello.txt")),
        "hello\n"
    );
    let head = sandbox.git(&target.join("solo.git"), &["symbolic-ref", "HEAD"]);
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "refs/heads/main"
    );

    let restore_args = read_text(&logs.path().join("pg_restore.args"));
    assert!(!restore_args.contains("s3cr"), "{restore_args}");
    for expected in [
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        "--dbname=scrim",
    ] {
        assert!(
            restore_args.lines().any(|line| line == expected),
            "{restore_args}"
        );
    }
    let restore_env = read_text(&logs.path().join("pg_restore.env"));
    assert!(
        restore_env
            .lines()
            .any(|line| line == format!("PGPASSWORD={DATABASE_PASSWORD}")),
        "{restore_env}"
    );
    assert_eq!(read_text(&logs.path().join("restored.dump")), FAKE_DUMP);

    // An explicit backup ID restores the same backup.
    let by_id = temp_dir();
    let mut config = restore_config(&endpoint, by_id.path(), None);
    config.backup_id = Some(manifest.backup_id.clone());
    match run_restore(config).await {
        Ok(restored) => assert_eq!(restored.backup_id, manifest.backup_id),
        Err(error) => panic!("restore by ID should succeed: {error:#}"),
    }
    assert!(mock.request_count() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_empty_repo_root_requires_force() {
    let (_mock, endpoint) = spawn_mock_r2().await;
    let sandbox = GitSandbox::new();
    let source = temp_dir();
    sandbox.init_bare_with_commit(&source.path().join("team/app.git"));
    let _ = backup(&endpoint, source.path(), None).await;

    let target = temp_dir();
    if let Err(error) = std::fs::write(target.path().join("keep.txt"), "keep") {
        panic!("write: {error}");
    }
    match run_restore(restore_config(&endpoint, target.path(), None)).await {
        Ok(_) => panic!("a non-empty repo root must be refused"),
        Err(error) => assert!(format!("{error:#}").contains("not empty"), "{error:#}"),
    }
    assert_eq!(directory_names(target.path()), ["keep.txt"]);

    let mut forced = restore_config(&endpoint, target.path(), None);
    forced.force = true;
    for _ in 0..2 {
        // The second pass replaces the repository restored by the first.
        if let Err(error) = run_restore(forced.clone()).await {
            panic!("a forced restore should succeed: {error:#}");
        }
        assert_eq!(directory_names(target.path()), ["keep.txt", "team"]);
        sandbox.git(
            &target.path().join("team/app.git"),
            &["fsck", "--no-progress"],
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_objects_are_rejected_before_use() {
    let (mock, endpoint) = spawn_mock_r2().await;
    let sandbox = GitSandbox::new();
    let source = temp_dir();
    sandbox.init_bare_with_commit(&source.path().join("team/app.git"));
    let tools = temp_dir();
    let logs = temp_dir();
    let (pg_dump, pg_restore) = write_pg_stubs(tools.path(), logs.path());
    let manifest = backup(&endpoint, source.path(), Some(&pg_dump)).await;

    // A tampered database dump never reaches pg_restore.
    let Some(database) = &manifest.database else {
        panic!("the database should be backed up");
    };
    let mut dump = FAKE_DUMP.as_bytes().to_vec();
    dump[0] ^= 0x01;
    mock.put(&database.object_key, dump);
    let target = temp_dir();
    match run_restore(restore_config(&endpoint, target.path(), Some(&pg_restore))).await {
        Ok(_) => panic!("a tampered dump must be refused"),
        Err(error) => assert!(
            format!("{error:#}").contains("SHA-256 mismatch"),
            "{error:#}"
        ),
    }
    assert!(!logs.path().join("pg_restore.args").exists());

    // A tampered repository archive is refused before extraction.
    let repo = &manifest.repos[0];
    let Some(mut archive) = mock.object(&repo.object_key) else {
        panic!("archive missing");
    };
    let last = archive.len() - 1;
    archive[last] ^= 0x01;
    mock.put(&repo.object_key, archive);
    let target = temp_dir();
    match run_restore(restore_config(&endpoint, target.path(), None)).await {
        Ok(_) => panic!("a tampered archive must be refused"),
        Err(error) => assert!(
            format!("{error:#}").contains("SHA-256 mismatch"),
            "{error:#}"
        ),
    }
    assert!(directory_names(target.path()).is_empty());
}

/// Builds a `.tar.gz` from raw headers, bypassing the `tar` crate's own path
/// checks so hostile entries can be produced.
fn hostile_archive(entries: &[(&[u8], tar::EntryType, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for (name, entry_type, payload) in entries {
        let mut header = tar::Header::new_old();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        if matches!(entry_type, tar::EntryType::Symlink | tar::EntryType::Link) {
            header.as_old_mut().linkname[..payload.len()].copy_from_slice(payload);
            header.set_size(0);
        } else {
            header.set_size(payload.len() as u64);
        }
        header.set_entry_type(*entry_type);
        header.set_mode(0o644);
        header.set_cksum();
        let data: &[u8] = if matches!(entry_type, tar::EntryType::Regular) {
            payload
        } else {
            &[]
        };
        if let Err(error) = builder.append(&header, data) {
            panic!("append: {error}");
        }
    }
    let encoder = match builder.into_inner() {
        Ok(encoder) => encoder,
        Err(error) => panic!("tar: {error}"),
    };
    match encoder.finish() {
        Ok(bytes) => bytes,
        Err(error) => panic!("gzip: {error}"),
    }
}

/// Publishes a one-repository backup whose archive is `archive`.
fn publish_backup(mock: &MockR2, backup_id: &str, archive: Vec<u8>) {
    let object_key = format!("{PREFIX}/{backup_id}/repos/evil.git.tar.gz");
    let manifest = BackupManifest {
        version: 1,
        backup_id: backup_id.to_owned(),
        created_at_utc: "2026-11-22T00:00:00Z".to_owned(),
        repos: vec![BackupRepoEntry {
            repo_key: "evil.git".to_owned(),
            object_key: object_key.clone(),
            sha256: hex(&Sha256::digest(&archive)),
            size_bytes: archive.len() as u64,
        }],
        database: None,
    };
    mock.put(&object_key, archive);
    let manifest_key = format!("{PREFIX}/{backup_id}/manifest.json");
    match serde_json::to_vec(&manifest) {
        Ok(json) => mock.put(&manifest_key, json),
        Err(error) => panic!("manifest json: {error}"),
    }
    let latest = LatestBackupPointer {
        backup_id: backup_id.to_owned(),
        manifest_key,
        created_at_utc: manifest.created_at_utc.clone(),
    };
    match serde_json::to_vec(&latest) {
        Ok(json) => mock.put(&format!("{PREFIX}/latest.json"), json),
        Err(error) => panic!("latest json: {error}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsafe_archive_entries_are_rejected() {
    let (mock, endpoint) = spawn_mock_r2().await;
    let cases: [(&str, Vec<u8>); 5] = [
        (
            "dotdot",
            hostile_archive(&[(b"../escape", tar::EntryType::Regular, b"pwned")]),
        ),
        (
            "nested-dotdot",
            hostile_archive(&[
                (b"objects/", tar::EntryType::Directory, b""),
                (b"objects/../../escape", tar::EntryType::Regular, b"pwned"),
            ]),
        ),
        (
            "absolute",
            hostile_archive(&[(b"/tmp/scrim-escape", tar::EntryType::Regular, b"pwned")]),
        ),
        (
            "symlink",
            hostile_archive(&[(b"HEAD", tar::EntryType::Symlink, b"/etc/passwd")]),
        ),
        (
            "hardlink",
            hostile_archive(&[(b"HEAD", tar::EntryType::Link, b"../escape")]),
        ),
    ];
    for (case, archive) in cases {
        publish_backup(&mock, &format!("hostile-{case}"), archive);
        let parent = temp_dir();
        let target = parent.path().join("root");
        match run_restore(restore_config(&endpoint, &target, None)).await {
            Ok(_) => panic!("{case}: a hostile archive must be refused"),
            Err(error) => assert!(
                format!("{error:#}").contains("refusing"),
                "{case}: {error:#}"
            ),
        }
        assert!(!parent.path().join("escape").exists(), "{case}");
        assert!(directory_names(&target).is_empty(), "{case}");
    }
    assert!(!Path::new("/tmp/scrim-escape").exists());
}

fn seed_synthetic_backup(
    mock: &MockR2,
    backup_id: &str,
    created_at_utc: &str,
    with_database: bool,
    set_latest: bool,
) {
    let repo_bytes = format!("archive-{backup_id}").into_bytes();
    let repo_key = format!("{PREFIX}/{backup_id}/repos/team/app.git.tar.gz");
    mock.put(&repo_key, repo_bytes.clone());

    let db_artifact = if with_database {
        let db_bytes = format!("dump-{backup_id}").into_bytes();
        let db_key = format!("{PREFIX}/{backup_id}/database.dump");
        mock.put(&db_key, db_bytes.clone());
        Some(scrim_server::BackupArtifact {
            object_key: db_key,
            sha256: hex(&Sha256::digest(&db_bytes)),
            size_bytes: db_bytes.len() as u64,
        })
    } else {
        None
    };

    let manifest = BackupManifest {
        version: 1,
        backup_id: backup_id.to_owned(),
        created_at_utc: created_at_utc.to_owned(),
        repos: vec![BackupRepoEntry {
            repo_key: "team/app.git".to_owned(),
            object_key: repo_key,
            sha256: hex(&Sha256::digest(&repo_bytes)),
            size_bytes: repo_bytes.len() as u64,
        }],
        database: db_artifact,
    };
    let manifest_key = format!("{PREFIX}/{backup_id}/manifest.json");
    match serde_json::to_vec(&manifest) {
        Ok(json) => mock.put(&manifest_key, json),
        Err(error) => panic!("manifest json: {error}"),
    }
    if set_latest {
        let latest = LatestBackupPointer {
            backup_id: backup_id.to_owned(),
            manifest_key,
            created_at_utc: created_at_utc.to_owned(),
        };
        match serde_json::to_vec(&latest) {
            Ok(json) => mock.put(&format!("{PREFIX}/latest.json"), json),
            Err(error) => panic!("latest json: {error}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_backups_paginates_sorts_newest_first_and_ignores_unexpected_keys() {
    let (mock, endpoint) = spawn_mock_r2().await;
    let r2 = r2_config(&endpoint);

    // Empty bucket returns an empty list cleanly even without latest.json.
    let empty = match list_backups(&r2).await {
        Ok(list) => list,
        Err(error) => panic!("listing empty bucket should succeed: {error:#}"),
    };
    assert!(empty.is_empty());

    // Force multi-page ListObjectsV2 responses (2 keys per page).
    mock.set_max_list_keys(2);

    seed_synthetic_backup(
        &mock,
        "20261120T000000Z-aaaa0001",
        "2026-11-20T00:00:00Z",
        false,
        false,
    );
    seed_synthetic_backup(
        &mock,
        "20261121T000000Z-aaaa0002",
        "2026-11-21T00:00:00Z",
        true,
        false,
    );
    seed_synthetic_backup(
        &mock,
        "20261121T000000Z-bbbb0003",
        "2026-11-21T00:00:00Z",
        true,
        true,
    );
    // Unexpected/malformed keys that must be ignored safely.
    mock.put(
        &format!("{PREFIX}/nested/extra/manifest.json"),
        b"not-a-manifest".to_vec(),
    );
    mock.put(
        &format!("{PREFIX}/../bad/manifest.json"),
        b"not-a-manifest".to_vec(),
    );
    mock.put(&format!("{PREFIX}/stray.txt"), b"hello".to_vec());

    let listed: Vec<BackupSummary> = match list_backups(&r2).await {
        Ok(list) => list,
        Err(error) => panic!("list_backups should succeed: {error:#}"),
    };
    assert!(
        mock.rejected_requests().is_empty(),
        "{:?}",
        mock.rejected_requests()
    );
    let ids: Vec<&str> = listed.iter().map(|b| b.backup_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "20261121T000000Z-bbbb0003",
            "20261121T000000Z-aaaa0002",
            "20261120T000000Z-aaaa0001",
        ]
    );
    assert!(listed[0].is_latest);
    assert!(!listed[1].is_latest);
    assert!(!listed[2].is_latest);
    assert_eq!(listed[0].repo_count, 1);
    assert!(listed[0].has_database);
    assert!(!listed[2].has_database);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prune_backups_rejects_zero_supports_dry_run_protects_latest_and_cleans_objects() {
    let (mock, endpoint) = spawn_mock_r2().await;
    let r2 = r2_config(&endpoint);

    // keep == 0 must be rejected.
    match prune_backups(PruneConfig {
        r2: r2.clone(),
        keep: 0,
        dry_run: false,
    })
    .await
    {
        Ok(_) => panic!("keep == 0 must be rejected"),
        Err(error) => assert!(format!("{error:#}").contains("at least 1"), "{error:#}"),
    }

    mock.set_max_list_keys(3);
    // Oldest backup is pointed to by latest.json to verify unconditional protection.
    seed_synthetic_backup(
        &mock,
        "20261118T000000Z-00000001",
        "2026-11-18T00:00:00Z",
        true,
        true,
    );
    seed_synthetic_backup(
        &mock,
        "20261119T000000Z-00000002",
        "2026-11-19T00:00:00Z",
        true,
        false,
    );
    seed_synthetic_backup(
        &mock,
        "20261120T000000Z-00000003",
        "2026-11-20T00:00:00Z",
        false,
        false,
    );
    seed_synthetic_backup(
        &mock,
        "20261121T000000Z-00000004",
        "2026-11-21T00:00:00Z",
        true,
        false,
    );

    let keys_before = mock.all_keys();

    // Dry run with keep = 2: keeps newest 2 (#4, #3) PLUS latest (#1), would prune #2.
    let dry: PruneReport = match prune_backups(PruneConfig {
        r2: r2.clone(),
        keep: 2,
        dry_run: true,
    })
    .await
    {
        Ok(report) => report,
        Err(error) => panic!("dry_run prune should succeed: {error:#}"),
    };
    assert!(dry.dry_run);
    assert_eq!(dry.deleted_objects, 0);
    assert_eq!(
        dry.kept,
        [
            "20261121T000000Z-00000004",
            "20261120T000000Z-00000003",
            "20261118T000000Z-00000001",
        ]
    );
    assert_eq!(dry.pruned, ["20261119T000000Z-00000002"]);
    assert_eq!(mock.all_keys(), keys_before);
    assert!(mock.deleted_keys().is_empty());

    // Actual prune with keep = 2.
    let report = match prune_backups(PruneConfig {
        r2: r2.clone(),
        keep: 2,
        dry_run: false,
    })
    .await
    {
        Ok(report) => report,
        Err(error) => panic!("prune should succeed: {error:#}"),
    };
    assert!(!report.dry_run);
    assert_eq!(report.kept, dry.kept);
    assert_eq!(report.pruned, ["20261119T000000Z-00000002"]);
    // #2 has repo archive + database.dump + manifest.json = 3 objects.
    assert_eq!(report.deleted_objects, 3);
    assert!(
        mock.rejected_requests().is_empty(),
        "{:?}",
        mock.rejected_requests()
    );

    // manifest.json must be deleted LAST so failed prunes remain retryable.
    let deleted = mock.deleted_keys();
    assert_eq!(deleted.len(), 3);
    assert_eq!(
        deleted[2],
        format!("{PREFIX}/20261119T000000Z-00000002/manifest.json")
    );
    for remaining in mock.all_keys() {
        assert!(
            !remaining.starts_with(&format!("{PREFIX}/20261119T000000Z-00000002/")),
            "leftover object {remaining}"
        );
    }

    // Protected oldest backup (pointed to by latest.json) can still be restored.
    let listed = match list_backups(&r2).await {
        Ok(list) => list,
        Err(error) => panic!("list_backups after prune: {error:#}"),
    };
    assert_eq!(listed.len(), 3);
    assert!(
        listed
            .iter()
            .any(|b| b.backup_id == "20261118T000000Z-00000001" && b.is_latest)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_backup_with_keep_prunes_older_backups_after_publishing_latest() {
    let (mock, endpoint) = spawn_mock_r2().await;
    let sandbox = GitSandbox::new();
    let source = temp_dir();
    sandbox.init_bare_with_commit(&source.path().join("team/app.git"));

    // Seed two older backups before taking a fresh backup with keep = 2.
    seed_synthetic_backup(
        &mock,
        "20261118T000000Z-old00001",
        "2026-11-18T00:00:00Z",
        false,
        false,
    );
    seed_synthetic_backup(
        &mock,
        "20261119T000000Z-old00002",
        "2026-11-19T00:00:00Z",
        false,
        true,
    );

    let newest = backup_with_keep(&endpoint, source.path(), None, Some(2)).await;
    let listed = match list_backups(&r2_config(&endpoint)).await {
        Ok(list) => list,
        Err(error) => panic!("list_backups should succeed: {error:#}"),
    };
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].backup_id, newest.backup_id);
    assert!(listed[0].is_latest);
    assert_eq!(listed[1].backup_id, "20261119T000000Z-old00002");
    assert!(!listed[1].is_latest);
    assert!(
        mock.object(&format!("{PREFIX}/20261118T000000Z-old00001/manifest.json"))
            .is_none()
    );
}
