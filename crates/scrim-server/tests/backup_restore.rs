//! Backup and restore against an in-process mock of Cloudflare R2's S3 API
//! that re-verifies every request's SigV4 signature, with stub `pg_dump` and
//! `pg_restore` executables recording how they were invoked.

#![cfg(unix)]

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
    BackupConfig, BackupManifest, BackupRepoEntry, LatestBackupPointer, R2Config, RestoreConfig,
    S3SigningRequest, SecretString, run_backup, run_restore, sign_s3_request,
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
#[derive(Clone, Default)]
struct MockR2 {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    rejected_requests: Arc<Mutex<Vec<String>>>,
    request_count: Arc<Mutex<usize>>,
}

impl MockR2 {
    fn object(&self, key: &str) -> Option<Vec<u8>> {
        match self.objects.lock() {
            Ok(objects) => objects.get(key).cloned(),
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

/// Verifies the request's SigV4 signature and serves PUT and GET of objects.
async fn handle_mock_request(State(mock): State<MockR2>, request: Request) -> Response {
    match mock.request_count.lock() {
        Ok(mut count) => *count += 1,
        Err(_) => panic!("mock counter mutex is poisoned"),
    }
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if request.uri().query().is_some() {
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
    let expected = sign_s3_request(&S3SigningRequest {
        method: method.as_str(),
        canonical_uri: &path,
        query: &[],
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
    let Some(key) = path.strip_prefix(&format!("/{BUCKET}/")) else {
        return mock.reject(format!("request outside the bucket: {path}"));
    };
    match method {
        Method::PUT => {
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
    let result = run_backup(BackupConfig {
        repo_root: repo_root.to_path_buf(),
        database_url: database.map(|_| SecretString::from(DATABASE_URL.to_owned())),
        r2: r2_config(endpoint),
        pg_dump_bin: match database {
            Some(pg_dump) => pg_dump.to_path_buf(),
            None => PathBuf::from("pg_dump-must-not-run"),
        },
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
