//! Drives the real `git` client through the server: clone, push and fetch under
//! protocol v0, v1 and v2, plus a large chunked push.

mod common;

use std::path::Path;

use common::{GitSandbox, spawn_server};
use tempfile::TempDir;

/// Clone → commit → push → second clone → commit → push → pull, with the given
/// `protocol.version`.
fn run_scenario(sandbox: &GitSandbox, base_url: &str, protocol_version: &str, scratch: &Path) {
    let url = format!("{base_url}/test.git");
    let protocol = format!("protocol.version={protocol_version}");
    let first = scratch.join("first");
    let second = scratch.join("second");
    if let Err(error) = std::fs::create_dir_all(scratch) {
        panic!(
            "failed to create scratch directory {}: {error}",
            scratch.display()
        );
    }

    sandbox.git(scratch, &["-c", &protocol, "clone", &url, "first"]);
    if let Err(error) = std::fs::write(first.join("file.txt"), "one\n") {
        panic!("failed to write first file.txt: {error}");
    }
    sandbox.git(&first, &["add", "file.txt"]);
    sandbox.git(&first, &["commit", "-m", "one"]);
    sandbox.git(
        &first,
        &["-c", &protocol, "push", "origin", "HEAD:refs/heads/main"],
    );

    sandbox.git(scratch, &["-c", &protocol, "clone", &url, "second"]);
    let contents = match std::fs::read_to_string(second.join("file.txt")) {
        Ok(contents) => contents,
        Err(error) => panic!("failed to read second file.txt: {error}"),
    };
    assert_eq!(contents, "one\n");

    if let Err(error) = std::fs::write(first.join("file.txt"), "two\n") {
        panic!("failed to write first file.txt: {error}");
    }
    sandbox.git(&first, &["commit", "-am", "two"]);
    sandbox.git(
        &first,
        &["-c", &protocol, "push", "origin", "HEAD:refs/heads/main"],
    );

    sandbox.git(&second, &["-c", &protocol, "fetch", "origin"]);
    sandbox.git(
        &second,
        &["-c", &protocol, "pull", "--ff-only", "origin", "main"],
    );
    let contents = match std::fs::read_to_string(second.join("file.txt")) {
        Ok(contents) => contents,
        Err(error) => panic!("failed to read second file.txt: {error}"),
    };
    assert_eq!(contents, "two\n");

    // Prove which protocol was really spoken on the wire.
    let trace = sandbox.git_with_env(
        scratch,
        &["-c", &protocol, "ls-remote", &url],
        &[("GIT_TRACE_PACKET", "1")],
    );
    let trace = String::from_utf8_lossy(&trace.stderr);
    assert_eq!(
        trace.contains("version 1"),
        protocol_version == "1",
        "unexpected protocol v1 negotiation:\n{trace}"
    );
    assert_eq!(
        trace.contains("version 2"),
        protocol_version == "2",
        "unexpected protocol v2 negotiation:\n{trace}"
    );
}

/// Generates deterministic incompressible bytes using xorshift64 so git
/// exceeds its default `http.postBuffer` and streams via chunked transfer.
fn deterministic_incompressible_bytes(length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    while output.len() < length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let remaining = length - output.len();
        let bytes = state.to_le_bytes();
        output.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
    }
    output
}

async fn clone_push_fetch(protocol_version: &'static str) {
    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create root temp dir: {error}"),
    };
    let scratch = match TempDir::new() {
        Ok(scratch) => scratch,
        Err(error) => panic!("failed to create scratch temp dir: {error}"),
    };
    let sandbox = GitSandbox::new();
    sandbox.init_bare(&root.path().join("test.git"));
    let base_url = spawn_server(root.path().to_path_buf()).await;

    let join_result = tokio::task::spawn_blocking(move || {
        run_scenario(&sandbox, &base_url, protocol_version, scratch.path());
        drop(scratch);
    })
    .await;
    if let Err(error) = join_result {
        panic!("blocking task failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn clone_push_fetch_with_protocol_v0() {
    clone_push_fetch("0").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clone_push_fetch_with_protocol_v1() {
    clone_push_fetch("1").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clone_push_fetch_with_protocol_v2() {
    clone_push_fetch("2").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn push_and_clone_large_incompressible_file() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let sandbox = GitSandbox::new();
    sandbox.init_bare(&root.path().join("large.git"));
    let base_url = spawn_server(root.path().to_path_buf()).await;

    let join_result = tokio::task::spawn_blocking(move || {
        let url = format!("{base_url}/large.git");
        let payload = deterministic_incompressible_bytes(5 * 1024 * 1024);
        let first = scratch.path().join("first");
        let second = scratch.path().join("second");

        sandbox.git(scratch.path(), &["clone", &url, "first"]);
        if let Err(error) = std::fs::write(first.join("random.bin"), &payload) {
            panic!("failed to write payload: {error}");
        }
        sandbox.git(&first, &["add", "random.bin"]);
        sandbox.git(&first, &["commit", "-m", "add 5 MiB incompressible file"]);
        sandbox.git(&first, &["push", "origin", "HEAD:refs/heads/main"]);

        sandbox.git(scratch.path(), &["clone", &url, "second"]);
        let cloned = match std::fs::read(second.join("random.bin")) {
            Ok(bytes) => bytes,
            Err(error) => panic!("failed to read cloned payload: {error}"),
        };
        assert_eq!(cloned, payload);
        drop(scratch);
    })
    .await;

    if let Err(error) = join_result {
        panic!("blocking task failed: {error}");
    }
}
