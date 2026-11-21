//! Drives the real `git` client and `scrim-server` binary: clone, push,
//! fetch under protocol v0, v1 and v2, large chunked pushes, HTTP auth
//! handshakes, and CLI startup/shutdown validation.

mod common;

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use common::{GitSandbox, TEST_TOKEN, spawn_server, test_auth};
use tempfile::TempDir;

/// Ensures a spawned `scrim-server` child process is always terminated and
/// reaped if a test fails or panics before explicit shutdown.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Clone → commit → push → second clone → commit → push → pull, with the given
/// `protocol.version` and `credential.helper`.
fn run_scenario(sandbox: &GitSandbox, base_url: &str, protocol_version: &str, scratch: &Path) {
    let url = format!("{base_url}/test.git");
    let protocol = format!("protocol.version={protocol_version}");
    let cred_helper = sandbox.credential_helper_config("scrim", TEST_TOKEN);
    let first = scratch.join("first");
    let second = scratch.join("second");
    if let Err(error) = std::fs::create_dir_all(scratch) {
        panic!(
            "failed to create scratch directory {}: {error}",
            scratch.display()
        );
    }

    sandbox.git(
        scratch,
        &["-c", &protocol, "-c", &cred_helper, "clone", &url, "first"],
    );
    if let Err(error) = std::fs::write(first.join("file.txt"), "one\n") {
        panic!("failed to write first file.txt: {error}");
    }
    sandbox.git(&first, &["add", "file.txt"]);
    sandbox.git(&first, &["commit", "-m", "one"]);
    sandbox.git(
        &first,
        &[
            "-c",
            &protocol,
            "-c",
            &cred_helper,
            "push",
            "origin",
            "HEAD:refs/heads/main",
        ],
    );

    sandbox.git(
        scratch,
        &["-c", &protocol, "-c", &cred_helper, "clone", &url, "second"],
    );
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
        &[
            "-c",
            &protocol,
            "-c",
            &cred_helper,
            "push",
            "origin",
            "HEAD:refs/heads/main",
        ],
    );

    sandbox.git(
        &second,
        &["-c", &protocol, "-c", &cred_helper, "fetch", "origin"],
    );
    sandbox.git(
        &second,
        &[
            "-c",
            &protocol,
            "-c",
            &cred_helper,
            "pull",
            "--ff-only",
            "origin",
            "main",
        ],
    );
    let contents = match std::fs::read_to_string(second.join("file.txt")) {
        Ok(contents) => contents,
        Err(error) => panic!("failed to read second file.txt: {error}"),
    };
    assert_eq!(contents, "two\n");

    // Prove which protocol was really spoken on the wire.
    let trace = sandbox.git_with_env(
        scratch,
        &["-c", &protocol, "-c", &cred_helper, "ls-remote", &url],
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
    let base_url = spawn_server(root.path().to_path_buf(), test_auth()).await;

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
    let base_url = spawn_server(root.path().to_path_buf(), test_auth()).await;

    let join_result = tokio::task::spawn_blocking(move || {
        let url = format!("{base_url}/large.git");
        let cred_helper = sandbox.credential_helper_config("scrim", TEST_TOKEN);
        let payload = deterministic_incompressible_bytes(5 * 1024 * 1024);
        let first = scratch.path().join("first");
        let second = scratch.path().join("second");

        sandbox.git(
            scratch.path(),
            &["-c", &cred_helper, "clone", &url, "first"],
        );
        if let Err(error) = std::fs::write(first.join("random.bin"), &payload) {
            panic!("failed to write payload: {error}");
        }
        sandbox.git(&first, &["add", "random.bin"]);
        sandbox.git(&first, &["commit", "-m", "add 5 MiB incompressible file"]);
        sandbox.git(
            &first,
            &["-c", &cred_helper, "push", "origin", "HEAD:refs/heads/main"],
        );

        sandbox.git(
            scratch.path(),
            &["-c", &cred_helper, "clone", &url, "second"],
        );
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

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_and_wrong_token_git_operations_fail() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let sandbox = GitSandbox::new();
    sandbox.init_bare_with_commit(&root.path().join("test.git"));
    let base_url = spawn_server(root.path().to_path_buf(), test_auth()).await;

    let join_result = tokio::task::spawn_blocking(move || {
        let url = format!("{base_url}/test.git");
        let valid_cred = sandbox.credential_helper_config("scrim", TEST_TOKEN);
        let wrong_cred = sandbox.credential_helper_config("scrim", "wrong-token");

        // Unauthenticated ls-remote and clone fail.
        let unauth_ls = sandbox.try_git(scratch.path(), &["ls-remote", &url]);
        assert!(
            !unauth_ls.status.success(),
            "expected unauthenticated ls-remote to fail"
        );
        let unauth_clone = sandbox.try_git(scratch.path(), &["clone", &url, "unauth"]);
        assert!(
            !unauth_clone.status.success(),
            "expected unauthenticated clone to fail"
        );

        // Wrong-token ls-remote and clone fail.
        let wrong_ls = sandbox.try_git(scratch.path(), &["-c", &wrong_cred, "ls-remote", &url]);
        assert!(
            !wrong_ls.status.success(),
            "expected wrong-token ls-remote to fail"
        );
        let wrong_clone =
            sandbox.try_git(scratch.path(), &["-c", &wrong_cred, "clone", &url, "wrong"]);
        assert!(
            !wrong_clone.status.success(),
            "expected wrong-token clone to fail"
        );

        // Create a valid clone and local commit so we can test fetch and push.
        sandbox.git(scratch.path(), &["-c", &valid_cred, "clone", &url, "work"]);
        let work = scratch.path().join("work");
        if let Err(error) = std::fs::write(work.join("blocked.txt"), "blocked\n") {
            panic!("failed to write blocked.txt: {error}");
        }
        sandbox.git(&work, &["add", "blocked.txt"]);
        sandbox.git(&work, &["commit", "-m", "blocked commit"]);

        let unauth_fetch = sandbox.try_git(&work, &["fetch", "origin"]);
        assert!(
            !unauth_fetch.status.success(),
            "expected unauthenticated fetch to fail"
        );
        let unauth_push = sandbox.try_git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
        assert!(
            !unauth_push.status.success(),
            "expected unauthenticated push to fail"
        );

        let wrong_fetch = sandbox.try_git(&work, &["-c", &wrong_cred, "fetch", "origin"]);
        assert!(
            !wrong_fetch.status.success(),
            "expected wrong-token fetch to fail"
        );
        let wrong_push = sandbox.try_git(
            &work,
            &["-c", &wrong_cred, "push", "origin", "HEAD:refs/heads/main"],
        );
        assert!(
            !wrong_push.status.success(),
            "expected wrong-token push to fail"
        );
        drop(scratch);
    })
    .await;

    if let Err(error) = join_result {
        panic!("blocking task failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn clone_commit_push_and_fetch_with_bearer_header() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let sandbox = GitSandbox::new();
    sandbox.init_bare(&root.path().join("test.git"));
    let base_url = spawn_server(root.path().to_path_buf(), test_auth()).await;

    let join_result = tokio::task::spawn_blocking(move || {
        let url = format!("{base_url}/test.git");
        let bearer_config = format!("http.extraHeader=Authorization: Bearer {TEST_TOKEN}");
        let first = scratch.path().join("first");
        let second = scratch.path().join("second");

        sandbox.git(
            scratch.path(),
            &["-c", &bearer_config, "clone", &url, "first"],
        );
        if let Err(error) = std::fs::write(first.join("bearer.txt"), "one\n") {
            panic!("failed to write bearer.txt: {error}");
        }
        sandbox.git(&first, &["add", "bearer.txt"]);
        sandbox.git(&first, &["commit", "-m", "one"]);
        sandbox.git(
            &first,
            &[
                "-c",
                &bearer_config,
                "push",
                "origin",
                "HEAD:refs/heads/main",
            ],
        );

        sandbox.git(
            scratch.path(),
            &["-c", &bearer_config, "clone", &url, "second"],
        );
        let contents = match std::fs::read_to_string(second.join("bearer.txt")) {
            Ok(contents) => contents,
            Err(error) => panic!("failed to read second bearer.txt: {error}"),
        };
        assert_eq!(contents, "one\n");

        if let Err(error) = std::fs::write(first.join("bearer.txt"), "two\n") {
            panic!("failed to update bearer.txt: {error}");
        }
        sandbox.git(&first, &["commit", "-am", "two"]);
        sandbox.git(
            &first,
            &[
                "-c",
                &bearer_config,
                "push",
                "origin",
                "HEAD:refs/heads/main",
            ],
        );

        sandbox.git(&second, &["-c", &bearer_config, "fetch", "origin"]);
        sandbox.git(
            &second,
            &["-c", &bearer_config, "pull", "--ff-only", "origin", "main"],
        );
        let contents = match std::fs::read_to_string(second.join("bearer.txt")) {
            Ok(contents) => contents,
            Err(error) => panic!("failed to read updated bearer.txt: {error}"),
        };
        assert_eq!(contents, "two\n");
        drop(scratch);
    })
    .await;

    if let Err(error) = join_result {
        panic!("blocking task failed: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ls_remote_and_clone_with_url_embedded_basic_credentials() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let sandbox = GitSandbox::new();
    sandbox.init_bare_with_commit(&root.path().join("test.git"));
    let base_url = spawn_server(root.path().to_path_buf(), test_auth()).await;

    let join_result = tokio::task::spawn_blocking(move || {
        let host = match base_url.strip_prefix("http://") {
            Some(host) => host,
            None => panic!("unexpected base URL: {base_url}"),
        };

        for (label, url) in [
            (
                "user-and-token",
                format!("http://scrim:{TEST_TOKEN}@{host}/test.git"),
            ),
            ("token-only", format!("http://{TEST_TOKEN}@{host}/test.git")),
        ] {
            let ls = sandbox.git(scratch.path(), &["ls-remote", &url]);
            let stdout = String::from_utf8_lossy(&ls.stdout);
            assert!(
                stdout.contains("refs/heads/main"),
                "expected refs/heads/main in ls-remote for {label}: {stdout:?}"
            );

            sandbox.git(scratch.path(), &["clone", &url, label]);
            let contents =
                match std::fs::read_to_string(scratch.path().join(label).join("hello.txt")) {
                    Ok(contents) => contents,
                    Err(error) => panic!("failed to read cloned hello.txt for {label}: {error}"),
                };
            assert_eq!(contents, "hello\n");
        }
        drop(scratch);
    })
    .await;

    if let Err(error) = join_result {
        panic!("blocking task failed: {error}");
    }
}

fn scrim_server_command(repo_root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scrim-server"));
    cmd.arg("--repo-root")
        .arg(repo_root)
        .env_remove("SCRIM_TOKEN")
        .env_remove("SCRIM_TOKEN_FILE")
        .env_remove("SCRIM_REPO_ROOT")
        .env_remove("SCRIM_LISTEN")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1");
    cmd
}

fn extract_listen_address(line: &str) -> Option<String> {
    if let Some((_, rest)) = line.split_once("address=")
        && let Some(addr) = rest
            .split(|ch: char| ch.is_whitespace() || ch == '\x1b')
            .next()
        && !addr.is_empty()
    {
        return Some(addr.to_owned());
    }
    None
}

#[test]
fn cli_fails_without_token_or_token_file() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let output = match scrim_server_command(root.path())
        .args(["--listen", "127.0.0.1:0"])
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run scrim-server: {error}"),
    };
    assert!(
        !output.status.success(),
        "expected scrim-server without token to fail"
    );
}

#[test]
fn cli_fails_when_both_token_and_token_file_are_provided() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let token_path = scratch.path().join("token.txt");
    if let Err(error) = std::fs::write(&token_path, TEST_TOKEN) {
        panic!("failed to write token file: {error}");
    }

    let output = match scrim_server_command(root.path())
        .args([
            "--listen",
            "127.0.0.1:0",
            "--token",
            TEST_TOKEN,
            "--token-file",
        ])
        .arg(&token_path)
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run scrim-server: {error}"),
    };
    assert!(
        !output.status.success(),
        "expected scrim-server with both --token and --token-file to fail"
    );
}

#[test]
fn cli_fails_when_scrim_token_is_empty_or_has_whitespace() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    for invalid in ["", "has space", "has\ttab", "has\nnewline"] {
        let output = match scrim_server_command(root.path())
            .args(["--listen", "127.0.0.1:0"])
            .env("SCRIM_TOKEN", invalid)
            .output()
        {
            Ok(output) => output,
            Err(error) => panic!("failed to run scrim-server: {error}"),
        };
        assert!(
            !output.status.success(),
            "expected scrim-server to reject SCRIM_TOKEN={invalid:?}"
        );
    }
}

#[test]
fn cli_fails_when_token_file_is_missing_or_oversized() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };

    let missing_path = scratch.path().join("missing-token.txt");
    let missing_output = match scrim_server_command(root.path())
        .args(["--listen", "127.0.0.1:0", "--token-file"])
        .arg(&missing_path)
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run scrim-server: {error}"),
    };
    assert!(
        !missing_output.status.success(),
        "expected missing --token-file to fail"
    );

    let oversized_path = scratch.path().join("oversized-token.txt");
    let oversized_contents = "a".repeat(4097);
    if let Err(error) = std::fs::write(&oversized_path, oversized_contents) {
        panic!("failed to write oversized token file: {error}");
    }
    let oversized_output = match scrim_server_command(root.path())
        .args(["--listen", "127.0.0.1:0", "--token-file"])
        .arg(&oversized_path)
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run scrim-server: {error}"),
    };
    assert!(
        !oversized_output.status.success(),
        "expected oversized --token-file to fail"
    );
}

#[cfg(unix)]
#[test]
fn cli_rejects_fifo_token_file_without_hanging() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let fifo_path = scratch.path().join("token.fifo");
    let mkfifo_status = match Command::new("mkfifo").arg(&fifo_path).status() {
        Ok(status) => status,
        Err(error) => panic!("failed to run mkfifo: {error}"),
    };
    assert!(mkfifo_status.success(), "mkfifo failed: {mkfifo_status}");

    let child = match scrim_server_command(root.path())
        .args(["--listen", "127.0.0.1:0", "--token-file"])
        .arg(&fifo_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => panic!("failed to spawn scrim-server: {error}"),
    };
    let mut guard = ChildGuard::new(child);

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        let try_result = match guard.child.as_mut() {
            Some(child) => child.try_wait(),
            None => panic!("child process missing"),
        };
        match try_result {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    panic!("scrim-server hung while opening FIFO --token-file");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("failed waiting on scrim-server: {error}"),
        }
    };
    guard.child = None;
    assert!(
        !status.success(),
        "expected FIFO --token-file to be rejected, got {status}"
    );
}

#[test]
fn cli_serves_with_token_file_and_shuts_down_cleanly() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let Ok(scratch) = TempDir::new() else {
        panic!("failed to create scratch temp dir");
    };
    let sandbox = GitSandbox::new();
    sandbox.init_bare_with_commit(&root.path().join("test.git"));

    let token_path = scratch.path().join("token.txt");
    if let Err(error) = std::fs::write(&token_path, format!("{TEST_TOKEN}\r\n")) {
        panic!("failed to write token file: {error}");
    }

    let mut child = match scrim_server_command(root.path())
        .args(["--listen", "127.0.0.1:0", "--token-file"])
        .arg(&token_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => panic!("failed to spawn scrim-server: {error}"),
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => panic!("child stdout was not captured"),
    };
    let mut guard = ChildGuard::new(child);

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some(addr) = extract_listen_address(&line) {
                    let _ = tx.send(addr);
                    break;
                }
            } else {
                break;
            }
        }
    });

    let address = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(address) => address,
        Err(error) => panic!("timed out waiting for scrim-server to bind: {error}"),
    };
    let url = format!("http://{address}/test.git");

    let unauth = sandbox.try_git(scratch.path(), &["ls-remote", &url]);
    assert!(
        !unauth.status.success(),
        "expected unauthenticated ls-remote against CLI server to fail"
    );

    let cred_helper = sandbox.credential_helper_config("scrim", TEST_TOKEN);
    let auth_out = sandbox.git(scratch.path(), &["-c", &cred_helper, "ls-remote", &url]);
    let stdout_text = String::from_utf8_lossy(&auth_out.stdout);
    assert!(
        stdout_text.contains("refs/heads/main"),
        "expected refs/heads/main from CLI server ls-remote: {stdout_text:?}"
    );

    #[cfg(unix)]
    {
        let pid = match guard.child.as_ref() {
            Some(child) => child.id(),
            None => panic!("child process missing before shutdown"),
        };
        let kill_status = match Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
        {
            Ok(status) => status,
            Err(error) => panic!("failed to send SIGINT to scrim-server: {error}"),
        };
        assert!(kill_status.success(), "kill -INT failed: {kill_status}");

        let deadline = Instant::now() + Duration::from_secs(5);
        let exit_status = loop {
            let status_result = match guard.child.as_mut() {
                Some(child) => child.try_wait(),
                None => panic!("child process missing during shutdown"),
            };
            match status_result {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        panic!("scrim-server did not shut down cleanly within 5s");
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => panic!("failed waiting for scrim-server shutdown: {error}"),
            }
        };
        guard.child = None;
        assert!(
            exit_status.success(),
            "expected clean exit after SIGINT, got {exit_status}"
        );
    }
}
