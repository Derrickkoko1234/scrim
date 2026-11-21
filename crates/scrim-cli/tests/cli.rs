#![allow(clippy::question_mark)]

use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

fn must<T, E: Display>(res: Result<T, E>, context: &str) -> T {
    match res {
        Ok(val) => val,
        Err(err) => panic!("{context}: {err}"),
    }
}

fn must_some<T>(opt: Option<T>, context: &str) -> T {
    match opt {
        Some(val) => val,
        None => panic!("expected Some for {context}"),
    }
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    target: String,
    authorization: Option<String>,
    body: String,
}

type Handler = dyn Fn(&RecordedRequest) -> (u16, String) + Send + Sync;

struct MockServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = must(
            TcpListener::bind("127.0.0.1:0"),
            "bind mock HTTP TcpListener",
        );
        must(
            listener.set_nonblocking(true),
            "set nonblocking on mock TcpListener",
        );
        let addr = must(listener.local_addr(), "read mock server local_addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);

        let requests_bg = Arc::clone(&requests);
        let stop_bg = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let req_log = Arc::clone(&requests_bg);
                        let h = Arc::clone(&handler);
                        handle_connection(stream, &req_log, h.as_ref());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn take_requests(&self) -> Vec<RecordedRequest> {
        let mut guard = match self.requests.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *guard)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    requests: &Mutex<Vec<RecordedRequest>>,
    handler: &Handler,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let cloned = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(cloned);

    let mut request_line = String::new();
    match reader.read_line(&mut request_line) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }

    let mut parts = request_line
        .trim_end_matches(['\r', '\n'])
        .split_whitespace();
    let method = match parts.next() {
        Some(m) => m.to_owned(),
        None => return,
    };
    let target = match parts.next() {
        Some(t) => t.to_owned(),
        None => return,
    };

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, val)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), val.trim().to_owned());
        }
    }

    let content_length = match headers.get("content-length") {
        Some(raw) => match raw.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return,
        },
        None => 0,
    };

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body_bytes).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body_bytes).into_owned();

    let recorded = RecordedRequest {
        method,
        target,
        authorization: headers.get("authorization").cloned(),
        body,
    };
    let (status, resp_body) = handler(&recorded);

    {
        let mut guard = match requests.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.push(recorded);
    }

    let reason = match status {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Status",
    };

    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
        resp_body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn scrim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_scrim")
}

fn git_scrim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_git-scrim")
}

fn run_bin(
    bin: &str,
    args: &[&str],
    cwd: &Path,
    config_path: &Path,
    stdin_data: Option<&str>,
) -> Output {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .env("SCRIM_CONFIG", config_path)
        .env_remove("SCRIM_SERVER")
        .env_remove("SCRIM_TOKEN")
        .env_remove("SCRIM_CONFIG_DIR")
        .env_remove("XDG_CONFIG_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let mut child = must(cmd.spawn(), "spawn CLI binary");
    if let Some(input) = stdin_data {
        let mut child_stdin = must_some(child.stdin.take(), "child stdin pipe");
        must(child_stdin.write_all(input.as_bytes()), "write stdin");
    }

    must(child.wait_with_output(), "wait for CLI binary")
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn init_temp_git_repo(parent: &Path, name: &str) -> PathBuf {
    let repo_dir = parent.join(name);
    must(fs::create_dir_all(&repo_dir), "create temp git repo dir");
    let output = must(
        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .arg("init")
            .output(),
        "run git init",
    );
    assert!(
        output.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    repo_dir
}

fn git_stdout(repo_dir: &Path, args: &[&str]) -> Option<String> {
    let output = must(
        Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(args)
            .output(),
        "run git command",
    );
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    )
}

#[test]
fn login_verifies_credentials_saves_0600_and_never_overwrites_on_401() {
    let server = MockServer::start(|req| match (req.method.as_str(), req.target.as_str()) {
        ("GET", "/api/v1/whoami") => {
            if req.authorization.as_deref() == Some("Bearer scrim_valid_tok") {
                (
                    200,
                    r#"{"id":1,"name":"alice","is_admin":true,"groups":["core"]}"#.to_owned(),
                )
            } else {
                (401, r#"{"error":"invalid token"}"#.to_owned())
            }
        }
        _ => (404, r#"{"error":"not found"}"#.to_owned()),
    });

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_path = tmp.path().join("cfg").join("config.toml");

    // 1. Valid login with --token-stdin (including CRLF newline).
    let out = run_bin(
        scrim_bin(),
        &[
            "login",
            "--server",
            &format!("{}/", server.url()),
            "--token-stdin",
        ],
        tmp.path(),
        &config_path,
        Some("scrim_valid_tok\r\n"),
    );
    assert!(
        out.status.success(),
        "login failed: stderr={}",
        stderr_str(&out)
    );
    let stdout = stdout_str(&out);
    assert!(stdout.contains("Logged in as alice (admin)"));
    assert!(stdout.contains(&server.url()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = must(fs::metadata(&config_path), "stat config.toml");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    let saved_before = must(fs::read_to_string(&config_path), "read saved config");
    assert!(saved_before.contains("scrim_valid_tok"));

    // 2. Invalid login (401) must fail and NOT overwrite existing config.
    let bad_out = run_bin(
        scrim_bin(),
        &[
            "login",
            "--server",
            &server.url(),
            "--token",
            "scrim_bad_tok",
        ],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(!bad_out.status.success(), "expected 401 login to fail");
    assert!(stderr_str(&bad_out).contains("invalid token"));

    let saved_after = must(fs::read_to_string(&config_path), "read config after 401");
    assert_eq!(saved_before, saved_after);
}

#[test]
fn whoami_works_via_both_scrim_and_git_scrim_binaries() {
    let server = MockServer::start(|req| match (req.method.as_str(), req.target.as_str()) {
        ("GET", "/api/v1/whoami") => {
            assert_eq!(req.authorization.as_deref(), Some("Bearer scrim_tok"));
            (
                200,
                r#"{"id":7,"name":"bob","is_admin":false,"groups":["backend","qa"]}"#.to_owned(),
            )
        }
        _ => (404, r#"{"error":"not found"}"#.to_owned()),
    });

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_path = tmp.path().join("config.toml");
    must(
        fs::write(
            &config_path,
            format!("server = \"{}\"\ntoken = \"scrim_tok\"\n", server.url()),
        ),
        "write config.toml",
    );

    for bin in [scrim_bin(), git_scrim_bin()] {
        let out = run_bin(bin, &["whoami"], tmp.path(), &config_path, None);
        assert!(
            out.status.success(),
            "whoami failed for {bin}: {}",
            stderr_str(&out)
        );
        let text = stdout_str(&out);
        assert!(text.contains("Member: bob (member)"));
        assert!(text.contains("Groups: backend, qa"));
    }

    let reqs = server.take_requests();
    assert_eq!(reqs.len(), 2);
}

#[test]
fn init_configures_local_git_repo_and_respects_force_and_no_remote() {
    let server = MockServer::start(|req| match (req.method.as_str(), req.target.as_str()) {
        ("POST", "/api/v1/repositories") => {
            let parsed: serde_json::Value =
                must(serde_json::from_str(&req.body), "parse init body");
            let path = must_some(parsed["path"].as_str(), "repo path in body");
            (
                201,
                format!(
                    r#"{{"id":10,"path":"{}","created":true,"bare_initialized":true}}"#,
                    path
                ),
            )
        }
        _ => (404, r#"{"error":"not found"}"#.to_owned()),
    });

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_path = tmp.path().join("config.toml");
    must(
        fs::write(
            &config_path,
            format!("server = \"{}\"\ntoken = \"scrim_tok\"\n", server.url()),
        ),
        "write config.toml",
    );

    let repo_dir = init_temp_git_repo(tmp.path(), "my-project");

    // 1. First init sets scrim.repo, scrim.server, and origin remote.
    let out = run_bin(scrim_bin(), &["init"], &repo_dir, &config_path, None);
    assert!(out.status.success(), "init failed: {}", stderr_str(&out));
    assert_eq!(
        git_stdout(&repo_dir, &["config", "--local", "--get", "scrim.repo"]).as_deref(),
        Some("my-project.git")
    );
    assert_eq!(
        git_stdout(&repo_dir, &["config", "--local", "--get", "scrim.server"]).as_deref(),
        Some(server.url().as_str())
    );
    let expected_remote = format!("{}/my-project.git", server.url());
    assert_eq!(
        git_stdout(&repo_dir, &["remote", "get-url", "origin"]).as_deref(),
        Some(expected_remote.as_str())
    );

    // 2. Re-running with same remote succeeds idempotently.
    let out_idem = run_bin(scrim_bin(), &["init"], &repo_dir, &config_path, None);
    assert!(
        out_idem.status.success(),
        "idempotent init failed: {}",
        stderr_str(&out_idem)
    );

    // 3. Conflicting origin remote fails without --force.
    let set_other = must(
        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args([
                "remote",
                "set-url",
                "origin",
                "https://other.example/repo.git",
            ])
            .output(),
        "set conflicting remote",
    );
    assert!(set_other.status.success());

    let out_conflict = run_bin(scrim_bin(), &["init"], &repo_dir, &config_path, None);
    assert!(
        !out_conflict.status.success(),
        "expected conflict without --force"
    );
    assert!(stderr_str(&out_conflict).contains("--force"));

    // 4. --no-remote skips touching the conflicting remote.
    let out_no_remote = run_bin(
        scrim_bin(),
        &["init", "--no-remote", "--no-create", "custom/repo.git"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(
        out_no_remote.status.success(),
        "init --no-remote failed: {}",
        stderr_str(&out_no_remote)
    );
    assert_eq!(
        git_stdout(&repo_dir, &["remote", "get-url", "origin"]).as_deref(),
        Some("https://other.example/repo.git")
    );
    assert_eq!(
        git_stdout(&repo_dir, &["config", "--local", "--get", "scrim.repo"]).as_deref(),
        Some("custom/repo.git")
    );

    // 5. --force overwrites the conflicting remote.
    let out_force = run_bin(
        scrim_bin(),
        &["init", "--force"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(
        out_force.status.success(),
        "init --force failed: {}",
        stderr_str(&out_force)
    );
    assert_eq!(
        git_stdout(&repo_dir, &["remote", "get-url", "origin"]).as_deref(),
        Some(expected_remote.as_str())
    );

    let reqs = server.take_requests();
    assert_eq!(reqs.len(), 5);
    let no_create_body: serde_json::Value = must(
        serde_json::from_str(&reqs[3].body),
        "parse --no-create body",
    );
    assert_eq!(no_create_body["create_bare"], serde_json::json!(false));
    assert_eq!(no_create_body["path"], serde_json::json!("custom/repo.git"));
}

#[test]
fn group_and_access_commands_call_expected_endpoints() {
    let server = MockServer::start(|req| {
        match (req.method.as_str(), req.target.as_str()) {
        ("POST", "/api/v1/groups") => (201, r#"{"id":1,"name":"core team"}"#.to_owned()),
        ("POST", "/api/v1/groups/core%20team/members") => (
            200,
            r#"{"group":"core team","member":"alice smith","added":true}"#.to_owned(),
        ),
        ("DELETE", "/api/v1/groups/core%20team/members/alice%20smith") => (
            200,
            r#"{"group":"core team","member":"alice smith","removed":true}"#.to_owned(),
        ),
        ("GET", "/api/v1/groups") => (
            200,
            r#"{"groups":[{"id":1,"name":"core team","members":["bob"]}]}"#.to_owned(),
        ),
        ("POST", "/api/v1/members") => (
            201,
            r#"{"member":{"id":2,"name":"ci-bot","is_admin":true,"is_machine":true,"groups":["core","ops"],"revoked":false},"token":"scrim_issued_once"}"#.to_owned(),
        ),
        ("POST", "/api/v1/members/ci-bot/tokens") => (
            201,
            r#"{"member":"ci-bot","label":"deploy","token":"scrim_second_tok"}"#.to_owned(),
        ),
        ("DELETE", "/api/v1/members/ci-bot") => {
            (200, r#"{"name":"ci-bot","revoked":true}"#.to_owned())
        }
        ("GET", "/api/v1/members?include_revoked=false") => (
            200,
            r#"{"members":[{"id":1,"name":"alice","is_admin":false,"is_machine":false,"groups":["core"],"revoked":false}]}"#.to_owned(),
        ),
        ("GET", "/api/v1/members?include_revoked=true") => (
            200,
            r#"{"members":[{"id":1,"name":"alice","is_admin":false,"is_machine":false,"groups":["core"],"revoked":false},{"id":2,"name":"ci-bot","is_admin":true,"is_machine":true,"groups":["core","ops"],"revoked":true}]}"#.to_owned(),
        ),
        _ => (404, r#"{"error":"unexpected route"}"#.to_owned()),
    }
    });

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_path = tmp.path().join("config.toml");
    must(
        fs::write(
            &config_path,
            format!("server = \"{}\"\ntoken = \"scrim_admin\"\n", server.url()),
        ),
        "write config.toml",
    );

    let out = run_bin(
        scrim_bin(),
        &["group", "create", "core team"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));

    let out = run_bin(
        scrim_bin(),
        &["group", "add", "core team", "alice smith"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));

    let out = run_bin(
        scrim_bin(),
        &["group", "remove", "core team", "alice smith"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));

    let out = run_bin(
        scrim_bin(),
        &["group", "list"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    assert!(stdout_str(&out).contains("core team: bob"));

    let out = run_bin(
        scrim_bin(),
        &[
            "access",
            "grant",
            "ci-bot",
            "--group",
            "core",
            "--group",
            "ops",
            "--admin",
            "--machine",
            "--token-label",
            "runner",
        ],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    let grant_out = stdout_str(&out);
    assert!(grant_out.contains("scrim_issued_once"));
    assert!(grant_out.contains("shown only once"));

    let out = run_bin(
        scrim_bin(),
        &["access", "token", "ci-bot", "--label", "deploy"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    assert!(stdout_str(&out).contains("scrim_second_tok"));

    let out = run_bin(
        scrim_bin(),
        &["access", "revoke", "ci-bot"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));

    let out = run_bin(
        scrim_bin(),
        &["access", "list"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    assert!(!stdout_str(&out).contains("ci-bot"));

    let out = run_bin(
        scrim_bin(),
        &["access", "list", "--all"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    let list_all = stdout_str(&out);
    assert!(list_all.contains("ci-bot: admin, machine, revoked"));

    let reqs = server.take_requests();
    assert_eq!(reqs.len(), 9);
    let grant_body: serde_json::Value =
        must(serde_json::from_str(&reqs[4].body), "parse grant body");
    assert_eq!(grant_body["name"], serde_json::json!("ci-bot"));
    assert_eq!(grant_body["is_admin"], serde_json::json!(true));
    assert_eq!(grant_body["is_machine"], serde_json::json!(true));
    assert_eq!(grant_body["groups"], serde_json::json!(["core", "ops"]));
    assert_eq!(grant_body["token_label"], serde_json::json!("runner"));
}

#[test]
fn branch_commands_validate_glob_locally_and_autodetect_repo_and_server() {
    let server = MockServer::start(|req| {
        match (req.method.as_str(), req.target.as_str()) {
        ("PUT", "/api/v1/branch-rules") => {
            let parsed: serde_json::Value = must(serde_json::from_str(&req.body), "parse branch put");
            assert_eq!(parsed["repository"], serde_json::json!("org/app.git"));
            assert_eq!(parsed["pattern"], serde_json::json!("refs/heads/private/*"));
            assert_eq!(parsed["groups"], serde_json::json!(["core"]));
            (
                200,
                r#"{"repository":"org/app.git","pattern":"refs/heads/private/*","groups":["core"]}"#
                    .to_owned(),
            )
        }
        ("GET", "/api/v1/branch-rules?repo=org%2Fapp.git") => (
            200,
            r#"{"repository":"org/app.git","rules":[{"pattern":"refs/heads/private/*","groups":["core"]}]}"#
                .to_owned(),
        ),
        ("DELETE", "/api/v1/branch-rules?repo=org%2Fapp.git&pattern=refs%2Fheads%2Fprivate%2F*") => (
            200,
            r#"{"repository":"org/app.git","pattern":"refs/heads/private/*","removed":true}"#
                .to_owned(),
        ),
        _ => (404, r#"{"error":"not found"}"#.to_owned()),
    }
    });

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_path = tmp.path().join("config.toml");
    // Config intentionally omits `server` so local git config `scrim.server` fallback is exercised.
    must(
        fs::write(&config_path, "token = \"scrim_tok\"\n"),
        "write config.toml",
    );

    let repo_dir = init_temp_git_repo(tmp.path(), "app");
    let set_repo = must(
        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["config", "--local", "scrim.repo", "org/app.git"])
            .output(),
        "set scrim.repo",
    );
    assert!(set_repo.status.success());
    let set_server = must(
        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["config", "--local", "scrim.server", &server.url()])
            .output(),
        "set scrim.server",
    );
    assert!(set_server.status.success());

    // Invalid glob must fail locally without hitting the server.
    let bad_glob = run_bin(
        scrim_bin(),
        &["branch", "private", "heads/bad", "--group", "core"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(!bad_glob.status.success());
    assert!(stderr_str(&bad_glob).contains("refs/"));
    assert!(server.take_requests().is_empty());

    // Valid private rule, list, and unprotect alias.
    let out = run_bin(
        scrim_bin(),
        &[
            "branch",
            "private",
            "refs/heads/private/*",
            "--group",
            "core",
        ],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));

    let out = run_bin(
        scrim_bin(),
        &["branch", "list"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    assert!(stdout_str(&out).contains("refs/heads/private/*: core"));

    let out = run_bin(
        scrim_bin(),
        &["branch", "unprotect", "refs/heads/private/*"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(out.status.success(), "{}", stderr_str(&out));
    assert!(stdout_str(&out).contains("Removed branch rule"));

    let reqs = server.take_requests();
    assert_eq!(reqs.len(), 3);
}

#[test]
fn surfaces_server_error_statuses_with_nonzero_exit() {
    for (status, json_body, expected_msg) in [
        (401, r#"{"error":"unauthorized"}"#, "unauthorized"),
        (403, r#"{"error":"admin required"}"#, "admin required"),
        (404, r#"{"error":"group missing"}"#, "group missing"),
        (409, r#"{"error":"already exists"}"#, "already exists"),
        (500, "plain text failure", "Internal Server Error"),
    ] {
        let body = json_body.to_owned();
        let server = MockServer::start(move |_| (status, body.clone()));
        let tmp = must(tempfile::tempdir(), "create tempdir");
        let config_path = tmp.path().join("config.toml");
        must(
            fs::write(
                &config_path,
                format!("server = \"{}\"\ntoken = \"scrim_tok\"\n", server.url()),
            ),
            "write config.toml",
        );

        let out = run_bin(scrim_bin(), &["whoami"], tmp.path(), &config_path, None);
        assert!(!out.status.success(), "expected failure for HTTP {status}");
        let err_out = stderr_str(&out);
        assert!(
            err_out.contains(expected_msg),
            "expected '{expected_msg}' in stderr for HTTP {status}, got: {err_out}"
        );
    }
}

#[test]
fn does_not_follow_redirects_and_validates_init_inputs() {
    // 1. A 302 redirect must fail without following Location with the bearer token.
    let listener = must(TcpListener::bind("127.0.0.1:0"), "bind redirect listener");
    let addr = must(listener.local_addr(), "read redirect listener addr");
    let redirect_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_path = tmp.path().join("config.toml");
    must(
        fs::write(
            &config_path,
            format!("server = \"http://{addr}\"\ntoken = \"scrim_tok\"\n"),
        ),
        "write config.toml",
    );

    let out = run_bin(scrim_bin(), &["whoami"], tmp.path(), &config_path, None);
    assert!(!out.status.success(), "302 redirect must not succeed");
    assert!(stderr_str(&out).contains("302"));
    let _ = redirect_handle.join();

    // 2. Reject leading '-' remote names before contacting the server, and do
    //    not append `.git.git` when the working directory already ends with `.git`.
    let server = MockServer::start(|req| match (req.method.as_str(), req.target.as_str()) {
        ("POST", "/api/v1/repositories") => {
            let parsed: serde_json::Value =
                must(serde_json::from_str(&req.body), "parse init body");
            let path = must_some(parsed["path"].as_str(), "repo path");
            (
                201,
                format!(r#"{{"id":1,"path":"{path}","created":true,"bare_initialized":true}}"#),
            )
        }
        _ => (404, r#"{"error":"not found"}"#.to_owned()),
    });
    must(
        fs::write(
            &config_path,
            format!("server = \"{}\"\ntoken = \"scrim_tok\"\n", server.url()),
        ),
        "write config.toml",
    );

    let dot_git_dir = init_temp_git_repo(tmp.path(), "service.git");
    let bad_remote = run_bin(
        scrim_bin(),
        &["init", "--remote=-mirror"],
        &dot_git_dir,
        &config_path,
        None,
    );
    assert!(!bad_remote.status.success());
    assert!(server.take_requests().is_empty());

    let ok_init = run_bin(scrim_bin(), &["init"], &dot_git_dir, &config_path, None);
    assert!(ok_init.status.success(), "{}", stderr_str(&ok_init));
    assert_eq!(
        git_stdout(&dot_git_dir, &["config", "--local", "--get", "scrim.repo"]).as_deref(),
        Some("service.git")
    );
}
