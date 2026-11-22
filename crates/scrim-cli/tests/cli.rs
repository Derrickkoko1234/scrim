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
    run_bin_with_env(bin, args, cwd, config_path, &[], stdin_data)
}

fn run_bin_with_env(
    bin: &str,
    args: &[&str],
    cwd: &Path,
    config_path: &Path,
    extra_env: &[(&str, &str)],
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
        .env_remove("SCRIM_KEY")
        .env_remove("SCRIM_KEY_FILE")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

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

#[test]
fn keygen_local_only_permissions_force_and_server_upload() {
    let uploaded_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let uploaded_key_srv = Arc::clone(&uploaded_key);

    let server = MockServer::start(
        move |req| match (req.method.as_str(), req.target.as_str()) {
            ("PUT", "/api/v1/me/public-key") => {
                let parsed: serde_json::Value =
                    must(serde_json::from_str(&req.body), "parse public-key body");
                let pk = must_some(parsed["public_key"].as_str(), "public_key").to_owned();
                {
                    let mut guard = match uploaded_key_srv.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    *guard = Some(pk.clone());
                }
                (200, format!(r#"{{"name":"alice","public_key":"{pk}"}}"#))
            }
            ("GET", "/api/v1/whoami") => {
                let guard = match uploaded_key_srv.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let pk_json = match guard.as_deref() {
                    Some(pk) => format!(r#""{pk}""#),
                    None => "null".to_owned(),
                };
                (
                    200,
                    format!(
                        r#"{{"id":1,"name":"alice","is_admin":false,"groups":["core"],"public_key":{pk_json}}}"#
                    ),
                )
            }
            _ => (404, r#"{"error":"not found"}"#.to_owned()),
        },
    );

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_dir = tmp.path().join("cfg");
    let config_path = config_dir.join("config.toml");
    let identity_path = config_dir.join("identity.age");

    // 1. Online keygen without login fails cleanly before generating a key file.
    let no_auth = run_bin(scrim_bin(), &["keygen"], tmp.path(), &config_path, None);
    assert!(!no_auth.status.success());
    assert!(!identity_path.exists());

    // 2. Local-only keygen generates 0600 key file without contacting any server.
    let local_out = run_bin(
        scrim_bin(),
        &["keygen", "--local-only"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(
        local_out.status.success(),
        "local keygen failed: {}",
        stderr_str(&local_out)
    );
    let local_stdout = stdout_str(&local_out);
    assert!(local_stdout.contains("Public key: age1"));
    assert!(!local_stdout.contains("AGE-SECRET-KEY-1"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = must(fs::metadata(&identity_path), "stat identity.age");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    let first_key = must(fs::read_to_string(&identity_path), "read identity.age");
    assert!(first_key.trim().starts_with("AGE-SECRET-KEY-1"));

    // 3. Refuses overwrite without --force.
    let refuse_out = run_bin(
        scrim_bin(),
        &["keygen", "--local-only"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(!refuse_out.status.success());
    assert!(stderr_str(&refuse_out).contains("--force"));
    assert_eq!(
        must(fs::read_to_string(&identity_path), "re-read identity.age"),
        first_key
    );

    // 4. Online keygen --force saves new key and uploads its public key.
    must(
        fs::write(
            &config_path,
            format!("server = \"{}\"\ntoken = \"scrim_tok\"\n", server.url()),
        ),
        "write config.toml",
    );
    let online_out = run_bin(
        scrim_bin(),
        &["keygen", "--force"],
        tmp.path(),
        &config_path,
        None,
    );
    assert!(
        online_out.status.success(),
        "online keygen failed: {}",
        stderr_str(&online_out)
    );
    let second_key = must(fs::read_to_string(&identity_path), "read overwritten key");
    assert_ne!(first_key, second_key);

    let whoami_out = run_bin(scrim_bin(), &["whoami"], tmp.path(), &config_path, None);
    assert!(whoami_out.status.success(), "{}", stderr_str(&whoami_out));
    let guard = match uploaded_key.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let expected_pk = must_some(guard.as_deref(), "uploaded public key");
    assert!(stdout_str(&whoami_out).contains(&format!("Public key: {expected_pk}")));
}

#[test]
fn offline_secrets_roundtrip_run_exit_codes_and_scrim_key_env() {
    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_dir = tmp.path().join("cfg");
    let config_path = config_dir.join("config.toml");
    let identity_path = config_dir.join("identity.age");
    let repo_dir = init_temp_git_repo(tmp.path(), "secrets-app");

    // Generate offline keypair.
    let kg = run_bin(
        scrim_bin(),
        &["keygen", "--local-only"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(kg.status.success(), "{}", stderr_str(&kg));

    // Set KEY=VALUE containing `=` offline.
    let set1 = run_bin(
        scrim_bin(),
        &[
            "secrets",
            "set",
            "DATABASE_URL=postgres://user:a=b@localhost/app",
            "--scope",
            "dev",
            "--offline",
        ],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(set1.status.success(), "{}", stderr_str(&set1));
    assert!(!stdout_str(&set1).contains("postgres://"));
    assert!(repo_dir.join(".scrim/keys/dev.toml").exists());
    assert!(repo_dir.join(".scrim/secrets/dev.enc").exists());

    // Set via --value-stdin (scope already exists -> completely offline even without --offline).
    let set2 = run_bin(
        scrim_bin(),
        &[
            "secrets",
            "set",
            "API_TOKEN",
            "--scope",
            "dev",
            "--value-stdin",
        ],
        &repo_dir,
        &config_path,
        Some("tok_with_spaces hello\r\n"),
    );
    assert!(set2.status.success(), "{}", stderr_str(&set2));

    // Get, list, export.
    let get1 = run_bin(
        scrim_bin(),
        &["secrets", "get", "DATABASE_URL", "--scope", "dev"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(get1.status.success(), "{}", stderr_str(&get1));
    assert_eq!(stdout_str(&get1), "postgres://user:a=b@localhost/app\n");

    let list_out = run_bin(
        scrim_bin(),
        &["secrets", "list", "--scope", "dev"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(list_out.status.success(), "{}", stderr_str(&list_out));
    assert_eq!(stdout_str(&list_out), "API_TOKEN\nDATABASE_URL\n");

    let export_out = run_bin(
        scrim_bin(),
        &["secrets", "export", "--scope", "dev", "--format", "dotenv"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(export_out.status.success(), "{}", stderr_str(&export_out));
    assert_eq!(
        stdout_str(&export_out),
        "API_TOKEN=\"tok_with_spaces hello\"\nDATABASE_URL=postgres://user:a=b@localhost/app\n"
    );

    // `scrim run` injects env vars and propagates non-zero exit code cleanly without error banner.
    let run_ok = run_bin(
        scrim_bin(),
        &[
            "run",
            "--scope",
            "dev",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$DATABASE_URL\" \"$API_TOKEN\"",
        ],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(run_ok.status.success(), "{}", stderr_str(&run_ok));
    assert_eq!(
        stdout_str(&run_ok),
        "postgres://user:a=b@localhost/app|tok_with_spaces hello"
    );

    let run_exit = run_bin(
        scrim_bin(),
        &["run", "--scope", "dev", "--", "sh", "-c", "exit 42"],
        &repo_dir,
        &config_path,
        None,
    );
    assert_eq!(run_exit.status.code(), Some(42));
    assert!(
        stderr_str(&run_exit).is_empty(),
        "unexpected stderr on child non-zero exit: {}",
        stderr_str(&run_exit)
    );

    // Remove a key and confirm it is gone.
    let rm_out = run_bin(
        scrim_bin(),
        &["secrets", "rm", "API_TOKEN", "--scope", "dev"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(rm_out.status.success(), "{}", stderr_str(&rm_out));
    let get_missing = run_bin(
        scrim_bin(),
        &["secrets", "get", "API_TOKEN", "--scope", "dev"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(!get_missing.status.success());

    // Delete key file from disk and decrypt solely via SCRIM_KEY env var!
    let secret_key = must(fs::read_to_string(&identity_path), "read identity.age");
    must(fs::remove_file(&identity_path), "remove identity.age");

    let run_ci = run_bin_with_env(
        scrim_bin(),
        &[
            "run",
            "--scope",
            "dev",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$DATABASE_URL\"",
        ],
        &repo_dir,
        &config_path,
        &[("SCRIM_KEY", secret_key.trim())],
        None,
    );
    assert!(run_ci.status.success(), "{}", stderr_str(&run_ci));
    assert_eq!(stdout_str(&run_ci), "postgres://user:a=b@localhost/app");

    // Also works in a bare CI container with ONLY PATH + SCRIM_KEY (no HOME or SCRIM_CONFIG).
    let mut bare_cmd = Command::new(scrim_bin());
    bare_cmd
        .args([
            "run",
            "--scope",
            "dev",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$DATABASE_URL\"",
        ])
        .current_dir(&repo_dir)
        .env_clear()
        .env("SCRIM_KEY", secret_key.trim());
    if let Ok(path_val) = std::env::var("PATH") {
        bare_cmd.env("PATH", path_val);
    }
    let bare_ci = must(bare_cmd.output(), "run bare CI scrim run");
    assert!(bare_ci.status.success(), "{}", stderr_str(&bare_ci));
    assert_eq!(stdout_str(&bare_ci), "postgres://user:a=b@localhost/app");
}

#[test]
fn secret_scopes_set_key_machine_grant_sync_and_revoke_rotation() {
    use scrim_crypto::MemberIdentity;

    let alice_id = MemberIdentity::generate();
    let alice_pk = alice_id.public_key().as_str().to_owned();
    let bob_id = MemberIdentity::generate();
    let bob_pk = bob_id.public_key().as_str().to_owned();

    let bob_active = Arc::new(AtomicBool::new(true));
    let bob_active_srv = Arc::clone(&bob_active);

    let alice_pk_srv = alice_pk.clone();
    let bob_pk_srv = bob_pk.clone();

    let server = MockServer::start(
        move |req| match (req.method.as_str(), req.target.as_str()) {
            ("PUT", "/api/v1/secret-scopes") => {
                let parsed: serde_json::Value =
                    must(serde_json::from_str(&req.body), "parse put secret-scope");
                assert_eq!(parsed["repository"], serde_json::json!("org/app.git"));
                assert_eq!(parsed["scope"], serde_json::json!("prod"));
                assert_eq!(parsed["groups"], serde_json::json!(["core"]));
                (
                    200,
                    r#"{"repository":"org/app.git","scope":"prod","groups":["core"]}"#.to_owned(),
                )
            }
            ("GET", "/api/v1/secret-scopes?repo=org%2Fapp.git") => (
                200,
                r#"{"repository":"org/app.git","scopes":[{"scope":"prod","groups":["core"]}]}"#
                    .to_owned(),
            ),
            ("DELETE", "/api/v1/secret-scopes?repo=org%2Fapp.git&scope=prod") => (
                200,
                r#"{"repository":"org/app.git","scope":"prod","removed":true}"#.to_owned(),
            ),
            ("PUT", "/api/v1/members/bob/public-key") => {
                let parsed: serde_json::Value =
                    must(serde_json::from_str(&req.body), "parse set-key");
                let pk = must_some(parsed["public_key"].as_str(), "public_key");
                (200, format!(r#"{{"name":"bob","public_key":"{pk}"}}"#))
            }
            ("POST", "/api/v1/members") => {
                let parsed: serde_json::Value =
                    must(serde_json::from_str(&req.body), "parse create-member");
                let pk = must_some(parsed["public_key"].as_str(), "public_key in create-member");
                assert!(
                    pk.starts_with("age1"),
                    "expected machine public_key in body"
                );
                (
                    201,
                    format!(
                        r#"{{"member":{{"id":5,"name":"ci-runner","is_admin":false,"is_machine":true,"public_key":"{pk}","groups":["core"],"revoked":false}},"token":"scrim_ci_tok"}}"#
                    ),
                )
            }
            ("GET", "/api/v1/secret-scopes/recipients?repo=org%2Fapp.git&scope=prod") => {
                if bob_active_srv.load(Ordering::Relaxed) {
                    (
                        200,
                        format!(
                            r#"{{"repository":"org/app.git","scope":"prod","groups":["core"],"recipients":[{{"member":"alice","public_key":"{alice_pk_srv}"}},{{"member":"bob","public_key":"{bob_pk_srv}"}}],"members_without_key":["carol"]}}"#
                        ),
                    )
                } else {
                    (
                        200,
                        format!(
                            r#"{{"repository":"org/app.git","scope":"prod","groups":["core"],"recipients":[{{"member":"alice","public_key":"{alice_pk_srv}"}}],"members_without_key":[]}}"#
                        ),
                    )
                }
            }
            ("DELETE", "/api/v1/members/bob") => {
                bob_active_srv.store(false, Ordering::Relaxed);
                (200, r#"{"name":"bob","revoked":true}"#.to_owned())
            }
            _ => (
                404,
                format!(r#"{{"error":"unexpected {} {}"}}"#, req.method, req.target),
            ),
        },
    );

    let tmp = must(tempfile::tempdir(), "create tempdir");
    let config_dir = tmp.path().join("cfg");
    let config_path = config_dir.join("config.toml");
    must(fs::create_dir_all(&config_dir), "create cfg dir");
    must(
        fs::write(
            &config_path,
            format!("server = \"{}\"\ntoken = \"scrim_admin\"\n", server.url()),
        ),
        "write config.toml",
    );

    let alice_key_file = config_dir.join("identity.age");
    must(
        fs::write(
            &alice_key_file,
            format!("{}\n", {
                use scrim_crypto::ExposeSecret;
                alice_id.to_secret_string().expose_secret().to_owned()
            }),
        ),
        "write alice identity.age",
    );

    let repo_dir = init_temp_git_repo(tmp.path(), "prod-repo");
    let set_repo = must(
        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["config", "--local", "scrim.repo", "org/app.git"])
            .output(),
        "set scrim.repo",
    );
    assert!(set_repo.status.success());

    // 1. Secret scope management commands.
    let scope_set = run_bin(
        scrim_bin(),
        &["secrets", "scope", "set", "prod", "--group", "core"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(scope_set.status.success(), "{}", stderr_str(&scope_set));

    let scope_list = run_bin(
        scrim_bin(),
        &["secrets", "scope", "list"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(scope_list.status.success(), "{}", stderr_str(&scope_list));
    assert!(stdout_str(&scope_list).contains("prod: core"));

    let scope_rm = run_bin(
        scrim_bin(),
        &["secrets", "scope", "rm", "prod"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(scope_rm.status.success(), "{}", stderr_str(&scope_rm));

    // 2. Access set-key (rejects bad key locally) & machine grant (prints SCRIM_KEY once).
    let bad_set_key = run_bin(
        scrim_bin(),
        &["access", "set-key", "bob", "not-an-age-key"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(!bad_set_key.status.success());

    let ok_set_key = run_bin(
        scrim_bin(),
        &["access", "set-key", "bob", &bob_pk],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(ok_set_key.status.success(), "{}", stderr_str(&ok_set_key));

    let grant_machine = run_bin(
        scrim_bin(),
        &[
            "access",
            "grant",
            "ci-runner",
            "--machine",
            "--group",
            "core",
        ],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(
        grant_machine.status.success(),
        "{}",
        stderr_str(&grant_machine)
    );
    let grant_stdout = stdout_str(&grant_machine);
    assert!(grant_stdout.contains("Token (shown only once): scrim_ci_tok"));
    assert!(grant_stdout.contains("SCRIM_KEY (shown only once): AGE-SECRET-KEY-1"));

    // 3. Create scope `prod` online (wraps for alice and bob, warns about carol).
    let set_secret = run_bin(
        scrim_bin(),
        &[
            "secrets",
            "set",
            "STRIPE_KEY=sk_live_123",
            "--scope",
            "prod",
        ],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(set_secret.status.success(), "{}", stderr_str(&set_secret));
    assert!(stderr_str(&set_secret).contains("carol"));

    // Bob can decrypt generation 1 via SCRIM_KEY.
    let bob_secret_str = {
        use scrim_crypto::ExposeSecret;
        bob_id.to_secret_string().expose_secret().to_owned()
    };
    let bob_get1 = run_bin_with_env(
        scrim_bin(),
        &["secrets", "get", "STRIPE_KEY", "--scope", "prod"],
        &repo_dir,
        &config_path,
        &[("SCRIM_KEY", &bob_secret_str)],
        None,
    );
    assert!(bob_get1.status.success(), "{}", stderr_str(&bob_get1));
    assert_eq!(stdout_str(&bob_get1), "sk_live_123\n");

    // 4. `scrim secrets sync` rotates generation 1 -> 2 when bob is removed on server.
    bob_active.store(false, Ordering::Relaxed);
    let sync_out = run_bin(
        scrim_bin(),
        &["secrets", "sync", "--scope", "prod"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(sync_out.status.success(), "{}", stderr_str(&sync_out));
    let sync_stdout = stdout_str(&sync_out);
    assert!(sync_stdout.contains("generation 2"));
    assert!(sync_stdout.contains("Secrets to rotate at their source:"));
    assert!(sync_stdout.contains("STRIPE_KEY"));

    // Bob can no longer decrypt generation 2.
    let bob_get2 = run_bin_with_env(
        scrim_bin(),
        &["secrets", "get", "STRIPE_KEY", "--scope", "prod"],
        &repo_dir,
        &config_path,
        &[("SCRIM_KEY", &bob_secret_str)],
        None,
    );
    assert!(!bob_get2.status.success());

    // 5. Re-add bob via offline keys file or re-enable bob, set another secret, and test `scrim access revoke bob` rotation!
    bob_active.store(true, Ordering::Relaxed);
    let sync_back = run_bin(
        scrim_bin(),
        &["secrets", "sync", "--scope", "prod"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(sync_back.status.success(), "{}", stderr_str(&sync_back));

    let revoke_out = run_bin(
        scrim_bin(),
        &["access", "revoke", "bob"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(revoke_out.status.success(), "{}", stderr_str(&revoke_out));
    let revoke_stdout = stdout_str(&revoke_out);
    assert!(revoke_stdout.contains("Revoked access for bob"));
    assert!(revoke_stdout.contains("Rotated scope 'prod' to generation 4"));
    assert!(revoke_stdout.contains("Secrets to rotate at their source:"));
    assert!(revoke_stdout.contains("STRIPE_KEY"));
    assert!(revoke_stdout.contains("Remember to commit and push the updated .scrim/ files."));

    // Bob cannot decrypt generation 4, Alice still can.
    let bob_get4 = run_bin_with_env(
        scrim_bin(),
        &["secrets", "get", "STRIPE_KEY", "--scope", "prod"],
        &repo_dir,
        &config_path,
        &[("SCRIM_KEY", &bob_secret_str)],
        None,
    );
    assert!(!bob_get4.status.success());

    let alice_get4 = run_bin(
        scrim_bin(),
        &["secrets", "get", "STRIPE_KEY", "--scope", "prod"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(alice_get4.status.success(), "{}", stderr_str(&alice_get4));
    assert_eq!(stdout_str(&alice_get4), "sk_live_123\n");

    // 6. Test --no-rotate and missing identity warning during revoke.
    bob_active.store(true, Ordering::Relaxed);
    let sync_5 = run_bin(
        scrim_bin(),
        &["secrets", "sync", "--scope", "prod"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(sync_5.status.success(), "{}", stderr_str(&sync_5));

    let revoke_no_rotate = run_bin(
        scrim_bin(),
        &["access", "revoke", "bob", "--no-rotate"],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(
        revoke_no_rotate.status.success(),
        "{}",
        stderr_str(&revoke_no_rotate)
    );
    assert!(!stdout_str(&revoke_no_rotate).contains("Rotated scope"));

    // Bob can still decrypt generation 5 because --no-rotate skipped rotation.
    let bob_get5 = run_bin_with_env(
        scrim_bin(),
        &["secrets", "get", "STRIPE_KEY", "--scope", "prod"],
        &repo_dir,
        &config_path,
        &[("SCRIM_KEY", &bob_secret_str)],
        None,
    );
    assert!(bob_get5.status.success(), "{}", stderr_str(&bob_get5));

    // Revoking without a local identity warns without failing the server revocation.
    let missing_key_path = config_dir.join("missing.age");
    let revoke_missing_key = run_bin(
        scrim_bin(),
        &[
            "--key-file",
            &missing_key_path.to_string_lossy(),
            "access",
            "revoke",
            "bob",
        ],
        &repo_dir,
        &config_path,
        None,
    );
    assert!(
        revoke_missing_key.status.success(),
        "revoke should still succeed when local key is missing: {}",
        stderr_str(&revoke_missing_key)
    );
    assert!(stderr_str(&revoke_missing_key).contains("scrim secrets sync"));
}
