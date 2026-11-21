//! Helpers shared by the integration tests: an isolated git environment and a
//! server running on an ephemeral port.

#![allow(dead_code)] // Each test binary uses a different subset.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

/// Runs real `git` commands with no access to the developer's own config.
pub struct GitSandbox {
    home: TempDir,
}

impl GitSandbox {
    pub fn new() -> Self {
        let home = match TempDir::new() {
            Ok(home) => home,
            Err(error) => panic!("failed to create git sandbox home: {error}"),
        };
        Self { home }
    }

    /// Runs `git <args>` in `dir`, panicking with git's output on failure.
    pub fn git(&self, dir: &Path, args: &[&str]) -> Output {
        self.git_with_env(dir, args, &[])
    }

    /// Like [`GitSandbox::git`] with extra environment variables.
    pub fn git_with_env(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let path = match std::env::var_os("PATH") {
            Some(path) => path,
            None => panic!("PATH is not set"),
        };
        let output = match Command::new("git")
            .args([
                "-c",
                "user.name=Scrim Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .envs(extra_env.iter().copied())
            .output()
        {
            Ok(output) => output,
            Err(error) => panic!("failed to run git {args:?}: {error}"),
        };
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Creates an empty bare repository whose HEAD is `refs/heads/main`.
    pub fn init_bare(&self, path: &Path) {
        if let Err(error) = std::fs::create_dir_all(path) {
            panic!(
                "failed to create repository directory {}: {error}",
                path.display()
            );
        }
        self.git(path, &["init", "--bare", "--initial-branch=main"]);
    }

    /// Creates a bare repository at `path` with one commit on `refs/heads/main`.
    pub fn init_bare_with_commit(&self, path: &Path) {
        self.init_bare(path);
        let work = match TempDir::new() {
            Ok(work) => work,
            Err(error) => panic!("failed to create work temp dir: {error}"),
        };
        self.git(work.path(), &["init", "--initial-branch=main"]);
        if let Err(error) = std::fs::write(work.path().join("hello.txt"), "hello\n") {
            panic!("failed to write hello.txt: {error}");
        }
        self.git(work.path(), &["add", "hello.txt"]);
        self.git(work.path(), &["commit", "-m", "first"]);
        let path = match path.to_str() {
            Some(path) => path,
            None => panic!("repository path is not valid UTF-8: {}", path.display()),
        };
        self.git(work.path(), &["push", path, "HEAD:refs/heads/main"]);
    }
}

/// Starts the server on an ephemeral loopback port and returns its base URL.
pub async fn spawn_server(repo_root: PathBuf) -> String {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => panic!("failed to bind server listener: {error}"),
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => panic!("failed to read server address: {error}"),
    };
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, scrim_server::router(repo_root)).await {
            panic!("server failed: {error}");
        }
    });
    format!("http://{address}")
}
