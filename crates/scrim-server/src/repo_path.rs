//! Maps the repository part of a request path to a bare repository directory.
//!
//! This is the trust boundary for filesystem access: nothing outside the
//! configured repository root may ever be handed to `git`.

use std::{
    io,
    path::{Path, PathBuf},
};

use tokio::io::AsyncReadExt;

/// Maximum bytes read from `HEAD` when verifying a bare repository layout.
const MAX_HEAD_BYTES: usize = 256;

/// Returns whether `repo` is one or more `/`-separated segments that are safe
/// to join onto the repository root.
///
/// A segment may contain only ASCII letters, digits, `.`, `_` and `-`, and may
/// not start with `.`. That rules out `.`, `..`, hidden directories, empty
/// segments (`a//b`) and `%` (so percent-encoded traversal such as `%2e%2e`
/// never reaches the filesystem; the raw, undecoded path is validated).
pub fn is_valid_repo_path(repo: &str) -> bool {
    repo.split('/').all(|segment| {
        !segment.is_empty()
            && !segment.starts_with('.')
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

/// Resolves `repo` (relative to `repo_root`) to the canonical directory of an
/// existing bare repository.
///
/// Returns `None` for an invalid path, a missing directory, a directory that
/// equals `repo_root`, a directory that does not look like a self-contained bare
/// repository (no `.git` entry; non-symlink `HEAD` file with valid ref or OID,
/// `objects` directory, and `refs` directory), or one that resolves outside the
/// root. Callers must not tell these cases apart to the client.
pub async fn resolve_bare_repo(repo_root: &Path, repo: &str) -> Option<PathBuf> {
    if !is_valid_repo_path(repo) {
        return None;
    }

    // Canonicalize both sides so a symlink inside the root pointing elsewhere
    // is rejected, and so the root itself may be reached through a symlink.
    let Ok(canonical_root) = tokio::fs::canonicalize(repo_root).await else {
        return None;
    };
    let Ok(canonical_repo) = tokio::fs::canonicalize(canonical_root.join(repo)).await else {
        return None;
    };
    if !canonical_repo.starts_with(&canonical_root) || canonical_repo == canonical_root {
        return None;
    }

    // Reject `<repo>/.git` in any form (file, symlink, or directory) so git's
    // `enter_repo` cannot follow a `gitdir:` file or nested `.git`, and reject
    // `<repo>/commondir`, which git follows to use another repository's
    // objects and refs.
    for redirect in [".git", "commondir"] {
        match tokio::fs::symlink_metadata(canonical_repo.join(redirect)).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return None,
        }
    }

    // Use `symlink_metadata` (no symlink following) so every required entry is
    // real and local to the repository directory.
    let head_path = canonical_repo.join("HEAD");
    let has_head_file = tokio::fs::symlink_metadata(&head_path)
        .await
        .is_ok_and(|metadata| metadata.is_file());
    let has_objects_dir = tokio::fs::symlink_metadata(canonical_repo.join("objects"))
        .await
        .is_ok_and(|metadata| metadata.is_dir());
    let has_refs_dir = tokio::fs::symlink_metadata(canonical_repo.join("refs"))
        .await
        .is_ok_and(|metadata| metadata.is_dir());
    if !has_head_file || !has_objects_dir || !has_refs_dir {
        return None;
    }

    // git also requires `objects` and `refs` to be searchable (`access(X_OK)`);
    // otherwise receive-pack, which has no `--strict`, falls back to
    // `<dir>.git`. Looking up `<dir>/.` needs search permission on `<dir>`.
    for directory in ["objects", "refs"] {
        if tokio::fs::metadata(canonical_repo.join(directory).join("."))
            .await
            .is_err()
        {
            return None;
        }
    }

    if !has_valid_head(&head_path).await {
        return None;
    }

    Some(canonical_repo)
}

async fn has_valid_head(head_path: &Path) -> bool {
    let Ok(file) = tokio::fs::File::open(head_path).await else {
        return false;
    };
    let mut bytes = Vec::new();
    let mut limited = file.take((MAX_HEAD_BYTES + 1) as u64);
    if limited.read_to_end(&mut bytes).await.is_err() {
        return false;
    }
    bytes.len() <= MAX_HEAD_BYTES && is_valid_head(&bytes)
}

/// Checks that `HEAD` contents match what git accepts as a bare repository
/// `HEAD`, preventing git from rejecting the directory and falling back to
/// `<dir>.git`.
fn is_valid_head(bytes: &[u8]) -> bool {
    let Some(line) = bytes.strip_suffix(b"\n") else {
        return false;
    };
    if let Some(ref_target) = line.strip_prefix(b"ref: refs/") {
        return !ref_target.is_empty()
            && ref_target.iter().all(|&byte| byte > 0x20 && byte != 0x7f);
    }
    (line.len() == 40 || line.len() == 64)
        && line
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::{is_valid_head, is_valid_repo_path};

    #[test]
    fn accepts_plain_nested_names() {
        assert!(is_valid_repo_path("test.git"));
        assert!(is_valid_repo_path("team/my-repo_2.git"));
    }

    #[test]
    fn rejects_unsafe_paths() {
        for repo in [
            "",
            ".",
            "..",
            "../x",
            "a/../b",
            ".git",
            "a/.hidden",
            "a//b",
            "a/",
            "/a",
            "%2e%2e",
            "a%2fb",
            "a b",
            "a\\b",
            "caf\u{e9}",
        ] {
            assert!(!is_valid_repo_path(repo), "{repo:?} should be rejected");
        }
    }

    #[test]
    fn validates_head_contents() {
        assert!(is_valid_head(b"ref: refs/heads/main\n"));
        assert!(is_valid_head(b"0123456789abcdef0123456789abcdef01234567\n"));
        assert!(is_valid_head(
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        ));

        for invalid in [
            b"" as &[u8],
            b"ref: refs/heads/main",
            b"ref: refs/\n",
            b"ref: heads/main\n",
            b"ref: refs/heads/main\nextra\n",
            b"0123456789ABCDEF0123456789abcdef01234567\n",
            b"0123456789abcdef\n",
            b"not-a-head\n",
        ] {
            assert!(!is_valid_head(invalid), "{invalid:?} should be rejected");
        }
    }
}
