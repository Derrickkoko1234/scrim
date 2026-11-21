//! Maps the repository part of a request path to a bare repository directory.
//!
//! This is the trust boundary for filesystem access: nothing outside the
//! configured repository root may ever be handed to `git`.

use std::{
    io,
    path::{Component, Path, PathBuf},
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

/// What a bare repository's `HEAD` file points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoHead {
    /// `HEAD` is a symbolic ref to this full ref name, e.g. `refs/heads/main`.
    Symbolic(String),
    /// `HEAD` holds a commit ID directly (a detached `HEAD`).
    Detached,
}

/// A bare repository located under the repository root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRepo {
    /// Canonical (symlink-free) directory of the bare repository.
    pub dir: PathBuf,
    /// `/`-separated path of [`ResolvedRepo::dir`] relative to the canonical
    /// repository root, e.g. `team/app.git`.
    ///
    /// This, not the path the client requested, is the key to look up
    /// repository policy by: an intra-root symlink such as
    /// `alias.git -> secret.git` resolves to the key `secret.git`, so it cannot
    /// be used to dodge rules attached to `secret.git`.
    pub canonical_key: String,
}

/// Resolves `repo` (relative to `repo_root`) to the canonical directory and
/// policy key of an existing bare repository.
///
/// Returns `None` for an invalid path, a missing directory, a directory that
/// equals `repo_root`, a directory that does not look like a self-contained bare
/// repository (no `.git`, `commondir`, `reftable`, `objects/info/alternates`
/// or `objects/info/http-alternates` entry; non-symlink `HEAD` file with valid
/// ref or OID, `objects` directory, and `refs` directory), one that resolves
/// outside the root, or one whose canonical path is not itself a valid
/// repository path. Callers must not tell these cases apart to the client.
///
/// `HEAD` is only validated here; callers that act on its target re-read it
/// with [`read_valid_head`] as late as possible, since it can change.
pub async fn resolve_bare_repo(repo_root: &Path, repo: &str) -> Option<ResolvedRepo> {
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
    let Some(canonical_key) = canonical_repo_key(&canonical_root, &canonical_repo) else {
        return None;
    };

    // Reject, in any form (file, symlink, or directory):
    // - `.git`, so git's `enter_repo` cannot follow a `gitdir:` file or a
    //   nested `.git`;
    // - `commondir`, which git follows to use another repository's objects
    //   and refs;
    // - `reftable`, whose refs this server does not vet (its `HEAD` file is a
    //   `refs/heads/.invalid` placeholder, not the real `HEAD`);
    // - object alternates, which would let another store's objects be fetched
    //   or advertised as `.have` tips, bypassing per-repository isolation.
    for redirect in [
        ".git",
        "commondir",
        "reftable",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
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

    if read_valid_head(&head_path).await.is_none() {
        return None;
    }

    Some(ResolvedRepo {
        dir: canonical_repo,
        canonical_key,
    })
}

/// Derives the policy key of `canonical_repo` from its path relative to
/// `canonical_root`, joined with `/` regardless of platform.
///
/// Returns `None` if the relative path contains anything but plain segments,
/// is not UTF-8, or fails [`is_valid_repo_path`]: a symlink target may have a
/// name a client could never request directly, and such a repository must not
/// be served under a key policy rules cannot express.
fn canonical_repo_key(canonical_root: &Path, canonical_repo: &Path) -> Option<String> {
    let Ok(relative_path) = canonical_repo.strip_prefix(canonical_root) else {
        return None;
    };
    let mut segments = Vec::new();
    for component in relative_path.components() {
        let Component::Normal(segment) = component else {
            return None;
        };
        let Some(segment) = segment.to_str() else {
            return None;
        };
        segments.push(segment);
    }
    let canonical_key = segments.join("/");
    is_valid_repo_path(&canonical_key).then_some(canonical_key)
}

/// Reads `HEAD` (at most [`MAX_HEAD_BYTES`]) and parses it with
/// [`parse_head`]; `None` if it cannot be read, is too long, or is invalid.
pub(crate) async fn read_valid_head(head_path: &Path) -> Option<RepoHead> {
    let Ok(file) = tokio::fs::File::open(head_path).await else {
        return None;
    };
    let mut bytes = Vec::new();
    let mut limited = file.take((MAX_HEAD_BYTES + 1) as u64);
    if limited.read_to_end(&mut bytes).await.is_err() {
        return None;
    }
    if bytes.len() > MAX_HEAD_BYTES {
        return None;
    }
    parse_head(&bytes)
}

/// Parses `HEAD` contents, accepting only what git accepts as a bare
/// repository `HEAD` so git never rejects the directory and falls back to
/// `<dir>.git`: `ref: refs/<name>\n` (printable, non-space bytes, no path
/// segment starting with `.`) or a 40/64 character lowercase hex object ID
/// followed by `\n`.
fn parse_head(bytes: &[u8]) -> Option<RepoHead> {
    let Some(line) = bytes.strip_suffix(b"\n") else {
        return None;
    };
    if let Some(ref_target) = line.strip_prefix(b"ref: refs/") {
        let is_valid_target =
            !ref_target.is_empty() && ref_target.iter().all(|&byte| byte > 0x20 && byte != 0x7f);
        if !is_valid_target {
            return None;
        }
        // Bytes above 0x7f may still be invalid UTF-8; such a ref name could
        // never be matched by a policy rule, so it is rejected outright.
        let Ok(ref_name) = std::str::from_utf8(&line[b"ref: ".len()..]) else {
            return None;
        };
        // Git never names a real ref with a `.`-prefixed segment; reftable
        // repositories write `refs/heads/.invalid` here as a placeholder.
        if ref_name.split('/').any(|segment| segment.starts_with('.')) {
            return None;
        }
        return Some(RepoHead::Symbolic(ref_name.to_owned()));
    }
    let is_object_id = (line.len() == 40 || line.len() == 64)
        && line
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    is_object_id.then_some(RepoHead::Detached)
}

/// Where [`locate_bare_repo`] found (or would create) a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BareRepoLocation {
    /// A valid bare repository already exists; this is its canonical key.
    Existing(String),
    /// Nothing exists at the path yet and every existing parent is a plain
    /// directory, so [`create_bare_repo`] may create it. The string is the
    /// canonical key with any existing parent directories resolved to their
    /// on-disk spelling (important on case-insensitive filesystems).
    Creatable(String),
}

/// Why a bare repository could not be located or created.
#[derive(Debug)]
pub enum BareRepoError {
    /// The path fails [`is_valid_repo_path`].
    InvalidPath,
    /// No bare repository exists and creating one was not requested.
    NotFound,
    /// Something other than a valid bare repository occupies the path, or a
    /// parent is a symlink or not a directory. The message is safe to show.
    Conflict(&'static str),
    /// A filesystem or git failure.
    Io(io::Error),
}

/// Finds the bare repository at `repo` under `repo_root`, or (with
/// `create_bare`) checks that [`create_bare_repo`] could create it there.
///
/// Fails with [`BareRepoError::NotFound`] when nothing valid exists and
/// `create_bare` is `false`, and with [`BareRepoError::Conflict`] when the path
/// is occupied by anything else (a plain directory, a file, a symlink, a broken
/// repository) or a parent is a symlink or not a directory: nothing is ever
/// clobbered, and new repositories are never created through a symlink.
pub async fn locate_bare_repo(
    repo_root: &Path,
    repo: &str,
    create_bare: bool,
) -> Result<BareRepoLocation, BareRepoError> {
    if !is_valid_repo_path(repo) {
        return Err(BareRepoError::InvalidPath);
    }
    if let Some(resolved) = resolve_bare_repo(repo_root, repo).await {
        return Ok(BareRepoLocation::Existing(resolved.canonical_key));
    }
    if !create_bare {
        return Err(BareRepoError::NotFound);
    }
    let canonical_root = match tokio::fs::canonicalize(repo_root).await {
        Ok(canonical_root) => canonical_root,
        Err(error) => return Err(BareRepoError::Io(error)),
    };
    let segments: Vec<&str> = repo.split('/').collect();
    let first_missing = match first_missing_segment(&canonical_root, &segments).await {
        Ok(first_missing) => first_missing,
        Err(error) => return Err(error),
    };
    let canonical_key =
        match canonical_creatable_key(&canonical_root, &segments, first_missing).await {
            Ok(key) => key,
            Err(error) => return Err(error),
        };
    Ok(BareRepoLocation::Creatable(canonical_key))
}

/// Builds the canonical key a new repository will have after creation, using
/// the on-disk spelling of any existing parent directories (`0..first_missing`)
/// so case-insensitive filesystems cannot register one spelling while Git
/// later looks up policy under another.
async fn canonical_creatable_key(
    canonical_root: &Path,
    segments: &[&str],
    first_missing: usize,
) -> Result<String, BareRepoError> {
    let mut key_parts = Vec::with_capacity(segments.len());
    if first_missing > 0 {
        let mut existing_parent = canonical_root.to_path_buf();
        for segment in &segments[..first_missing] {
            existing_parent.push(segment);
        }
        let canonical_parent = match tokio::fs::canonicalize(&existing_parent).await {
            Ok(path) => path,
            Err(error) => return Err(BareRepoError::Io(error)),
        };
        if !canonical_parent.starts_with(canonical_root) {
            return Err(BareRepoError::Conflict(
                "a parent of the repository path escapes the repository root",
            ));
        }
        let Some(parent_key) = canonical_repo_key(canonical_root, &canonical_parent) else {
            return Err(BareRepoError::InvalidPath);
        };
        key_parts.push(parent_key);
    }
    for segment in &segments[first_missing..] {
        key_parts.push((*segment).to_owned());
    }
    let combined = key_parts.join("/");
    if is_valid_repo_path(&combined) {
        Ok(combined)
    } else {
        Err(BareRepoError::InvalidPath)
    }
}

/// Creates a bare repository (`HEAD` -> `refs/heads/main`) at `repo` under
/// `repo_root` and returns its canonical key.
///
/// Missing parents are created one directory at a time; existing parents must
/// be plain directories (not symlinks), and the target must not exist (see
/// [`locate_bare_repo`]). `git init` runs without any system or user git
/// config. If anything fails after directories were created, they are removed
/// again.
pub async fn create_bare_repo(repo_root: &Path, repo: &str) -> Result<String, BareRepoError> {
    if !is_valid_repo_path(repo) {
        return Err(BareRepoError::InvalidPath);
    }
    let canonical_root = match tokio::fs::canonicalize(repo_root).await {
        Ok(canonical_root) => canonical_root,
        Err(error) => return Err(BareRepoError::Io(error)),
    };
    let segments: Vec<&str> = repo.split('/').collect();
    let first_missing = match first_missing_segment(&canonical_root, &segments).await {
        Ok(first_missing) => first_missing,
        Err(error) => return Err(error),
    };

    let mut path = canonical_root;
    let mut created_dirs = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        path.push(segment);
        if index < first_missing {
            continue;
        }
        // `create_dir`, unlike `create_dir_all`, fails if anything (including
        // a symlink planted since the check above) already has this name.
        match tokio::fs::create_dir(&path).await {
            Ok(()) => created_dirs.push(path.clone()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                remove_created_dirs(&created_dirs).await;
                return Err(BareRepoError::Conflict(
                    "the repository path was created concurrently",
                ));
            }
            Err(error) => {
                remove_created_dirs(&created_dirs).await;
                return Err(BareRepoError::Io(error));
            }
        }
    }

    if let Err(error) = crate::git_service::init_bare_repository(&path).await {
        remove_created_dirs(&created_dirs).await;
        return Err(BareRepoError::Io(error));
    }
    match resolve_bare_repo(repo_root, repo).await {
        Some(resolved) => Ok(resolved.canonical_key),
        None => {
            remove_created_dirs(&created_dirs).await;
            Err(BareRepoError::Io(io::Error::other(
                "the initialized repository failed verification",
            )))
        }
    }
}

/// Returns the index of the first segment of `segments` (joined onto
/// `canonical_root`) that does not exist, after checking that every existing
/// one before it is a real directory, not a symlink.
///
/// Fails with [`BareRepoError::Conflict`] if the final segment exists.
async fn first_missing_segment(
    canonical_root: &Path,
    segments: &[&str],
) -> Result<usize, BareRepoError> {
    let mut path = canonical_root.to_path_buf();
    for (index, segment) in segments.iter().enumerate() {
        path.push(segment);
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(index),
            Err(error) => return Err(BareRepoError::Io(error)),
        };
        if index + 1 == segments.len() {
            return Err(BareRepoError::Conflict(
                "the repository path already exists but is not a valid bare repository",
            ));
        }
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BareRepoError::Conflict(
                "a parent of the repository path is a symlink or not a directory",
            ));
        }
    }
    Err(BareRepoError::Conflict(
        "the repository path already exists but is not a valid bare repository",
    ))
}

/// Best-effort removal of directories [`create_bare_repo`] created, deepest
/// (the repository itself, with whatever `git init` wrote) first; a parent
/// is only removed while empty.
async fn remove_created_dirs(created_dirs: &[PathBuf]) {
    for (index, dir) in created_dirs.iter().enumerate().rev() {
        let result = if index + 1 == created_dirs.len() {
            tokio::fs::remove_dir_all(dir).await
        } else {
            tokio::fs::remove_dir(dir).await
        };
        if let Err(error) = result {
            tracing::warn!(%error, dir = %dir.display(), "cannot remove a partly created repository directory");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::{RepoHead, is_valid_repo_path, parse_head, read_valid_head, resolve_bare_repo};

    /// Creates the minimal bare repository layout `resolve_bare_repo` accepts.
    fn create_bare_repo_layout(repo_dir: &Path) {
        for directory in ["objects", "refs"] {
            if let Err(error) = std::fs::create_dir_all(repo_dir.join(directory)) {
                panic!("failed to create {directory} in {repo_dir:?}: {error}");
            }
        }
        if let Err(error) = std::fs::write(repo_dir.join("HEAD"), b"ref: refs/heads/main\n") {
            panic!("failed to write HEAD in {repo_dir:?}: {error}");
        }
    }

    fn create_temp_root() -> TempDir {
        match TempDir::new() {
            Ok(root) => root,
            Err(error) => panic!("failed to create repository root: {error}"),
        }
    }

    #[tokio::test]
    async fn canonical_key_is_the_path_relative_to_the_root() {
        let root = create_temp_root();
        create_bare_repo_layout(&root.path().join("team").join("app.git"));

        let Some(resolved) = resolve_bare_repo(root.path(), "team/app.git").await else {
            panic!("team/app.git should resolve");
        };
        assert_eq!(resolved.canonical_key, "team/app.git");
        assert_eq!(
            read_valid_head(&resolved.dir.join("HEAD")).await,
            Some(RepoHead::Symbolic("refs/heads/main".to_owned()))
        );
        let canonical_root = match std::fs::canonicalize(root.path()) {
            Ok(path) => path,
            Err(error) => panic!("failed to canonicalize root: {error}"),
        };
        assert_eq!(resolved.dir, canonical_root.join("team").join("app.git"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn intra_root_symlink_resolves_to_the_target_key() {
        let root = create_temp_root();
        create_bare_repo_layout(&root.path().join("secret.git"));
        if let Err(error) = std::os::unix::fs::symlink("secret.git", root.path().join("alias.git"))
        {
            panic!("failed to create alias symlink: {error}");
        }

        let Some(resolved) = resolve_bare_repo(root.path(), "alias.git").await else {
            panic!("alias.git should resolve to secret.git");
        };
        assert_eq!(resolved.canonical_key, "secret.git");
        assert!(resolved.dir.ends_with("secret.git"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_to_a_name_clients_cannot_request_is_rejected() {
        let root = create_temp_root();
        create_bare_repo_layout(&root.path().join("has space.git"));
        if let Err(error) =
            std::os::unix::fs::symlink("has space.git", root.path().join("alias.git"))
        {
            panic!("failed to create alias symlink: {error}");
        }

        assert!(resolve_bare_repo(root.path(), "alias.git").await.is_none());
    }

    #[tokio::test]
    async fn repos_with_foreign_refs_or_objects_are_rejected() {
        let entries: [(&str, bool); 4] = [
            ("reftable", true),
            ("objects/info/alternates", false),
            ("objects/info/http-alternates", false),
            ("objects/info/alternates", true),
        ];
        for (entry, is_dir) in entries {
            let root = create_temp_root();
            let repo_dir = root.path().join("repo.git");
            create_bare_repo_layout(&repo_dir);
            assert!(resolve_bare_repo(root.path(), "repo.git").await.is_some());

            let entry_path = repo_dir.join(entry);
            let result = if is_dir {
                std::fs::create_dir_all(&entry_path)
            } else {
                match std::fs::create_dir_all(repo_dir.join("objects/info")) {
                    Ok(()) => std::fs::write(&entry_path, b"/elsewhere/objects\n"),
                    Err(error) => Err(error),
                }
            };
            if let Err(error) = result {
                panic!("failed to create {entry}: {error}");
            }
            assert!(
                resolve_bare_repo(root.path(), "repo.git").await.is_none(),
                "repository with {entry} (dir: {is_dir}) should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn repo_with_reftable_placeholder_head_is_rejected() {
        let root = create_temp_root();
        let repo_dir = root.path().join("repo.git");
        create_bare_repo_layout(&repo_dir);
        if let Err(error) = std::fs::write(repo_dir.join("HEAD"), b"ref: refs/heads/.invalid\n") {
            panic!("failed to write HEAD: {error}");
        }
        assert!(resolve_bare_repo(root.path(), "repo.git").await.is_none());
    }

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
    fn parses_head_contents() {
        assert_eq!(
            parse_head(b"ref: refs/heads/main\n"),
            Some(RepoHead::Symbolic("refs/heads/main".to_owned()))
        );
        assert_eq!(
            parse_head(b"0123456789abcdef0123456789abcdef01234567\n"),
            Some(RepoHead::Detached)
        );
        assert_eq!(
            parse_head(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"),
            Some(RepoHead::Detached)
        );

        for invalid in [
            b"" as &[u8],
            b"ref: refs/heads/main",
            b"ref: refs/\n",
            b"ref: heads/main\n",
            b"ref: refs/heads/main\nextra\n",
            b"0123456789ABCDEF0123456789abcdef01234567\n",
            b"0123456789abcdef\n",
            b"not-a-head\n",
            b"ref: refs/heads/\xff\n",
            b"ref: refs/heads/.invalid\n",
            b"ref: refs/.heads/main\n",
            b"ref: refs/heads/a/../b\n",
        ] {
            assert_eq!(parse_head(invalid), None, "{invalid:?} should be rejected");
        }
    }
}
