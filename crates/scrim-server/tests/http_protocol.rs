//! In-process tests of the router: protocol framing, status codes and path
//! validation.

mod common;

use std::io::Write;

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use common::GitSandbox;
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// A temp root containing `test.git` with one commit on `main`.
fn router_with_repo() -> (TempDir, Router) {
    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create repo root temp dir: {error}"),
    };
    GitSandbox::new().init_bare_with_commit(&root.path().join("test.git"));
    let router = scrim_server::router(root.path().to_path_buf());
    (root, router)
}

async fn get(router: Router, uri: &str, git_protocol: Option<&str>) -> Response<Body> {
    let mut request = Request::builder().uri(uri);
    if let Some(value) = git_protocol {
        request = request.header("Git-Protocol", value);
    }
    let request = match request.body(Body::empty()) {
        Ok(request) => request,
        Err(error) => panic!("failed to build request for {uri}: {error}"),
    };
    match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("request to {uri} failed: {error}"),
    }
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    let collected = match response.into_body().collect().await {
        Ok(collected) => collected,
        Err(error) => panic!("failed to collect response body: {error}"),
    };
    collected.to_bytes().to_vec()
}

#[tokio::test]
async fn v0_advertisement_starts_with_service_header() {
    let (_root, router) = router_with_repo();
    let response = get(router, "/test.git/info/refs?service=git-upload-pack", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/x-git-upload-pack-advertisement"
    );
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "no-cache, max-age=0, must-revalidate"
    );
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert_eq!(
        response.headers()[header::EXPIRES],
        "Fri, 01 Jan 1980 00:00:00 GMT"
    );
    let body = body_bytes(response).await;
    assert!(body.starts_with(b"001e# service=git-upload-pack\n0000"));
}

#[tokio::test]
async fn receive_pack_advertisement_has_matching_header() {
    let (_root, router) = router_with_repo();
    let response = get(router, "/test.git/info/refs?service=git-receive-pack", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    assert!(body.starts_with(b"001f# service=git-receive-pack\n0000"));
}

#[tokio::test]
async fn v2_advertisement_has_no_service_header() {
    let (_root, router) = router_with_repo();
    let response = get(
        router,
        "/test.git/info/refs?service=git-upload-pack",
        Some("version=2"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    assert!(body.starts_with(b"000eversion 2\n"));
    assert!(!String::from_utf8_lossy(&body).contains("# service="));
}

#[tokio::test]
async fn dumb_http_and_unknown_services_are_forbidden() {
    let (_root, router) = router_with_repo();
    for uri in [
        "/test.git/info/refs",
        "/test.git/info/refs?service=git-upload-archive",
        "/test.git/info/refs?service=",
    ] {
        let response = get(router.clone(), uri, None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }
}

#[tokio::test]
async fn post_with_wrong_content_type_is_rejected() {
    let (_root, router) = router_with_repo();
    for content_type in [
        Some("application/json"),
        Some("application/x-git-receive-pack-request"),
        None,
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/test.git/git-upload-pack");
        if let Some(value) = content_type {
            request = request.header(header::CONTENT_TYPE, value);
        }
        let request = match request.body(Body::empty()) {
            Ok(request) => request,
            Err(error) => panic!("failed to build request for {content_type:?}: {error}"),
        };
        let response = match router.clone().oneshot(request).await {
            Ok(response) => response,
            Err(error) => panic!("request failed for {content_type:?}: {error}"),
        };
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?}"
        );
    }
}

#[tokio::test]
async fn wrong_method_is_rejected() {
    let (_root, router) = router_with_repo();
    let response = get(router, "/test.git/git-upload-pack", None).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn missing_and_unsafe_repositories_are_not_found() {
    // A bare repo next to the served root, as a tempting traversal target.
    let parent = match TempDir::new() {
        Ok(parent) => parent,
        Err(error) => panic!("failed to create parent temp dir: {error}"),
    };
    let root = parent.path().join("root");
    if let Err(error) = std::fs::create_dir(&root) {
        panic!("failed to create served root {}: {error}", root.display());
    }
    let sandbox = GitSandbox::new();
    sandbox.init_bare_with_commit(&root.join("test.git"));
    sandbox.init_bare(&parent.path().join("scrim-test-outside.git"));
    let router = scrim_server::router(root);

    for path in [
        "/missing.git",
        "/../scrim-test-outside.git",
        "/../x",
        "/%2e%2e/x",
        "/%2E%2E/scrim-test-outside.git",
        "/.git",
        "/a//b",
        "/test.git//",
        "/test.git%2f..%2f..",
    ] {
        let uri = format!("{path}/info/refs?service=git-upload-pack");
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body_bytes(response).await, b"not found");
    }
}

#[tokio::test]
async fn directory_without_bare_repo_layout_is_not_found() {
    let (root, router) = router_with_repo();
    if let Err(error) = std::fs::create_dir(root.path().join("plain-dir")) {
        panic!("failed to create plain directory: {error}");
    }
    let response = get(router, "/plain-dir/info/refs?service=git-upload-pack", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escaping_the_root_is_not_found() {
    let outside = match TempDir::new() {
        Ok(outside) => outside,
        Err(error) => panic!("failed to create outside temp dir: {error}"),
    };
    GitSandbox::new().init_bare(&outside.path().join("secret.git"));
    let root = match TempDir::new() {
        Ok(root) => root,
        Err(error) => panic!("failed to create root temp dir: {error}"),
    };
    if let Err(error) = std::os::unix::fs::symlink(
        outside.path().join("secret.git"),
        root.path().join("link.git"),
    ) {
        panic!("failed to create escaping symlink: {error}");
    }
    let router = scrim_server::router(root.path().to_path_buf());

    let response = get(router, "/link.git/info/refs?service=git-upload-pack", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn gzip_encoded_protocol_v2_request_is_decompressed() {
    let (_root, router) = router_with_repo();
    // command=ls-refs, delimiter, flush.
    let request_body = b"0014command=ls-refs\n00010000";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    if let Err(error) = encoder.write_all(request_body) {
        panic!("failed to write gzip request body: {error}");
    }
    let compressed = match encoder.finish() {
        Ok(compressed) => compressed,
        Err(error) => panic!("failed to finish gzip encoding: {error}"),
    };

    let request = match Request::builder()
        .method("POST")
        .uri("/test.git/git-upload-pack")
        .header(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-request",
        )
        .header(header::CONTENT_ENCODING, "gzip")
        .header("Git-Protocol", "version=2")
        .body(Body::from(compressed))
    {
        Ok(request) => request,
        Err(error) => panic!("failed to build gzip request: {error}"),
    };
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router failed: {error}"),
    };

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/x-git-upload-pack-result"
    );
    let body = match String::from_utf8(body_bytes(response).await) {
        Ok(body) => body,
        Err(error) => panic!("response body is not valid UTF-8: {error}"),
    };
    assert!(
        body.contains(" refs/heads/main\n"),
        "unexpected ls-refs output: {body:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn decoy_dir_next_to_escaping_git_symlink_is_not_found() {
    let Ok(outside) = TempDir::new() else {
        panic!("failed to create outside temp dir");
    };
    GitSandbox::new().init_bare_with_commit(&outside.path().join("secret.git"));

    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let decoy = root.path().join("foo");
    if let Err(error) = std::fs::create_dir_all(decoy.join("objects")) {
        panic!("failed to create decoy objects dir: {error}");
    }
    if let Err(error) = std::fs::create_dir_all(decoy.join("refs")) {
        panic!("failed to create decoy refs dir: {error}");
    }
    if let Err(error) = std::fs::write(decoy.join("HEAD"), "not-a-valid-head\n") {
        panic!("failed to write decoy HEAD: {error}");
    }
    if let Err(error) = std::os::unix::fs::symlink(
        outside.path().join("secret.git"),
        root.path().join("foo.git"),
    ) {
        panic!("failed to create escaping symlink: {error}");
    }

    let router = scrim_server::router(root.path().to_path_buf());
    for service in ["git-upload-pack", "git-receive-pack"] {
        let uri = format!("/foo/info/refs?service={service}");
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn dir_with_escaping_gitdir_file_is_not_found() {
    let Ok(outside) = TempDir::new() else {
        panic!("failed to create outside temp dir");
    };
    let outside_repo = outside.path().join("secret.git");
    let sandbox = GitSandbox::new();
    sandbox.init_bare_with_commit(&outside_repo);

    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    let decoy = root.path().join("decoy.git");
    sandbox.init_bare_with_commit(&decoy);
    if let Err(error) = std::fs::write(
        decoy.join(".git"),
        format!("gitdir: {}\n", outside_repo.display()),
    ) {
        panic!("failed to write .git gitdir file: {error}");
    }

    let router = scrim_server::router(root.path().to_path_buf());
    for service in ["git-upload-pack", "git-receive-pack"] {
        let uri = format!("/decoy.git/info/refs?service={service}");
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_resolving_to_repo_root_is_not_found() {
    let Ok(root) = TempDir::new() else {
        panic!("failed to create root temp dir");
    };
    // Make the root itself look like a valid bare repo so the test exercises
    // the `canonical_repo == canonical_root` check specifically.
    GitSandbox::new().init_bare_with_commit(root.path());
    if let Err(error) = std::os::unix::fs::symlink(".", root.path().join("self.git")) {
        panic!("failed to create self symlink: {error}");
    }

    let router = scrim_server::router(root.path().to_path_buf());
    let response = get(router, "/self.git/info/refs?service=git-upload-pack", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_head_is_not_found() {
    let (root, router) = router_with_repo();
    let real_head = root.path().join("real-head");
    if let Err(error) = std::fs::write(&real_head, "ref: refs/heads/main\n") {
        panic!("failed to write real HEAD target: {error}");
    }
    let repo_head = root.path().join("test.git/HEAD");
    if let Err(error) = std::fs::remove_file(&repo_head) {
        panic!("failed to remove repo HEAD: {error}");
    }
    if let Err(error) = std::os::unix::fs::symlink(&real_head, &repo_head) {
        panic!("failed to symlink repo HEAD: {error}");
    }

    let response = get(router, "/test.git/info/refs?service=git-upload-pack", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn corrupt_gzip_upload_pack_body_aborts_response() {
    let (_root, router) = router_with_repo();
    let request = match Request::builder()
        .method("POST")
        .uri("/test.git/git-upload-pack")
        .header(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-request",
        )
        .header(header::CONTENT_ENCODING, "gzip")
        .header("Git-Protocol", "version=2")
        .body(Body::from(&b"definitely-not-valid-gzip-bytes"[..]))
    {
        Ok(request) => request,
        Err(error) => panic!("failed to build request: {error}"),
    };

    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => panic!("router failed: {error}"),
    };

    // git is started before the body is read, so the error can only surface
    // as an aborted response stream after a 200.
    assert_eq!(response.status(), StatusCode::OK);
    let collected = response.into_body().collect().await;
    assert!(
        collected.is_err(),
        "expected corrupt gzip body to fail the response stream"
    );
}

#[tokio::test]
async fn repo_with_commondir_is_not_found() {
    let outside = match TempDir::new() {
        Ok(outside) => outside,
        Err(error) => panic!("failed to create outside temp dir: {error}"),
    };
    let outside_repo = outside.path().join("secret.git");
    let sandbox = GitSandbox::new();
    sandbox.init_bare_with_commit(&outside_repo);

    let (root, router) = router_with_repo();
    if let Err(error) = std::fs::write(
        root.path().join("test.git/commondir"),
        format!("{}\n", outside_repo.display()),
    ) {
        panic!("failed to write commondir: {error}");
    }

    for service in ["git-upload-pack", "git-receive-pack"] {
        let uri = format!("/test.git/info/refs?service={service}");
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn repo_with_unsearchable_objects_or_refs_is_not_found() {
    use std::os::unix::fs::PermissionsExt;

    for directory in ["objects", "refs"] {
        let (root, router) = router_with_repo();
        let path = root.path().join("test.git").join(directory);
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            panic!("failed to make {directory} unsearchable: {error}");
        }

        let response = get(router, "/test.git/info/refs?service=git-receive-pack", None).await;
        // Restore permissions so the temp dir can be cleaned up.
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        {
            panic!("failed to restore {directory} permissions: {error}");
        }
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{directory}");
    }
}

#[tokio::test]
async fn receive_pack_with_v2_header_still_has_service_prefix() {
    let (_root, router) = router_with_repo();
    let response = get(
        router,
        "/test.git/info/refs?service=git-receive-pack",
        Some("version=2"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    assert!(
        body.starts_with(b"001f# service=git-receive-pack\n0000"),
        "unexpected receive-pack advertisement: {:?}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn corrupt_repo_config_returns_internal_server_error() {
    let (root, router) = router_with_repo();
    if let Err(error) = std::fs::write(root.path().join("test.git/config"), "[core\n") {
        panic!("failed to corrupt repo config: {error}");
    }

    for service in ["git-upload-pack", "git-receive-pack"] {
        let uri = format!("/test.git/info/refs?service={service}");
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{uri}"
        );
    }
}
