//! Pass-through Git smart-HTTP server for bare repositories.
//!
//! There is no authentication yet: anything that can reach the listener can
//! read and write every repository under the root.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod git_service;
mod repo_path;

use std::path::{Path, PathBuf};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use tower_http::decompression::RequestDecompressionLayer;

use git_service::{GitService, advertise_refs, sanitize_git_protocol, serve_rpc};
use repo_path::resolve_bare_repo;

/// Builds the router that serves the bare repositories found under `repo_root`
/// over Git smart HTTP (`info/refs`, `git-upload-pack`, `git-receive-pack`).
///
/// Gzip-encoded request bodies, which git sends for large fetch requests, are
/// decompressed transparently. Every other path or method yields an error
/// response.
pub fn router(repo_root: PathBuf) -> Router {
    Router::new()
        // Axum wildcards cannot be followed by a literal suffix, so a single
        // fallback parses `<repo>/info/refs` and `<repo>/git-*-pack` itself.
        .fallback(handle_request)
        .with_state(repo_root)
        .layer(RequestDecompressionLayer::new())
}

/// The kind of smart-HTTP endpoint a request path addresses.
#[derive(Clone, Copy)]
enum Endpoint {
    InfoRefs,
    Rpc(GitService),
}

/// Splits a request path into the repository part and the endpoint suffix.
fn parse_path(path: &str) -> Option<(&str, Endpoint)> {
    let path = match path.strip_prefix('/') {
        Some(path) => path,
        None => return None,
    };
    [
        ("/info/refs", Endpoint::InfoRefs),
        ("/git-upload-pack", Endpoint::Rpc(GitService::UploadPack)),
        ("/git-receive-pack", Endpoint::Rpc(GitService::ReceivePack)),
    ]
    .into_iter()
    .find_map(|(suffix, endpoint)| path.strip_suffix(suffix).map(|repo| (repo, endpoint)))
}

async fn handle_request(State(repo_root): State<PathBuf>, request: Request) -> Response {
    let mut response = route_request(&repo_root, request).await;
    // Git responses must never be cached by clients or proxies.
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, max-age=0, must-revalidate"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::EXPIRES,
        HeaderValue::from_static("Fri, 01 Jan 1980 00:00:00 GMT"),
    );
    response
}

async fn route_request(repo_root: &Path, request: Request) -> Response {
    let (parts, body) = request.into_parts();

    // Same generic answer for malformed, missing and out-of-root repositories.
    let not_found = || (StatusCode::NOT_FOUND, "not found").into_response();
    let Some((repo, endpoint)) = parse_path(parts.uri.path()) else {
        return not_found();
    };
    let Some(repo_dir) = resolve_bare_repo(repo_root, repo).await else {
        return not_found();
    };

    // Only pass through a Git-Protocol value git can safely receive.
    let git_protocol = parts
        .headers
        .get("git-protocol")
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_git_protocol);

    let result = match endpoint {
        Endpoint::InfoRefs => {
            if parts.method != Method::GET {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            // Without a valid `service` this is a dumb-HTTP request, which is
            // not supported.
            let service = parts
                .uri
                .query()
                .and_then(|query| {
                    query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("service="))
                })
                .and_then(GitService::from_service_name);
            let Some(service) = service else {
                return (StatusCode::FORBIDDEN, "dumb HTTP is not supported").into_response();
            };
            advertise_refs(service, &repo_dir, git_protocol)
                .await
                .map(|body| (service, "advertisement", body))
        }
        Endpoint::Rpc(service) => {
            if parts.method != Method::POST {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            let expected_content_type = format!("application/x-{}-request", service.service_name());
            let has_expected_content_type = parts
                .headers
                .get(header::CONTENT_TYPE)
                .is_some_and(|value| value.as_bytes() == expected_content_type.as_bytes());
            if !has_expected_content_type {
                return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
            }
            serve_rpc(service, &repo_dir, git_protocol, body).map(|body| (service, "result", body))
        }
    };

    match result {
        Ok((service, kind, body)) => git_response(service, kind, body),
        Err(error) => {
            tracing::error!(%error, "failed to run git");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn git_response(service: GitService, kind: &str, body: Body) -> Response {
    let content_type = format!("application/x-{}-{kind}", service.service_name());
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}
