//! HTTP client for the Scrim server `/api/v1` admin API.

use std::io::Read;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Method;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::config::normalize_server_url;

/// Maximum API response body size accepted by the CLI (1 MiB).
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Maximum time allowed to establish a TCP/TLS connection to the server.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum total time allowed for a single Admin API request.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Percent-encode every byte except RFC 3986 unreserved characters (`A-Z`, `a-z`,
/// `0-9`, `-`, `.`, `_`, `~`) so path segments containing `/`, spaces, or `%`
/// cannot alter routing.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encodes a single URL path segment.
pub fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn deserialize_secret_string<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let mut raw = match String::deserialize(deserializer) {
        Ok(value) => Zeroizing::new(value),
        Err(err) => return Err(err),
    };
    let secret = SecretString::from(raw.as_str());
    raw.zeroize();
    Ok(secret)
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, Deserialize)]
pub struct WhoamiResponse {
    pub id: i64,
    pub name: String,
    pub is_admin: bool,
    pub groups: Vec<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Serialize)]
struct CreateRepositoryRequest<'a> {
    path: &'a str,
    create_bare: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateRepositoryResponse {
    pub id: i64,
    pub path: String,
    pub created: bool,
    pub bare_initialized: bool,
}

#[derive(Debug, Deserialize)]
pub struct RepositoryInfo {
    pub id: i64,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct ListRepositoriesResponse {
    pub repositories: Vec<RepositoryInfo>,
}

#[derive(Serialize)]
struct CreateGroupRequest<'a> {
    name: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupResponse {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct GroupInfo {
    pub id: i64,
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListGroupsResponse {
    pub groups: Vec<GroupInfo>,
}

#[derive(Serialize)]
struct GroupMemberRequest<'a> {
    member: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct AddGroupMemberResponse {
    pub group: String,
    pub member: String,
    pub added: bool,
}

#[derive(Debug, Deserialize)]
pub struct RemoveGroupMemberResponse {
    pub group: String,
    pub member: String,
    pub removed: bool,
}

#[derive(Serialize)]
struct CreateMemberRequest<'a> {
    name: &'a str,
    is_admin: bool,
    is_machine: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
    groups: &'a [String],
    token_label: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct MemberInfo {
    pub id: i64,
    pub name: String,
    pub is_admin: bool,
    pub is_machine: bool,
    #[serde(default)]
    pub public_key: Option<String>,
    pub groups: Vec<String>,
    pub revoked: bool,
}

#[derive(Deserialize)]
pub struct CreateMemberResponse {
    pub member: MemberInfo,
    #[serde(deserialize_with = "deserialize_secret_string")]
    pub token: SecretString,
}

impl std::fmt::Debug for CreateMemberResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateMemberResponse")
            .field("member", &self.member)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct IssueTokenRequest<'a> {
    label: &'a str,
}

#[derive(Deserialize)]
pub struct IssueTokenResponse {
    pub member: String,
    pub label: String,
    #[serde(deserialize_with = "deserialize_secret_string")]
    pub token: SecretString,
}

impl std::fmt::Debug for IssueTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssueTokenResponse")
            .field("member", &self.member)
            .field("label", &self.label)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeMemberResponse {
    pub name: String,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberInfo>,
}

#[derive(Serialize)]
struct PutBranchRuleRequest<'a> {
    repository: &'a str,
    pattern: &'a str,
    groups: &'a [String],
}

#[derive(Debug, Deserialize)]
pub struct PutBranchRuleResponse {
    pub repository: String,
    pub pattern: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BranchRuleInfo {
    pub pattern: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListBranchRulesResponse {
    pub repository: String,
    pub rules: Vec<BranchRuleInfo>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteBranchRuleResponse {
    pub repository: String,
    pub pattern: String,
    pub removed: bool,
}

#[derive(Serialize)]
struct SetPublicKeyRequest<'a> {
    public_key: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct MemberPublicKeyResponse {
    pub name: String,
    pub public_key: String,
}

#[derive(Serialize)]
struct PutSecretScopeRequest<'a> {
    repository: &'a str,
    scope: &'a str,
    groups: &'a [String],
}

#[derive(Debug, Deserialize)]
pub struct PutSecretScopeResponse {
    pub repository: String,
    pub scope: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SecretScopeInfo {
    pub scope: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListSecretScopesResponse {
    pub repository: String,
    pub scopes: Vec<SecretScopeInfo>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteSecretScopeResponse {
    pub repository: String,
    pub scope: String,
    pub removed: bool,
}

#[derive(Debug, Deserialize)]
pub struct ScopeRecipientInfo {
    pub member: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ScopeRecipientsResponse {
    pub repository: String,
    pub scope: String,
    pub groups: Vec<String>,
    pub recipients: Vec<ScopeRecipientInfo>,
    pub members_without_key: Vec<String>,
}

/// Blocking HTTP client for talking to a Scrim server's `/api/v1` endpoints.
pub struct ScrimClient {
    base_url: String,
    token: SecretString,
    http: Client,
}

impl std::fmt::Debug for ScrimClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScrimClient")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl ScrimClient {
    /// Creates a new client pointing at `base_url` using bearer `token`.
    pub fn new(base_url: &str, token: SecretString) -> anyhow::Result<Self> {
        let normalized = match normalize_server_url(base_url) {
            Ok(url) => url,
            Err(err) => return Err(err),
        };
        let http = match Client::builder()
            .redirect(Policy::none())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
        {
            Ok(client) => client,
            Err(err) => return Err(anyhow!("failed to build HTTP client: {err}")),
        };
        Ok(Self {
            base_url: normalized,
            token,
            http,
        })
    }

    /// Returns the normalized base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn whoami(&self) -> anyhow::Result<WhoamiResponse> {
        self.send_empty(Method::GET, "/api/v1/whoami", &[])
    }

    pub fn create_repository(
        &self,
        path: &str,
        create_bare: bool,
    ) -> anyhow::Result<CreateRepositoryResponse> {
        let body = CreateRepositoryRequest { path, create_bare };
        self.send_json(Method::POST, "/api/v1/repositories", &[], &body)
    }

    pub fn list_repositories(&self) -> anyhow::Result<ListRepositoriesResponse> {
        self.send_empty(Method::GET, "/api/v1/repositories", &[])
    }

    pub fn create_group(&self, name: &str) -> anyhow::Result<CreateGroupResponse> {
        let body = CreateGroupRequest { name };
        self.send_json(Method::POST, "/api/v1/groups", &[], &body)
    }

    pub fn list_groups(&self) -> anyhow::Result<ListGroupsResponse> {
        self.send_empty(Method::GET, "/api/v1/groups", &[])
    }

    pub fn add_group_member(
        &self,
        group: &str,
        member: &str,
    ) -> anyhow::Result<AddGroupMemberResponse> {
        let path = format!("/api/v1/groups/{}/members", encode_path_segment(group));
        let body = GroupMemberRequest { member };
        self.send_json(Method::POST, &path, &[], &body)
    }

    pub fn remove_group_member(
        &self,
        group: &str,
        member: &str,
    ) -> anyhow::Result<RemoveGroupMemberResponse> {
        let path = format!(
            "/api/v1/groups/{}/members/{}",
            encode_path_segment(group),
            encode_path_segment(member)
        );
        self.send_empty(Method::DELETE, &path, &[])
    }

    pub fn create_member(
        &self,
        name: &str,
        is_admin: bool,
        is_machine: bool,
        public_key: Option<&str>,
        groups: &[String],
        token_label: &str,
    ) -> anyhow::Result<CreateMemberResponse> {
        let body = CreateMemberRequest {
            name,
            is_admin,
            is_machine,
            public_key,
            groups,
            token_label,
        };
        self.send_json(Method::POST, "/api/v1/members", &[], &body)
    }

    pub fn set_own_public_key(&self, public_key: &str) -> anyhow::Result<MemberPublicKeyResponse> {
        let body = SetPublicKeyRequest { public_key };
        self.send_json(Method::PUT, "/api/v1/me/public-key", &[], &body)
    }

    pub fn set_member_public_key(
        &self,
        member: &str,
        public_key: &str,
    ) -> anyhow::Result<MemberPublicKeyResponse> {
        let path = format!("/api/v1/members/{}/public-key", encode_path_segment(member));
        let body = SetPublicKeyRequest { public_key };
        self.send_json(Method::PUT, &path, &[], &body)
    }

    pub fn issue_token(&self, member: &str, label: &str) -> anyhow::Result<IssueTokenResponse> {
        let path = format!("/api/v1/members/{}/tokens", encode_path_segment(member));
        let body = IssueTokenRequest { label };
        self.send_json(Method::POST, &path, &[], &body)
    }

    pub fn revoke_member(&self, member: &str) -> anyhow::Result<RevokeMemberResponse> {
        let path = format!("/api/v1/members/{}", encode_path_segment(member));
        self.send_empty(Method::DELETE, &path, &[])
    }

    pub fn list_members(&self, include_revoked: bool) -> anyhow::Result<ListMembersResponse> {
        let flag = if include_revoked { "true" } else { "false" };
        self.send_empty(Method::GET, "/api/v1/members", &[("include_revoked", flag)])
    }

    pub fn put_branch_rule(
        &self,
        repository: &str,
        pattern: &str,
        groups: &[String],
    ) -> anyhow::Result<PutBranchRuleResponse> {
        let body = PutBranchRuleRequest {
            repository,
            pattern,
            groups,
        };
        self.send_json(Method::PUT, "/api/v1/branch-rules", &[], &body)
    }

    pub fn list_branch_rules(&self, repository: &str) -> anyhow::Result<ListBranchRulesResponse> {
        self.send_empty(Method::GET, "/api/v1/branch-rules", &[("repo", repository)])
    }

    pub fn delete_branch_rule(
        &self,
        repository: &str,
        pattern: &str,
    ) -> anyhow::Result<DeleteBranchRuleResponse> {
        self.send_empty(
            Method::DELETE,
            "/api/v1/branch-rules",
            &[("repo", repository), ("pattern", pattern)],
        )
    }

    pub fn put_secret_scope(
        &self,
        repository: &str,
        scope: &str,
        groups: &[String],
    ) -> anyhow::Result<PutSecretScopeResponse> {
        let body = PutSecretScopeRequest {
            repository,
            scope,
            groups,
        };
        self.send_json(Method::PUT, "/api/v1/secret-scopes", &[], &body)
    }

    pub fn list_secret_scopes(&self, repository: &str) -> anyhow::Result<ListSecretScopesResponse> {
        self.send_empty(
            Method::GET,
            "/api/v1/secret-scopes",
            &[("repo", repository)],
        )
    }

    pub fn delete_secret_scope(
        &self,
        repository: &str,
        scope: &str,
    ) -> anyhow::Result<DeleteSecretScopeResponse> {
        self.send_empty(
            Method::DELETE,
            "/api/v1/secret-scopes",
            &[("repo", repository), ("scope", scope)],
        )
    }

    pub fn get_secret_scope_recipients(
        &self,
        repository: &str,
        scope: &str,
    ) -> anyhow::Result<ScopeRecipientsResponse> {
        self.send_empty(
            Method::GET,
            "/api/v1/secret-scopes/recipients",
            &[("repo", repository), ("scope", scope)],
        )
    }

    fn send_empty<R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        api_path: &str,
        query: &[(&str, &str)],
    ) -> anyhow::Result<R> {
        let url = format!("{}{api_path}", self.base_url);
        let mut request = self
            .http
            .request(method, &url)
            .bearer_auth(self.token.expose_secret());
        if !query.is_empty() {
            request = request.query(query);
        }
        execute_request(request, api_path)
    }

    fn send_json<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        api_path: &str,
        query: &[(&str, &str)],
        body: &B,
    ) -> anyhow::Result<R> {
        let url = format!("{}{api_path}", self.base_url);
        let mut request = self
            .http
            .request(method, &url)
            .bearer_auth(self.token.expose_secret())
            .json(body);
        if !query.is_empty() {
            request = request.query(query);
        }
        execute_request(request, api_path)
    }
}

fn execute_request<R: for<'de> Deserialize<'de>>(
    request: reqwest::blocking::RequestBuilder,
    api_path: &str,
) -> anyhow::Result<R> {
    let response = match request.send() {
        Ok(resp) => resp,
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| format!("request to {api_path} failed"));
        }
    };

    let status = response.status();
    // Bound response size and keep the raw body zeroized because member/token
    // endpoints return newly issued bearer tokens in JSON.
    let mut raw_bytes = Zeroizing::new(Vec::new());
    let mut limited = response.take(MAX_RESPONSE_BYTES + 1);
    if let Err(err) = limited.read_to_end(&mut raw_bytes) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to read response body from {api_path}"));
    }
    if raw_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("response body from {api_path} exceeded {MAX_RESPONSE_BYTES} bytes");
    }
    let text = match String::from_utf8(std::mem::take(&mut *raw_bytes)) {
        Ok(body) => Zeroizing::new(body),
        Err(err) => {
            let mut invalid = err.into_bytes();
            invalid.zeroize();
            bail!("response body from {api_path} was not valid UTF-8");
        }
    };

    if !status.is_success() {
        if let Ok(err_body) = serde_json::from_str::<ErrorBody>(&text)
            && !err_body.error.is_empty()
        {
            bail!("server returned {status}: {}", err_body.error);
        }
        let reason = match status.canonical_reason() {
            Some(reason) => reason.to_owned(),
            None => status.to_string(),
        };
        bail!("server returned {status}: {reason}");
    }

    match serde_json::from_str::<R>(&text) {
        Ok(parsed) => Ok(parsed),
        Err(err) => Err(anyhow!(err))
            .with_context(|| format!("failed to decode JSON response from {api_path}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encodes_path_segments_safely() {
        assert_eq!(encode_path_segment("core-team_1.0~a"), "core-team_1.0~a");
        assert_eq!(encode_path_segment("team/sub"), "team%2Fsub");
        assert_eq!(encode_path_segment("alice smith"), "alice%20smith");
        assert_eq!(encode_path_segment("a?b#c%d"), "a%3Fb%23c%25d");
    }

    #[test]
    fn client_debug_redacts_token() {
        let client = match ScrimClient::new(
            "http://127.0.0.1:8080/",
            SecretString::from("scrim_secret_xyz"),
        ) {
            Ok(c) => c,
            Err(err) => panic!("client construction failed: {err}"),
        };
        assert_eq!(client.base_url(), "http://127.0.0.1:8080");
        let debug = format!("{client:?}");
        assert!(!debug.contains("scrim_secret_xyz"));
        assert!(debug.contains("[REDACTED]"));
    }
}
