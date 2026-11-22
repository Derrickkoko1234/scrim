//! `scrim audit`: reads the server's audit log of access and policy changes.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use secrecy::SecretString;

use crate::cli::AuditArgs;
use crate::client::{AuditLogEntry, AuditLogQuery, ListAuditLogResponse};
use crate::{CliEnv, build_authenticated_client, escape_control_chars, write_line};

/// Largest page size the server accepts for `GET /api/v1/audit-log`.
const MAX_AUDIT_LIMIT: u32 = 500;

/// Handles `scrim audit`. Arguments are validated before any server call.
pub(crate) fn handle_audit(
    args: AuditArgs,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    if let Err(err) = validate_audit_args(&args) {
        return Err(err);
    }
    let client =
        match build_authenticated_client(server_flag, token_override, config_path, &env.cwd) {
            Ok(client) => client,
            Err(err) => return Err(err),
        };
    let query = AuditLogQuery {
        actor: args.actor.as_deref(),
        action: args.action.as_deref(),
        target_type: args.target_type.as_deref(),
        limit: Some(args.limit),
        before_id: args.before_id,
    };
    let response = match client.list_audit_log(&query) {
        Ok(response) => response,
        Err(err) => return Err(err),
    };
    if args.json {
        let text = match serde_json::to_string_pretty(&response) {
            Ok(text) => text,
            Err(err) => return Err(anyhow!(err)).context("failed to encode audit log as JSON"),
        };
        return write_line(env.stdout, &text);
    }
    print_audit_log(env.stdout, &response)
}

fn validate_audit_args(args: &AuditArgs) -> anyhow::Result<()> {
    if args.limit == 0 || args.limit > MAX_AUDIT_LIMIT {
        bail!(
            "--limit must be between 1 and {MAX_AUDIT_LIMIT}, got {}",
            args.limit
        );
    }
    if let Some(before_id) = args.before_id
        && before_id <= 0
    {
        bail!("--before-id must be a positive audit log ID, got {before_id}");
    }
    for (flag, value) in [
        ("--actor", &args.actor),
        ("--action", &args.action),
        ("--target-type", &args.target_type),
    ] {
        if let Some(value) = value
            && value.trim().is_empty()
        {
            bail!("{flag} cannot be empty");
        }
    }
    Ok(())
}

fn print_audit_log(out: &mut dyn Write, response: &ListAuditLogResponse) -> anyhow::Result<()> {
    if response.entries.is_empty()
        && let Err(err) = write_line(out, "No audit log entries.")
    {
        return Err(err);
    }
    for entry in &response.entries {
        if let Err(err) = write_line(out, &format_audit_entry(entry)) {
            return Err(err);
        }
    }
    if let Some(cursor) = response.next_before_id {
        return write_line(
            out,
            &format!("More entries available; pass --before-id {cursor} to view older entries."),
        );
    }
    Ok(())
}

/// Formats one entry as
/// `#<id>  <occurred_at>  <actor>  <action>  <target_type>:<target_name>  [details]`,
/// escaping control characters in every server-supplied field.
fn format_audit_entry(entry: &AuditLogEntry) -> String {
    let actor = match (&entry.actor_name, entry.actor_member_id) {
        (Some(name), _) => name.clone(),
        (None, Some(member_id)) => format!("member#{member_id}"),
        (None, None) => "system".to_owned(),
    };
    let mut line = format!(
        "#{}  {}  {}  {}  {}:{}",
        entry.id,
        escape_control_chars(&entry.occurred_at),
        escape_control_chars(&actor),
        escape_control_chars(&entry.action),
        escape_control_chars(&entry.target_type),
        escape_control_chars(&entry.target_name),
    );
    if let Some(details) = compact_details(&entry.details) {
        line.push_str("  ");
        line.push_str(&escape_control_chars(&details));
    }
    line
}

/// Returns `details` as compact JSON, or `None` when there is nothing to show
/// (`null`, `{}` or `[]`).
fn compact_details(details: &serde_json::Value) -> Option<String> {
    let is_empty = match details {
        serde_json::Value::Null => true,
        serde_json::Value::Object(map) => map.is_empty(),
        serde_json::Value::Array(items) => items.is_empty(),
        _ => false,
    };
    if is_empty {
        return None;
    }
    serde_json::to_string(details).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(actor_name: Option<&str>, details: serde_json::Value) -> AuditLogEntry {
        AuditLogEntry {
            id: 42,
            occurred_at: "2026-11-22T17:00:00Z".to_owned(),
            actor_member_id: Some(1),
            actor_name: actor_name.map(str::to_owned),
            action: "path_rule.set".to_owned(),
            target_type: "path_rule".to_owned(),
            target_name: "team.git:config/billing/**".to_owned(),
            details,
        }
    }

    #[test]
    fn formats_entries_with_actor_fallbacks_and_details() {
        assert_eq!(
            format_audit_entry(&entry(Some("root"), serde_json::json!({}))),
            "#42  2026-11-22T17:00:00Z  root  path_rule.set  path_rule:team.git:config/billing/**"
        );
        assert_eq!(
            format_audit_entry(&entry(None, serde_json::json!({"groups": ["finance"]}))),
            "#42  2026-11-22T17:00:00Z  member#1  path_rule.set  path_rule:team.git:config/billing/**  {\"groups\":[\"finance\"]}"
        );
        let mut system = entry(None, serde_json::Value::Null);
        system.actor_member_id = None;
        assert!(format_audit_entry(&system).contains("  system  "));
    }

    #[test]
    fn escapes_control_characters_from_the_server() {
        let line = format_audit_entry(&entry(Some("ev\u{1b}[2Jil\nx"), serde_json::json!([])));
        assert!(!line.contains('\u{1b}'));
        assert!(!line.contains('\n'));
        assert!(line.contains("ev\\u{1b}[2Jil\\nx"));
    }

    fn args(limit: u32, before_id: Option<i64>, actor: Option<&str>) -> AuditArgs {
        AuditArgs {
            actor: actor.map(str::to_owned),
            action: None,
            target_type: None,
            limit,
            before_id,
            json: false,
        }
    }

    #[test]
    fn validates_limit_before_id_and_filters() {
        assert!(validate_audit_args(&args(1, None, None)).is_ok());
        assert!(validate_audit_args(&args(500, Some(1), Some("root"))).is_ok());
        assert!(validate_audit_args(&args(0, None, None)).is_err());
        assert!(validate_audit_args(&args(501, None, None)).is_err());
        assert!(validate_audit_args(&args(50, Some(0), None)).is_err());
        assert!(validate_audit_args(&args(50, Some(-3), None)).is_err());
        assert!(validate_audit_args(&args(50, None, Some(" "))).is_err());
    }
}
