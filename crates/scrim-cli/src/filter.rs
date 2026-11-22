//! Git long-running clean/smudge filter (`filter.scrim.process`), speaking
//! Git's filter protocol version 2 over pkt-lines.
//!
//! Git starts `scrim filter-process` once per command and streams every
//! `filter=scrim` path through it:
//!
//! - **clean** (working tree → Git object store) encrypts plaintext with the
//!   group key from `.scrim/group-keys/<group>.toml`, and turns an intact
//!   placeholder or an already-encrypted blob back into the exact original
//!   blob, so non-members never see spurious modifications and blobs are
//!   never encrypted twice.
//! - **smudge** (Git object store → working tree) decrypts blobs for group
//!   members and renders a readable placeholder for everyone else.
//!
//! Key files are read from the working tree first and then from Git
//! (`<treeish>:` or `HEAD:`), so `git clone` and checkouts of commits made
//! under older key generations work before `.scrim/` is (re)written. Every
//! unwrapped `(group, generation)` key is cached for the life of the process
//! and zeroized on drop. Diagnostics never include plaintext or key material.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufWriter, ErrorKind, Write};
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use scrim_crypto::{
    CryptoError, GroupDataKey, GroupKeysFile, MemberIdentity, decrypt_file, encrypt_file,
    extract_placeholder, format_placeholder, is_encrypted_file, is_placeholder,
    parse_encrypted_file_header,
};
use scrim_policy::PathPolicy;
use zeroize::Zeroizing;

use crate::git::git_cat_file_blob;
use crate::private_store::{
    empty_path_policy, parse_path_policy, read_group_keys, read_path_policy_file,
};

/// Largest request payload accepted from Git, in bytes. It covers the
/// placeholder for the largest private file `scrim-crypto` accepts (64 MiB of
/// plaintext becomes roughly 87 MiB of wrapped base64); larger inputs are
/// drained and answered with `status=error` instead of being buffered.
pub const MAX_FILTER_INPUT_BYTES: usize = 90 * 1024 * 1024;

/// Largest pkt-line including its 4-byte length header.
const MAX_PKT_LINE_BYTES: usize = 65520;
/// Largest pkt-line payload.
const MAX_PKT_DATA_BYTES: usize = MAX_PKT_LINE_BYTES - 4;
/// Upper bound on lines in one handshake or request header list.
const MAX_LIST_LINES: usize = 128;

/// A single pkt-line read from Git.
enum Packet {
    /// `0000`.
    Flush,
    /// A data packet whose payload occupies the first `len` bytes of the
    /// caller's buffer.
    Data(usize),
}

/// Key, identity and policy state shared by every request of one
/// `scrim filter-process` run.
pub struct FilterContext {
    repo_root: PathBuf,
    identity: Option<MemberIdentity>,
    /// Why `identity` is `None`, reported when encryption needs it.
    identity_problem: String,
    key_cache: BTreeMap<(String, u64), GroupDataKey>,
    /// `(group, generation)` pairs the identity is known not to be able to
    /// unwrap, so non-members do not retry `age` decryption for every file.
    denied: BTreeSet<(String, u64)>,
}

impl FilterContext {
    /// Creates a context for the repository at `repo_root`. `identity` is
    /// `None` for callers without a configured identity, in which case
    /// `identity_problem` explains why (it must not contain secrets).
    pub fn new(
        repo_root: PathBuf,
        identity: Option<MemberIdentity>,
        identity_problem: String,
    ) -> Self {
        Self {
            repo_root,
            identity,
            identity_problem,
            key_cache: BTreeMap::new(),
            denied: BTreeSet::new(),
        }
    }

    /// Converts working-tree content for `pathname` into the bytes Git stores.
    ///
    /// # Errors
    ///
    /// Fails on malformed blobs, edited or moved placeholders, ambiguous path
    /// rules, a missing group key file, a missing identity, or a caller who
    /// is not a member of the protecting group.
    pub fn clean(&mut self, pathname: &str, input: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if is_encrypted_file(input) {
            // Already encrypted (for example a raw blob checked out without
            // the filter): store it unchanged rather than encrypting twice.
            return match parse_encrypted_file_header(input) {
                Ok(_) => Ok(Zeroizing::new(input.to_vec())),
                Err(err) => Err(anyhow!(err)).context("malformed encrypted private file"),
            };
        }
        if is_placeholder(input) {
            let extracted = match extract_placeholder(input) {
                Ok(extracted) => extracted,
                Err(err) => {
                    return Err(anyhow!(err)).context(
                        "the private file placeholder was edited or corrupted; restore it with 'git checkout -- <path>'",
                    );
                }
            };
            if extracted.path != pathname {
                bail!(
                    "placeholder belongs to '{}'; an encrypted private file cannot be moved or copied without access to group '{}'",
                    extracted.path,
                    extracted.header.group
                );
            }
            return Ok(Zeroizing::new(extracted.blob));
        }

        let policy = match self.load_path_policy() {
            Ok(policy) => policy,
            Err(err) => return Err(err),
        };
        let group = match policy.group_for_path(pathname) {
            Ok(Some(group)) => group.to_owned(),
            Ok(None) => return Ok(Zeroizing::new(input.to_vec())),
            Err(err) => return Err(anyhow!(err)),
        };
        if self.identity.is_none() {
            bail!(
                "no Scrim identity is available to encrypt this private file of group '{group}' ({})",
                self.identity_problem
            );
        }
        let keys_file = match self.find_group_keys(&group, None, None) {
            Ok(Some(file)) => file,
            Ok(None) => bail!(
                "group key file .scrim/group-keys/{group}.toml is missing; run 'scrim private add' or pull it first"
            ),
            Err(err) => return Err(err),
        };
        match self.unwrap_and_cache(&group, &keys_file) {
            Ok(()) => {}
            Err(CryptoError::Unauthorized) => bail!(
                "you are not a member of group '{group}'; refusing to store plaintext for a private file you cannot encrypt"
            ),
            Err(err) => {
                return Err(anyhow!(err))
                    .with_context(|| format!("failed to unwrap the key for group '{group}'"));
            }
        }
        let Some(data_key) = self.key_cache.get(&(group.clone(), keys_file.generation)) else {
            bail!("internal error: group key for '{group}' was not cached");
        };
        match encrypt_file(&group, keys_file.generation, pathname, data_key, input) {
            Ok(blob) => Ok(Zeroizing::new(blob)),
            Err(err) => Err(anyhow!(err)).context("failed to encrypt private file"),
        }
    }

    /// Converts a stored blob for `pathname` into working-tree content:
    /// plaintext for group members, a placeholder for everyone else, and
    /// non-encrypted content unchanged. `treeish` is the tree Git is checking
    /// out, when it reports one.
    ///
    /// # Errors
    ///
    /// Fails on a malformed blob, an invalid key file, a wrapped key bound to
    /// another group or generation, or a blob that fails authenticated
    /// decryption for a member (tampering is never hidden behind a
    /// placeholder).
    pub fn smudge(
        &mut self,
        pathname: &str,
        treeish: Option<&str>,
        input: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if !is_encrypted_file(input) {
            return Ok(Zeroizing::new(input.to_vec()));
        }
        let header = match parse_encrypted_file_header(input) {
            Ok(header) => header,
            Err(err) => return Err(anyhow!(err)).context("malformed encrypted private file"),
        };
        let cache_key = (header.group.clone(), header.generation);
        if self.identity.is_none() || self.denied.contains(&cache_key) {
            return placeholder(pathname, input);
        }
        if !self.key_cache.contains_key(&cache_key) {
            let keys_file =
                match self.find_group_keys(&header.group, Some(header.generation), treeish) {
                    Ok(Some(file)) => file,
                    Ok(None) => return placeholder(pathname, input),
                    Err(err) => return Err(err),
                };
            match self.unwrap_and_cache(&header.group, &keys_file) {
                Ok(()) => {}
                Err(CryptoError::Unauthorized) => {
                    self.denied.insert(cache_key);
                    return placeholder(pathname, input);
                }
                Err(err) => {
                    return Err(anyhow!(err)).with_context(|| {
                        format!("failed to unwrap the key for group '{}'", header.group)
                    });
                }
            }
        }
        let Some(data_key) = self.key_cache.get(&cache_key) else {
            bail!(
                "internal error: group key for '{}' was not cached",
                header.group
            );
        };
        match decrypt_file(&header.group, header.generation, pathname, data_key, input) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) => Err(anyhow!(err)).context("failed to decrypt private file"),
        }
    }

    /// Unwraps `keys_file` with the identity and caches the key under
    /// `(group, keys_file.generation)`.
    fn unwrap_and_cache(
        &mut self,
        group: &str,
        keys_file: &GroupKeysFile,
    ) -> Result<(), CryptoError> {
        let cache_key = (group.to_owned(), keys_file.generation);
        if self.key_cache.contains_key(&cache_key) {
            return Ok(());
        }
        let Some(identity) = &self.identity else {
            return Err(CryptoError::Unauthorized);
        };
        match keys_file.unwrap_key(group, identity) {
            Ok(key) => {
                self.key_cache.insert(cache_key, key);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Finds the key file for `group`: the working-tree copy when it matches
    /// `wanted_generation` (any generation when `None`), otherwise the copy
    /// stored at `treeish` and then at `HEAD`.
    fn find_group_keys(
        &self,
        group: &str,
        wanted_generation: Option<u64>,
        treeish: Option<&str>,
    ) -> anyhow::Result<Option<GroupKeysFile>> {
        let wanted = |file: &GroupKeysFile| match wanted_generation {
            Some(generation) => file.generation == generation,
            None => true,
        };
        match read_group_keys(&self.repo_root, group) {
            Ok(Some(file)) if wanted(&file) => return Ok(Some(file)),
            Ok(_) => {}
            Err(err) => return Err(err),
        }

        let mut revisions = Vec::with_capacity(2);
        if let Some(treeish) = treeish
            && is_object_id(treeish)
        {
            revisions.push(treeish);
        }
        revisions.push("HEAD");
        for revision in revisions {
            let spec = format!("{revision}:.scrim/group-keys/{group}.toml");
            let bytes = match git_cat_file_blob(&self.repo_root, &spec) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => continue,
                Err(err) => return Err(err),
            };
            let Ok(text) = String::from_utf8(bytes) else {
                bail!("{spec} is not valid UTF-8");
            };
            let file = match GroupKeysFile::from_toml_str(&text) {
                Ok(file) => file,
                Err(err) => return Err(anyhow!(err)).with_context(|| format!("invalid {spec}")),
            };
            if file.group == group && wanted(&file) {
                return Ok(Some(file));
            }
        }
        Ok(None)
    }

    /// Reads `.scrim/paths.toml` from the working tree, falling back to the
    /// copy at `HEAD` (and to an empty policy) when it is absent.
    fn load_path_policy(&self) -> anyhow::Result<PathPolicy> {
        match read_path_policy_file(&self.repo_root) {
            Ok(Some(policy)) => return Ok(policy),
            Ok(None) => {}
            Err(err) => return Err(err),
        }
        match git_cat_file_blob(&self.repo_root, "HEAD:.scrim/paths.toml") {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(text) => parse_path_policy(&text),
                Err(_) => bail!("HEAD:.scrim/paths.toml is not valid UTF-8"),
            },
            Ok(None) => empty_path_policy(),
            Err(err) => Err(err),
        }
    }
}

fn placeholder(pathname: &str, blob: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match format_placeholder(pathname, blob) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(err) => Err(anyhow!(err)).context("failed to render placeholder"),
    }
}

/// Accepts only hexadecimal object ids, so a Git-supplied `treeish` can never
/// smuggle revision syntax or options into `git cat-file`.
fn is_object_id(value: &str) -> bool {
    (4..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Serves Git's long-running filter protocol on `input`/`output` until Git
/// closes the stream between requests.
///
/// Per-file failures are reported to Git as `status=error` (with a
/// diagnostic on `stderr`) and the loop continues.
///
/// # Errors
///
/// Fails on I/O errors, a malformed handshake, malformed pkt-lines, or a
/// stream that ends in the middle of a request.
pub fn serve(
    context: &mut FilterContext,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    stderr: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut writer = BufWriter::with_capacity(MAX_PKT_LINE_BYTES, output);
    // Reused for every packet; zeroized on drop because it carries plaintext.
    let mut packet_buffer = Zeroizing::new(vec![0_u8; MAX_PKT_DATA_BYTES]);

    if let Err(err) = handshake(input, &mut writer, &mut packet_buffer) {
        return Err(err).context("git filter protocol handshake failed");
    }

    loop {
        let header = match read_text_list(input, &mut packet_buffer) {
            Ok(Some(lines)) => lines,
            Ok(None) => return Ok(()),
            Err(err) => return Err(anyhow!(err)).context("failed to read filter request"),
        };
        let mut command = None;
        let mut pathname = None;
        let mut treeish = None;
        for line in header {
            if let Some(value) = line.strip_prefix("command=") {
                command = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("pathname=") {
                pathname = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("treeish=") {
                treeish = Some(value.to_owned());
            }
        }
        let (Some(command), Some(pathname)) = (command, pathname) else {
            bail!("filter request is missing command= or pathname=");
        };
        let content = match read_content(input, &mut packet_buffer) {
            Ok(content) => content,
            Err(err) => return Err(anyhow!(err)).context("failed to read filter content"),
        };

        let result = match (content, command.as_str()) {
            (None, _) => Err(anyhow!(
                "input is larger than the {MAX_FILTER_INPUT_BYTES}-byte filter limit"
            )),
            (Some(content), "clean") => context.clean(&pathname, &content),
            (Some(content), "smudge") => context.smudge(&pathname, treeish.as_deref(), &content),
            (Some(_), other) => Err(anyhow!("unsupported filter command {other:?}")),
        };
        let written = match result {
            Ok(converted) => write_success(&mut writer, &converted),
            Err(err) => {
                let _ = writeln!(stderr, "scrim: {command} '{pathname}' failed: {err:#}");
                let _ = stderr.flush();
                write_error(&mut writer)
            }
        };
        if let Err(err) = written {
            return Err(anyhow!(err)).context("failed to write filter response");
        }
    }
}

fn handshake(
    input: &mut dyn BufRead,
    writer: &mut dyn Write,
    buffer: &mut [u8],
) -> anyhow::Result<()> {
    let welcome = match read_text_list(input, buffer) {
        Ok(Some(lines)) => lines,
        Ok(None) => bail!("git closed the stream before the handshake"),
        Err(err) => return Err(anyhow!(err)),
    };
    if welcome.first().map(String::as_str) != Some("git-filter-client") {
        bail!("expected git-filter-client greeting");
    }
    if !welcome.iter().any(|line| line == "version=2") {
        bail!("git does not offer filter protocol version 2");
    }
    let replied = write_text(writer, "git-filter-server")
        .and_then(|()| write_text(writer, "version=2"))
        .and_then(|()| write_flush(writer))
        .and_then(|()| writer.flush());
    if let Err(err) = replied {
        return Err(anyhow!(err));
    }

    let offered = match read_text_list(input, buffer) {
        Ok(Some(lines)) => lines,
        Ok(None) => bail!("git closed the stream before sending capabilities"),
        Err(err) => return Err(anyhow!(err)),
    };
    for capability in ["clean", "smudge"] {
        let line = format!("capability={capability}");
        if offered.contains(&line)
            && let Err(err) = write_text(writer, &line)
        {
            return Err(anyhow!(err));
        }
    }
    match write_flush(writer).and_then(|()| writer.flush()) {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(err)),
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

/// Reads one pkt-line into `buffer`. Returns `Ok(None)` on end of stream at a
/// packet boundary.
fn read_packet(input: &mut dyn BufRead, buffer: &mut [u8]) -> io::Result<Option<Packet>> {
    match input.fill_buf() {
        Ok([]) => return Ok(None),
        Ok(_) => {}
        Err(err) => return Err(err),
    }
    let mut header = [0_u8; 4];
    if let Err(err) = input.read_exact(&mut header) {
        return Err(err);
    }
    let mut length = 0_usize;
    for byte in header {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(invalid_data("pkt-line length is not 4 hex digits")),
        };
        length = length * 16 + usize::from(digit);
    }
    if length == 0 {
        return Ok(Some(Packet::Flush));
    }
    if !(4..=MAX_PKT_LINE_BYTES).contains(&length) {
        return Err(invalid_data("invalid pkt-line length"));
    }
    let data_len = length - 4;
    let Some(target) = buffer.get_mut(..data_len) else {
        return Err(invalid_data("pkt-line buffer is too small"));
    };
    match input.read_exact(target) {
        Ok(()) => Ok(Some(Packet::Data(data_len))),
        Err(err) => Err(err),
    }
}

/// Reads text packets up to a flush. Returns `Ok(None)` when the stream ends
/// before the first packet.
fn read_text_list(input: &mut dyn BufRead, buffer: &mut [u8]) -> io::Result<Option<Vec<String>>> {
    let mut lines = Vec::new();
    loop {
        let len = match read_packet(input, buffer) {
            Ok(Some(Packet::Flush)) => return Ok(Some(lines)),
            Ok(Some(Packet::Data(len))) => len,
            Ok(None) if lines.is_empty() => return Ok(None),
            Ok(None) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Err(err) => return Err(err),
        };
        if lines.len() >= MAX_LIST_LINES {
            return Err(invalid_data("too many lines in pkt-line list"));
        }
        let Some(data) = buffer.get(..len) else {
            return Err(invalid_data("pkt-line buffer is too small"));
        };
        let Ok(text) = std::str::from_utf8(data) else {
            return Err(invalid_data("pkt-line text is not UTF-8"));
        };
        let text = match text.strip_suffix('\n') {
            Some(stripped) => stripped,
            None => text,
        };
        lines.push(text.to_owned());
    }
}

/// Reads content packets up to a flush into a zeroizing buffer. Returns
/// `Ok(None)` (after draining the content) when it exceeds
/// [`MAX_FILTER_INPUT_BYTES`].
fn read_content(
    input: &mut dyn BufRead,
    buffer: &mut [u8],
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut content = Zeroizing::new(Vec::new());
    let mut too_large = false;
    loop {
        let len = match read_packet(input, buffer) {
            Ok(Some(Packet::Flush)) => break,
            Ok(Some(Packet::Data(len))) => len,
            Ok(None) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Err(err) => return Err(err),
        };
        if too_large {
            continue;
        }
        if content.len() + len > MAX_FILTER_INPUT_BYTES {
            too_large = true;
            content = Zeroizing::new(Vec::new());
            continue;
        }
        let Some(data) = buffer.get(..len) else {
            return Err(invalid_data("pkt-line buffer is too small"));
        };
        append_zeroizing(&mut content, data);
    }
    if too_large {
        Ok(None)
    } else {
        Ok(Some(content))
    }
}

/// Appends `data`, growing into a fresh zeroizing allocation so plaintext is
/// never left behind in memory freed by a `Vec` reallocation.
fn append_zeroizing(content: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    let needed = content.len() + data.len();
    if needed > content.capacity() {
        let capacity = needed.max(content.capacity().saturating_mul(2));
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(content);
        grown.extend_from_slice(data);
        *content = grown;
    } else {
        content.extend_from_slice(data);
    }
}

fn write_packet(writer: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    let header = format!("{:04x}", data.len() + 4);
    match writer.write_all(header.as_bytes()) {
        Ok(()) => writer.write_all(data),
        Err(err) => Err(err),
    }
}

fn write_text(writer: &mut dyn Write, line: &str) -> io::Result<()> {
    let mut data = Vec::with_capacity(line.len() + 1);
    data.extend_from_slice(line.as_bytes());
    data.push(b'\n');
    write_packet(writer, &data)
}

fn write_flush(writer: &mut dyn Write) -> io::Result<()> {
    writer.write_all(b"0000")
}

/// Writes `status=success`, the converted content, and the empty trailing
/// status list that protocol version 2 requires after the content.
fn write_success(writer: &mut dyn Write, content: &[u8]) -> io::Result<()> {
    if let Err(err) = write_text(writer, "status=success").and_then(|()| write_flush(writer)) {
        return Err(err);
    }
    for chunk in content.chunks(MAX_PKT_DATA_BYTES) {
        if let Err(err) = write_packet(writer, chunk) {
            return Err(err);
        }
    }
    write_flush(writer)
        .and_then(|()| write_flush(writer))
        .and_then(|()| writer.flush())
}

fn write_error(writer: &mut dyn Write) -> io::Result<()> {
    write_text(writer, "status=error")
        .and_then(|()| write_flush(writer))
        .and_then(|()| writer.flush())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Cursor;
    use std::path::Path;
    use std::process::Command;

    use scrim_crypto::rotate_group_key;
    use scrim_policy::PathRule;

    use super::*;
    use crate::private_store::{write_group_keys, write_path_policy};

    const SECRET: &[u8] = b"BILLING_TOKEN=top_secret_billing_value\n";

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{context}: {err}"),
        }
    }

    fn pkt(data: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", data.len() + 4).into_bytes();
        out.extend_from_slice(data);
        out
    }

    fn text(line: &str) -> Vec<u8> {
        pkt(format!("{line}\n").as_bytes())
    }

    fn handshake_bytes(capabilities: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(text("git-filter-client"));
        out.extend(text("version=2"));
        out.extend_from_slice(b"0000");
        for capability in capabilities {
            out.extend(text(&format!("capability={capability}")));
        }
        out.extend_from_slice(b"0000");
        out
    }

    fn request_bytes(
        command: &str,
        pathname: &str,
        treeish: Option<&str>,
        content: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(text(&format!("command={command}")));
        out.extend(text(&format!("pathname={pathname}")));
        if let Some(treeish) = treeish {
            out.extend(text(&format!("treeish={treeish}")));
        }
        out.extend(text("can-delay=1"));
        out.extend_from_slice(b"0000");
        for chunk in content.chunks(MAX_PKT_DATA_BYTES) {
            out.extend(pkt(chunk));
        }
        out.extend_from_slice(b"0000");
        out
    }

    /// Parsed response: `Ok(content)` for success, `Err(())` for error.
    type Response = Result<Vec<u8>, ()>;

    /// Splits server output into the handshake packets and per-request
    /// responses.
    fn parse_output(bytes: &[u8]) -> (Vec<Option<String>>, Vec<Response>) {
        let mut reader = Cursor::new(bytes.to_vec());
        let mut buffer = vec![0_u8; MAX_PKT_DATA_BYTES];
        let mut handshake = Vec::new();
        for _ in 0..2 {
            let lines = must(read_text_list(&mut reader, &mut buffer), "read handshake");
            let lines = match lines {
                Some(lines) => lines,
                None => panic!("missing handshake list"),
            };
            handshake.extend(lines.into_iter().map(Some));
            handshake.push(None);
        }
        let mut responses = Vec::new();
        while let Some(status) = must(read_text_list(&mut reader, &mut buffer), "read status") {
            if status == ["status=error"] {
                responses.push(Err(()));
                continue;
            }
            assert_eq!(status, ["status=success"]);
            let content = match must(read_content(&mut reader, &mut buffer), "read content") {
                Some(content) => content.to_vec(),
                None => panic!("content too large"),
            };
            let trailer = must(read_text_list(&mut reader, &mut buffer), "read trailer");
            assert_eq!(
                trailer,
                Some(Vec::new()),
                "missing empty trailing status list"
            );
            responses.push(Ok(content));
        }
        (handshake, responses)
    }

    fn run(
        context: &mut FilterContext,
        input: Vec<u8>,
    ) -> (Vec<Option<String>>, Vec<Response>, String) {
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        let mut stderr = Vec::new();
        if let Err(err) = serve(context, &mut reader, &mut output, &mut stderr) {
            panic!("serve failed: {err:#}");
        }
        let (handshake, responses) = parse_output(&output);
        (
            handshake,
            responses,
            String::from_utf8_lossy(&stderr).into_owned(),
        )
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        alice: MemberIdentity,
        keys: GroupKeysFile,
    }

    fn git(root: &Path, args: &[&str]) {
        let output = must(
            Command::new("git").arg("-C").arg(root).args(args).output(),
            "run git",
        );
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A repository with `config/**` protected by group `finance`, whose only
    /// recipient is alice.
    fn fixture(init_git: bool) -> Fixture {
        let dir = must(tempfile::tempdir(), "tempdir");
        let root = dir.path().to_path_buf();
        if init_git {
            git(&root, &["init", "-q"]);
            git(&root, &["config", "user.email", "test@example.com"]);
            git(&root, &["config", "user.name", "Test"]);
        }
        let alice = MemberIdentity::generate();
        let key = must(GroupDataKey::generate(), "generate key");
        let mut recipients = BTreeMap::new();
        recipients.insert("alice".to_owned(), alice.public_key());
        let keys = must(
            GroupKeysFile::wrap_for_recipients("finance", 1, &key, &recipients),
            "wrap",
        );
        must(write_group_keys(&root, "finance", &keys), "write keys");
        let policy = must(
            PathPolicy::compile([must(PathRule::new("config/**", "finance"), "rule")]),
            "compile",
        );
        must(write_path_policy(&root, &policy), "write policy");
        Fixture {
            _dir: dir,
            root,
            alice,
            keys,
        }
    }

    fn context(fixture: &Fixture, identity: Option<MemberIdentity>) -> FilterContext {
        FilterContext::new(
            fixture.root.clone(),
            identity,
            "no identity configured".to_owned(),
        )
    }

    #[test]
    fn pkt_line_reader_validates_framing() {
        let mut buffer = vec![0_u8; MAX_PKT_DATA_BYTES];
        for bad in [&b"000g"[..], b"0001", b"0003", b"fff1", b"00"] {
            let mut reader = Cursor::new(bad.to_vec());
            assert!(read_packet(&mut reader, &mut buffer).is_err(), "{bad:?}");
        }
        let mut reader = Cursor::new(b"0004".to_vec());
        assert!(matches!(
            read_packet(&mut reader, &mut buffer),
            Ok(Some(Packet::Data(0)))
        ));
        let mut reader = Cursor::new(b"0009hello".to_vec());
        assert!(matches!(
            read_packet(&mut reader, &mut buffer),
            Ok(Some(Packet::Data(5)))
        ));
        assert_eq!(buffer.get(..5), Some(&b"hello"[..]));
        let mut reader = Cursor::new(Vec::new());
        assert!(matches!(read_packet(&mut reader, &mut buffer), Ok(None)));
        // Truncated payload.
        let mut reader = Cursor::new(b"0009hel".to_vec());
        assert!(read_packet(&mut reader, &mut buffer).is_err());

        let mut out = Vec::new();
        must(
            write_success(&mut out, &vec![7_u8; MAX_PKT_DATA_BYTES + 1]),
            "write",
        );
        assert!(out.starts_with(b"0013status=success\n0000fff0"));
        assert!(out.ends_with(b"0005\x0700000000"));
    }

    #[test]
    fn handshake_negotiates_offered_capabilities_and_rejects_bad_greetings() {
        let fixture = fixture(false);
        let mut ctx = context(&fixture, None);
        let (handshake, responses, _) = run(&mut ctx, handshake_bytes(&["clean", "delay"]));
        assert_eq!(
            handshake,
            vec![
                Some("git-filter-server".to_owned()),
                Some("version=2".to_owned()),
                None,
                Some("capability=clean".to_owned()),
                None,
            ]
        );
        assert!(responses.is_empty());

        let mut bad = Vec::new();
        bad.extend(text("git-filter-client"));
        bad.extend(text("version=3"));
        bad.extend_from_slice(b"0000");
        let mut reader = Cursor::new(bad);
        let mut output = Vec::new();
        let mut stderr = Vec::new();
        assert!(serve(&mut ctx, &mut reader, &mut output, &mut stderr).is_err());
    }

    #[test]
    fn clean_smudge_round_trip_placeholders_and_access_rules() {
        let fixture = fixture(false);
        let mut alice = context(&fixture, Some(fixture.alice.clone()));
        let mut bob = context(&fixture, Some(MemberIdentity::generate()));
        let mut nobody = context(&fixture, None);

        // Clean encrypts deterministically and never double-encrypts.
        let blob = must(alice.clean("config/app.env", SECRET), "clean").to_vec();
        assert!(blob.starts_with(b"SCRIMFILE\0"));
        assert!(!blob.windows(SECRET.len()).any(|window| window == SECRET));
        assert_eq!(
            must(alice.clean("config/app.env", SECRET), "clean").to_vec(),
            blob
        );
        assert_eq!(
            must(alice.clean("config/app.env", &blob), "clean").to_vec(),
            blob
        );

        // Public paths and non-encrypted content pass through unchanged.
        assert_eq!(
            must(alice.clean("README.md", b"hi"), "clean").to_vec(),
            b"hi"
        );
        assert_eq!(
            must(nobody.smudge("config/legacy", None, b"plain"), "smudge").to_vec(),
            b"plain"
        );

        // Members get plaintext; others get a placeholder that cleans back to
        // the identical blob.
        assert_eq!(
            must(alice.smudge("config/app.env", None, &blob), "smudge").to_vec(),
            SECRET
        );
        for ctx in [&mut bob, &mut nobody] {
            let shown = must(ctx.smudge("config/app.env", None, &blob), "smudge").to_vec();
            assert!(is_placeholder(&shown));
            assert!(!shown.windows(SECRET.len()).any(|window| window == SECRET));
            assert_eq!(
                must(ctx.clean("config/app.env", &shown), "clean").to_vec(),
                blob
            );
            // Moving the placeholder is refused.
            assert!(ctx.clean("config/moved.env", &shown).is_err());
            // Editing it is refused.
            let mut edited = shown.clone();
            edited.extend_from_slice(b"extra\n");
            assert!(ctx.clean("config/app.env", &edited).is_err());
            // Replacing it with plaintext is refused for non-members.
            assert!(ctx.clean("config/app.env", b"overwritten").is_err());
        }

        // A member decrypting a blob moved to another path fails loudly.
        assert!(alice.smudge("config/other.env", None, &blob).is_err());
        // A malformed blob is an error, not a placeholder.
        assert!(
            nobody
                .smudge("config/app.env", None, b"SCRIMFILE\0x")
                .is_err()
        );
    }

    #[test]
    fn serve_reports_per_file_errors_and_keeps_going() {
        let fixture = fixture(false);
        let mut bob = context(&fixture, Some(MemberIdentity::generate()));
        let mut input = handshake_bytes(&["clean", "smudge"]);
        input.extend(request_bytes(
            "clean",
            "config/a.env",
            None,
            b"super-secret-content",
        ));
        input.extend(request_bytes("clean", "notes.txt", None, b"public"));
        let (_, responses, stderr) = run(&mut bob, input);
        assert_eq!(responses, vec![Err(()), Ok(b"public".to_vec())]);
        assert!(stderr.contains("config/a.env"));
        assert!(stderr.contains("not a member"));
        assert!(!stderr.contains("super-secret-content"));
    }

    #[test]
    fn smudge_finds_older_generation_keys_in_git_history() {
        let fixture = fixture(true);
        let root = fixture.root.clone();
        let mut alice = context(&fixture, Some(fixture.alice.clone()));
        let blob_v1 = must(alice.clean("config/app.env", SECRET), "clean").to_vec();
        git(&root, &["add", ".scrim"]);
        git(&root, &["commit", "-q", "-m", "gen1"]);
        let head_v1 = {
            let output = must(
                Command::new("git")
                    .arg("-C")
                    .arg(&root)
                    .args(["rev-parse", "HEAD"])
                    .output(),
                "rev-parse",
            );
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };

        // Rotate to generation 2 on disk and commit it.
        let mut recipients = BTreeMap::new();
        recipients.insert("alice".to_owned(), fixture.alice.public_key());
        let rotated = must(
            rotate_group_key("finance", &fixture.keys, &fixture.alice, &recipients),
            "rotate",
        );
        must(
            write_group_keys(&root, "finance", &rotated.keys_file),
            "write keys",
        );
        git(&root, &["commit", "-q", "-am", "gen2"]);

        // A fresh process finds generation 1 through HEAD~1 via treeish...
        let mut fresh = context(&fixture, Some(fixture.alice.clone()));
        assert!(
            fresh
                .smudge("config/app.env", Some("--bad"), &blob_v1)
                .is_ok_and(|out| is_placeholder(&out))
        );
        let mut fresh = context(&fixture, Some(fixture.alice.clone()));
        let plaintext = must(
            fresh.smudge("config/app.env", Some(&head_v1), &blob_v1),
            "smudge",
        );
        assert_eq!(plaintext.to_vec(), SECRET);

        // ...and through HEAD when the working-tree key file is missing.
        let mut fresh = context(&fixture, Some(fixture.alice.clone()));
        let blob_v2 = must(fresh.clean("config/app.env", SECRET), "clean").to_vec();
        must(fs::remove_dir_all(root.join(".scrim")), "remove .scrim");
        let mut fresh = context(&fixture, Some(fixture.alice.clone()));
        assert_eq!(
            must(fresh.smudge("config/app.env", None, &blob_v2), "smudge").to_vec(),
            SECRET
        );
        // Clean also falls back to HEAD for the policy and key file.
        assert_eq!(
            must(fresh.clean("config/app.env", SECRET), "clean").to_vec(),
            blob_v2
        );
    }
}
