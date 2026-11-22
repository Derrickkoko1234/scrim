//! Readable placeholders that non-members check out instead of a private
//! file.
//!
//! A placeholder explains why the file is unreadable and embeds the encrypted
//! blob verbatim as wrapped base64, so the clean filter can restore the exact
//! original Git object and an untouched placeholder never shows up as a
//! modification:
//!
//! ```text
//! # scrim: encrypted private file (access denied)
//! # group: <group>
//! # generation: <generation>
//! # path: <repo_relative_path>
//! # Ask an administrator to add you to group '<group>', run 'scrim keygen', and re-checkout.
//! # Do not edit below this line; Scrim preserves this encrypted block so 'git status' stays clean.
//! -----BEGIN SCRIM ENCRYPTED BLOB-----
//! <standard base64, 76 characters per line>
//! -----END SCRIM ENCRYPTED BLOB-----
//! ```
//!
//! The `# path:` line is informational: the blob header does not record the
//! path, but its associated data binds it, so decryption under any other path
//! fails.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::file_crypto::MAX_ENCRYPTED_FILE_BYTES;
use crate::{
    CryptoError, EncryptedFileHeader, MAX_FILE_PATH_BYTES, parse_encrypted_file_header,
    validate_file_path,
};

/// Start of every placeholder; also the [`is_placeholder`] prefix.
const PLACEHOLDER_PREFIX: &str = "# scrim: encrypted private file";
/// The complete first line of a placeholder.
const TITLE_LINE: &str = "# scrim: encrypted private file (access denied)";
const GROUP_PREFIX: &str = "# group: ";
const GENERATION_PREFIX: &str = "# generation: ";
const PATH_PREFIX: &str = "# path: ";
const PRESERVE_LINE: &str = "# Do not edit below this line; Scrim preserves this encrypted block so 'git status' stays clean.";
const BEGIN_MARKER: &str = "-----BEGIN SCRIM ENCRYPTED BLOB-----";
const END_MARKER: &str = "-----END SCRIM ENCRYPTED BLOB-----";
/// Base64 characters per line inside the blob block (the MIME line length).
const BASE64_LINE_CHARS: usize = 76;
/// Lines before the first base64 line: title, group, generation, path,
/// advice, preservation notice and the begin marker.
const HEADER_LINES: usize = 7;

/// Upper bound on a well-formed placeholder, checked before decoding base64 so
/// oversized fake placeholders cannot force large allocations.
const MAX_BASE64_CHARS: usize = MAX_ENCRYPTED_FILE_BYTES.div_ceil(3) * 4;
const MAX_PLACEHOLDER_BYTES: usize = MAX_BASE64_CHARS
    + (MAX_BASE64_CHARS / BASE64_LINE_CHARS + HEADER_LINES + 4) * 2
    + MAX_FILE_PATH_BYTES
    + 1024;

/// The parsed metadata and raw encrypted blob recovered from a placeholder by
/// [`extract_placeholder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedPlaceholder {
    /// Repo-relative path recorded on the placeholder's `# path:` line.
    pub path: String,
    /// Validated header of the embedded `SCRIMFILE\0` blob.
    pub header: EncryptedFileHeader,
    /// Exact original encrypted blob bytes.
    pub blob: Vec<u8>,
}

/// Formats the placeholder a non-member sees for `repo_relative_path`,
/// embedding `encrypted_blob` verbatim. Lines end in `\n`, including the last.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidFilePath`] for an invalid path, or the
/// header error from [`parse_encrypted_file_header`] when `encrypted_blob`
/// is not an encrypted private file.
pub fn format_placeholder(
    repo_relative_path: &str,
    encrypted_blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if let Err(error) = validate_file_path(repo_relative_path) {
        return Err(error);
    }
    let header = match parse_encrypted_file_header(encrypted_blob) {
        Ok(header) => header,
        Err(error) => return Err(error),
    };
    let group = header.group;
    let encoded = BASE64.encode(encrypted_blob);
    let mut output = format!(
        "{TITLE_LINE}\n\
         {GROUP_PREFIX}{group}\n\
         {GENERATION_PREFIX}{generation}\n\
         {PATH_PREFIX}{repo_relative_path}\n\
         # Ask an administrator to add you to group '{group}', run 'scrim keygen', and re-checkout.\n\
         {PRESERVE_LINE}\n\
         {BEGIN_MARKER}\n",
        generation = header.generation,
    )
    .into_bytes();
    output.reserve(encoded.len() + encoded.len() / BASE64_LINE_CHARS + END_MARKER.len() + 2);
    for line in encoded.as_bytes().chunks(BASE64_LINE_CHARS) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(END_MARKER.as_bytes());
    output.push(b'\n');
    Ok(output)
}

/// Returns whether `bytes` looks like a placeholder: it starts with the
/// placeholder title and contains the begin marker. This is a cheap filter;
/// [`extract_placeholder_blob`] does the full validation.
pub fn is_placeholder(bytes: &[u8]) -> bool {
    bytes.starts_with(PLACEHOLDER_PREFIX.as_bytes())
        && bytes
            .windows(BEGIN_MARKER.len())
            .any(|window| window == BEGIN_MARKER.as_bytes())
}

/// Recovers the exact encrypted blob embedded in a placeholder made by
/// [`format_placeholder`].
///
/// See [`extract_placeholder`] for validation details.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPlaceholder`] when the input is oversized,
/// edited, truncated, missing a marker, has trailing content, carries
/// corrupted base64, or its metadata disagrees with the embedded blob.
pub fn extract_placeholder_blob(bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match extract_placeholder(bytes) {
        Ok(extracted) => Ok(extracted.blob),
        Err(error) => Err(error),
    }
}

/// Recovers the recorded path, parsed blob header, and exact encrypted blob
/// embedded in a placeholder made by [`format_placeholder`].
///
/// Accepts `\n` or `\r\n` line endings (for `core.autocrlf`) and an optional
/// final line ending, but otherwise requires the placeholder to be exactly
/// what [`format_placeholder`] would produce for the embedded blob, so the
/// metadata lines must match the blob header.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPlaceholder`] when the input is oversized,
/// edited, truncated, missing a marker, has trailing content, carries
/// corrupted base64, or its metadata disagrees with the embedded blob.
pub fn extract_placeholder(bytes: &[u8]) -> Result<ExtractedPlaceholder, CryptoError> {
    let reject = |reason| Err(CryptoError::InvalidPlaceholder { reason });
    if bytes.len() > MAX_PLACEHOLDER_BYTES {
        return reject("placeholder exceeds the private file size limit");
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return reject("placeholder is not UTF-8");
    };
    let body = match text.strip_suffix('\n') {
        Some(body) => body,
        None => text,
    };
    let lines: Vec<&str> = body
        .split('\n')
        .map(|line| match line.strip_suffix('\r') {
            Some(line) => line,
            None => line,
        })
        .collect();
    if lines.first() != Some(&TITLE_LINE) {
        return reject("missing placeholder title line");
    }
    if lines.get(HEADER_LINES - 1) != Some(&BEGIN_MARKER) {
        return reject("missing begin marker");
    }
    if lines.last() != Some(&END_MARKER) || lines.len() <= HEADER_LINES {
        return reject("missing end marker or trailing content after it");
    }
    let field = |index: usize, prefix: &str| match lines.get(index) {
        Some(line) => line.strip_prefix(prefix),
        None => None,
    };
    let Some(group) = field(1, GROUP_PREFIX) else {
        return reject("missing group line");
    };
    let Some(generation) = field(2, GENERATION_PREFIX) else {
        return reject("missing generation line");
    };
    let Some(path) = field(3, PATH_PREFIX) else {
        return reject("missing path line");
    };
    let Some(base64_lines) = lines.get(HEADER_LINES..lines.len() - 1) else {
        return reject("missing encrypted block");
    };
    let encoded_len: usize = base64_lines.iter().map(|line| line.len()).sum();
    if encoded_len > MAX_BASE64_CHARS {
        return reject("encrypted block exceeds the private file size limit");
    }
    let blob = match BASE64.decode(base64_lines.concat()) {
        Ok(blob) => blob,
        Err(_) => return reject("encrypted block is not valid base64"),
    };
    let header = match parse_encrypted_file_header(&blob) {
        Ok(header) => header,
        Err(_) => return reject("encrypted block is not a valid encrypted file"),
    };
    if header.group != group {
        return reject("group line does not match the encrypted block");
    }
    if header.generation.to_string() != generation {
        return reject("generation line does not match the encrypted block");
    }
    // Re-rendering catches every other edit (advice text, line wrapping,
    // invalid path) in one comparison, keeping the format canonical.
    let canonical = match format_placeholder(path, &blob) {
        Ok(canonical) => canonical,
        Err(_) => return reject("path line is not a valid repo-relative path"),
    };
    let mut normalized = lines.join("\n").into_bytes();
    normalized.push(b'\n');
    if canonical != normalized {
        return reject("placeholder was edited");
    }
    Ok(ExtractedPlaceholder {
        path: path.to_owned(),
        header,
        blob,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_crypto::tests::encrypt;
    use crate::group_key::tests::group_key;

    fn sample_blob(plaintext: &[u8]) -> Vec<u8> {
        encrypt("backend", 12, "config/prod.env", &group_key(), plaintext)
    }

    fn placeholder(blob: &[u8]) -> Vec<u8> {
        match format_placeholder("config/prod.env", blob) {
            Ok(placeholder) => placeholder,
            Err(error) => panic!("formatting should succeed: {error}"),
        }
    }

    fn text_of(bytes: Vec<u8>) -> String {
        match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => panic!("placeholder should be UTF-8: {error}"),
        }
    }

    fn expect_invalid(bytes: &[u8]) {
        match extract_placeholder_blob(bytes) {
            Err(CryptoError::InvalidPlaceholder { .. }) => {}
            other => panic!("expected InvalidPlaceholder, got {other:?}"),
        }
    }

    #[test]
    fn placeholder_round_trips_the_exact_blob() {
        for plaintext in [&b""[..], &[7_u8; 1000][..]] {
            let blob = sample_blob(plaintext);
            let formatted = placeholder(&blob);
            assert!(is_placeholder(&formatted));
            match extract_placeholder(&formatted) {
                Ok(extracted) => {
                    assert_eq!(extracted.path, "config/prod.env");
                    assert_eq!(extracted.header.group, "backend");
                    assert_eq!(extracted.header.generation, 12);
                    assert_eq!(extracted.blob, blob);
                }
                Err(error) => panic!("extraction should succeed: {error}"),
            }
            match extract_placeholder_blob(&formatted) {
                Ok(extracted) => assert_eq!(extracted, blob),
                Err(error) => panic!("extraction should succeed: {error}"),
            }
            let text = text_of(formatted);
            assert!(text.starts_with(
                "# scrim: encrypted private file (access denied)\n# group: backend\n\
                 # generation: 12\n# path: config/prod.env\n\
                 # Ask an administrator to add you to group 'backend', run 'scrim keygen', and re-checkout.\n"
            ));
            assert!(text.ends_with("-----END SCRIM ENCRYPTED BLOB-----\n"));
            assert!(text.lines().all(|line| line.len() <= 100));
        }
    }

    #[test]
    fn crlf_and_missing_final_newline_are_tolerated() {
        let blob = sample_blob(&[1_u8; 300]);
        let text = text_of(placeholder(&blob));
        let crlf = text.replace('\n', "\r\n");
        let trimmed = text.trim_end_matches('\n').to_owned();
        for variant in [crlf, trimmed] {
            match extract_placeholder_blob(variant.as_bytes()) {
                Ok(extracted) => assert_eq!(extracted, blob),
                Err(error) => panic!("extraction should succeed: {error}"),
            }
        }
    }

    #[test]
    fn edited_or_corrupted_placeholders_are_rejected() {
        let blob = sample_blob(b"secret contents");
        let text = text_of(placeholder(&blob));
        let edits = [
            text.replace("# group: backend", "# group: finance"),
            text.replace("# generation: 12", "# generation: 11"),
            text.replace("# path: config/prod.env", "# path: /etc/passwd"),
            text.replace("Ask an administrator", "Ask nobody"),
            text.replace(BEGIN_MARKER, "-----BEGIN SOMETHING-----"),
            text.replace(END_MARKER, ""),
            format!("{text}trailing garbage\n"),
            format!("{text}\n"),
            // Corrupted base64 in the encrypted block.
            text.replacen(
                &format!("{BEGIN_MARKER}\n"),
                &format!("{BEGIN_MARKER}\n!!!!"),
                1,
            ),
        ];
        for edited in &edits {
            expect_invalid(edited.as_bytes());
        }
        // Truncating the encrypted block, or re-wrapping it, is rejected too.
        let lines: Vec<&str> = text.lines().collect();
        let mut truncated: Vec<&str> = lines.clone();
        truncated.remove(HEADER_LINES);
        expect_invalid(format!("{}\n", truncated.join("\n")).as_bytes());
        let Some(head) = lines.get(..HEADER_LINES) else {
            panic!("placeholder should have a full header");
        };
        let encoded = BASE64.encode(&blob);
        assert!(encoded.len() > BASE64_LINE_CHARS);
        let rewrapped = format!("{}\n{encoded}\n{END_MARKER}\n", head.join("\n"));
        expect_invalid(rewrapped.as_bytes());
        expect_invalid(b"not a placeholder");
        expect_invalid(&[0xff, 0xfe]);
    }

    #[test]
    fn format_rejects_non_encrypted_input_and_bad_paths() {
        match format_placeholder("notes.txt", b"plain text, not a SCRIMFILE blob") {
            Err(CryptoError::InvalidEncryptedFile { .. }) => {}
            other => panic!("expected InvalidEncryptedFile, got {other:?}"),
        }
        match format_placeholder("../notes.txt", &sample_blob(b"x")) {
            Err(CryptoError::InvalidFilePath { .. }) => {}
            other => panic!("expected InvalidFilePath, got {other:?}"),
        }
        assert!(!is_placeholder(
            b"# scrim: encrypted private file but no block"
        ));
        assert!(!is_placeholder(b"ordinary file"));
    }
}
