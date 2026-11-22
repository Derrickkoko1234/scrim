//! Dotenv output for `scrim secrets export --format dotenv`.

use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::SecretBundle;

/// Formats `secrets` as `KEY=VALUE` lines, sorted by key.
///
/// Values made only of `[A-Za-z0-9_./:@%+,=-]` are written bare. Every other
/// value, including the empty value, is double-quoted with `\\`, `\"`, `\n`,
/// `\r`, `\$` and `` \` `` escapes, so neither a dotenv parser nor a shell
/// sourcing the file can split, expand or execute it. Keys need no quoting
/// because [`SecretBundle`] only holds valid environment variable names.
///
/// The output buffer is zeroized on drop.
pub fn format_dotenv(secrets: &SecretBundle) -> Zeroizing<String> {
    // Escaping at most doubles a value; reserving the worst case up front
    // means the buffer never reallocates and strands an unzeroized copy.
    let capacity = secrets
        .iter()
        .map(|(key, value)| key.len() + value.expose_secret().len() * 2 + 4)
        .sum();
    let mut output = Zeroizing::new(String::with_capacity(capacity));
    for (key, value) in secrets.iter() {
        let value = value.expose_secret();
        output.push_str(key);
        output.push('=');
        if !value.is_empty() && value.bytes().all(is_bare_safe) {
            output.push_str(value);
        } else {
            output.push('"');
            for character in value.chars() {
                match character {
                    '\\' => output.push_str("\\\\"),
                    '"' => output.push_str("\\\""),
                    '\n' => output.push_str("\\n"),
                    '\r' => output.push_str("\\r"),
                    '$' => output.push_str("\\$"),
                    '`' => output.push_str("\\`"),
                    other => output.push(other),
                }
            }
            output.push('"');
        }
        output.push('\n');
    }
    output
}

/// Whether `byte` may appear in an unquoted dotenv value.
fn is_bare_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b',' | b'=' | b'-'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::tests::bundle;

    #[test]
    fn formats_sorted_lines_with_safe_quoting() {
        let secrets = bundle(&[
            ("PLAIN", "abc-123_x.y/z:8080@host%2B+a,b=c"),
            ("EMPTY", ""),
            ("SPACES", "hello world"),
            ("NEWLINES", "line1\nline2\r\n"),
            ("QUOTES", "say \"hi\" 'there'"),
            ("DOLLAR", "$HOME and ${PATH}"),
            ("BACKSLASH", "C:\\dir\\"),
            ("BACKTICK", "`rm -rf /`"),
            ("HASH", "abc#comment"),
            ("UNICODE", "pässwörd"),
        ]);
        let expected = concat!(
            "BACKSLASH=\"C:\\\\dir\\\\\"\n",
            "BACKTICK=\"\\`rm -rf /\\`\"\n",
            "DOLLAR=\"\\$HOME and \\${PATH}\"\n",
            "EMPTY=\"\"\n",
            "HASH=\"abc#comment\"\n",
            "NEWLINES=\"line1\\nline2\\r\\n\"\n",
            "PLAIN=abc-123_x.y/z:8080@host%2B+a,b=c\n",
            "QUOTES=\"say \\\"hi\\\" 'there'\"\n",
            "SPACES=\"hello world\"\n",
            "UNICODE=\"pässwörd\"\n",
        );
        assert_eq!(format_dotenv(&secrets).as_str(), expected);
    }

    #[test]
    fn empty_bundle_formats_as_empty_string() {
        assert_eq!(format_dotenv(&bundle(&[])).as_str(), "");
    }
}
