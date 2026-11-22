//! Deterministic AES-256-SIV encryption of private files into the binary
//! blobs Scrim stores in Git's object store.
//!
//! A blob is a big-endian header followed by the RFC 5297 SIV output:
//!
//! ```text
//! magic "SCRIMFILE\0" (10) || version u32 || generation u64
//!     || group_len u16 || group || SIV tag (16) || ciphertext
//! ```
//!
//! The SIV associated data is the vector
//! `["scrim-file-v1", group, generation (u64 BE), repo_relative_path]`; S2V
//! authenticates each element separately, so element boundaries are
//! unambiguous. Encryption is deterministic, so the same key, group,
//! generation, path and plaintext always produce byte-identical blobs and Git
//! sees no change when an unmodified file is re-cleaned. The only thing this
//! reveals is whether two encryptions of the same path under the same key
//! have identical content.

use aes_siv::KeyInit;
use aes_siv::siv::Aes256Siv;
use zeroize::Zeroizing;

use crate::validation::{validate_generation, validate_version};
use crate::{
    CryptoError, FILE_FORMAT_VERSION, GroupDataKey, MAX_GROUP_NAME_BYTES, MAX_PRIVATE_FILE_BYTES,
    validate_file_path, validate_group_name,
};

/// Prefix of every encrypted private file blob. The embedded NUL makes Git
/// treat stored blobs as binary, so it never applies text conversions to them.
pub const ENCRYPTED_FILE_MAGIC: &[u8] = b"SCRIMFILE\x00";

/// First associated-data element, naming the format and its version.
const FILE_AAD_DOMAIN: &[u8] = b"scrim-file-v1";

/// Length of the SIV tag that starts the ciphertext, in bytes.
const SIV_TAG_BYTES: usize = 16;

/// Header bytes before the group name: magic, version, generation and
/// group length.
const FIXED_HEADER_BYTES: usize = ENCRYPTED_FILE_MAGIC.len() + 4 + 8 + 2;

/// Largest well-formed blob: the longest header, the tag and the largest
/// accepted plaintext.
pub(crate) const MAX_ENCRYPTED_FILE_BYTES: usize =
    FIXED_HEADER_BYTES + MAX_GROUP_NAME_BYTES + SIV_TAG_BYTES + MAX_PRIVATE_FILE_BYTES;

/// The cleartext header of an encrypted private file blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFileHeader {
    /// Blob format version; always [`FILE_FORMAT_VERSION`] once parsed.
    pub version: u32,
    /// Group whose data key encrypted the file.
    pub group: String,
    /// Generation of that group data key.
    pub generation: u64,
}

/// Returns whether `bytes` starts with [`ENCRYPTED_FILE_MAGIC`]. This is a
/// cheap filter, not a validity check; use [`parse_encrypted_file_header`]
/// for that.
pub fn is_encrypted_file(bytes: &[u8]) -> bool {
    bytes.starts_with(ENCRYPTED_FILE_MAGIC)
}

/// Parses and validates the header of an encrypted private file blob.
///
/// Checks the magic, size limit, version, generation and group name, and that
/// at least a full SIV tag follows the header. The ciphertext itself is only
/// authenticated by [`decrypt_file`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidEncryptedFile`] for a malformed or oversized
/// blob, [`CryptoError::UnsupportedVersion`],
/// [`CryptoError::InvalidGeneration`] or [`CryptoError::InvalidGroupName`].
pub fn parse_encrypted_file_header(bytes: &[u8]) -> Result<EncryptedFileHeader, CryptoError> {
    match split_encrypted_file(bytes) {
        Ok((header, _)) => Ok(header),
        Err(error) => Err(error),
    }
}

/// Encrypts `plaintext` deterministically under `data_key`, bound to `group`,
/// `generation` and `repo_relative_path`, and returns the complete blob.
///
/// Empty files are supported.
///
/// # Errors
///
/// Fails on an invalid group, generation 0, an invalid path, a plaintext
/// larger than [`MAX_PRIVATE_FILE_BYTES`] ([`CryptoError::FileTooLarge`]),
/// or an encryption failure.
pub fn encrypt_file(
    group: &str,
    generation: u64,
    repo_relative_path: &str,
    data_key: &GroupDataKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if let Err(error) = validate_group_name(group) {
        return Err(error);
    }
    if let Err(error) = validate_generation(generation) {
        return Err(error);
    }
    if let Err(error) = validate_file_path(repo_relative_path) {
        return Err(error);
    }
    if plaintext.len() > MAX_PRIVATE_FILE_BYTES {
        return Err(CryptoError::FileTooLarge {
            max_bytes: MAX_PRIVATE_FILE_BYTES,
        });
    }
    let Ok(group_len) = u16::try_from(group.len()) else {
        return Err(CryptoError::InvalidGroupName {
            group: group.to_owned(),
            reason: "group name is too long",
        });
    };
    let mut cipher = match Aes256Siv::new_from_slice(data_key.as_bytes()) {
        Ok(cipher) => cipher,
        Err(error) => return Err(CryptoError::Encryption(error.to_string())),
    };
    let generation_bytes = generation.to_be_bytes();
    let associated_data = [
        FILE_AAD_DOMAIN,
        group.as_bytes(),
        &generation_bytes,
        repo_relative_path.as_bytes(),
    ];
    // `encrypt` sizes its buffer for the tag up front, so the plaintext copy
    // it makes is overwritten in place by ciphertext and never reallocated.
    let ciphertext = match cipher.encrypt(associated_data, plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(error) => return Err(CryptoError::Encryption(error.to_string())),
    };
    let mut blob = Vec::with_capacity(FIXED_HEADER_BYTES + group.len() + ciphertext.len());
    blob.extend_from_slice(ENCRYPTED_FILE_MAGIC);
    blob.extend_from_slice(&FILE_FORMAT_VERSION.to_be_bytes());
    blob.extend_from_slice(&generation_bytes);
    blob.extend_from_slice(&group_len.to_be_bytes());
    blob.extend_from_slice(group.as_bytes());
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypts a blob produced by [`encrypt_file`], checking that it belongs to
/// `expected_group` at `expected_generation` and was encrypted for
/// `expected_path`.
///
/// # Errors
///
/// Returns header errors from [`parse_encrypted_file_header`],
/// [`CryptoError::GroupMismatch`], [`CryptoError::GenerationMismatch`],
/// [`CryptoError::InvalidFilePath`], or [`CryptoError::FileDecryptionFailed`]
/// when authentication fails (wrong key, wrong path, or tampered blob).
pub fn decrypt_file(
    expected_group: &str,
    expected_generation: u64,
    expected_path: &str,
    data_key: &GroupDataKey,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (header, ciphertext) = match split_encrypted_file(blob) {
        Ok(parts) => parts,
        Err(error) => return Err(error),
    };
    if header.group != expected_group {
        return Err(CryptoError::GroupMismatch {
            expected: expected_group.to_owned(),
            found: header.group,
        });
    }
    if header.generation != expected_generation {
        return Err(CryptoError::GenerationMismatch {
            expected: expected_generation,
            found: header.generation,
        });
    }
    if let Err(error) = validate_file_path(expected_path) {
        return Err(error);
    }
    let mut cipher = match Aes256Siv::new_from_slice(data_key.as_bytes()) {
        Ok(cipher) => cipher,
        Err(_) => return Err(CryptoError::FileDecryptionFailed),
    };
    let generation_bytes = header.generation.to_be_bytes();
    let associated_data = [
        FILE_AAD_DOMAIN,
        header.group.as_bytes(),
        &generation_bytes,
        expected_path.as_bytes(),
    ];
    // Decrypting in place into a zeroizing buffer keeps the plaintext out of
    // unzeroized memory; the buffer only shrinks, so it never reallocates.
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    match cipher.decrypt_in_place(associated_data, &mut *buffer) {
        Ok(()) => Ok(buffer),
        Err(_) => Err(CryptoError::FileDecryptionFailed),
    }
}

/// Validates a blob's header and splits off the SIV output (tag and
/// ciphertext) that follows it.
fn split_encrypted_file(bytes: &[u8]) -> Result<(EncryptedFileHeader, &[u8]), CryptoError> {
    let reject = |reason| Err(CryptoError::InvalidEncryptedFile { reason });
    let Some(rest) = bytes.strip_prefix(ENCRYPTED_FILE_MAGIC) else {
        return reject("missing SCRIMFILE magic");
    };
    if bytes.len() > MAX_ENCRYPTED_FILE_BYTES {
        return reject("blob exceeds the private file size limit");
    }
    let Some((version_bytes, rest)) = rest.split_first_chunk::<4>() else {
        return reject("truncated header");
    };
    let version = u32::from_be_bytes(*version_bytes);
    if let Err(error) = validate_version(version) {
        return Err(error);
    }
    let Some((generation_bytes, rest)) = rest.split_first_chunk::<8>() else {
        return reject("truncated header");
    };
    let generation = u64::from_be_bytes(*generation_bytes);
    if let Err(error) = validate_generation(generation) {
        return Err(error);
    }
    let Some((group_len_bytes, rest)) = rest.split_first_chunk::<2>() else {
        return reject("truncated header");
    };
    let group_len = usize::from(u16::from_be_bytes(*group_len_bytes));
    if group_len == 0 || group_len > MAX_GROUP_NAME_BYTES {
        return reject("group name length is out of range");
    }
    let Some((group_bytes, ciphertext)) = rest.split_at_checked(group_len) else {
        return reject("truncated header");
    };
    let Ok(group) = std::str::from_utf8(group_bytes) else {
        return reject("group name is not UTF-8");
    };
    if let Err(error) = validate_group_name(group) {
        return Err(error);
    }
    if ciphertext.len() < SIV_TAG_BYTES {
        return reject("truncated SIV tag");
    }
    let header = EncryptedFileHeader {
        version,
        group: group.to_owned(),
        generation,
    };
    Ok((header, ciphertext))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::group_key::tests::group_key;
    use crate::scope_key::tests::ErrorCheck;

    pub(crate) fn encrypt(
        group: &str,
        generation: u64,
        path: &str,
        key: &GroupDataKey,
        plaintext: &[u8],
    ) -> Vec<u8> {
        match encrypt_file(group, generation, path, key, plaintext) {
            Ok(blob) => blob,
            Err(error) => panic!("encryption should succeed: {error}"),
        }
    }

    fn expect_decrypt_error(
        result: Result<Zeroizing<Vec<u8>>, CryptoError>,
        is_expected: fn(&CryptoError) -> bool,
    ) {
        match result {
            Err(error) if is_expected(&error) => {}
            Err(error) => panic!("unexpected error: {error:?}"),
            Ok(_) => panic!("decryption should fail"),
        }
    }

    fn is_decryption_failure(error: &CryptoError) -> bool {
        matches!(error, CryptoError::FileDecryptionFailed)
    }

    #[test]
    fn encryption_is_deterministic() {
        let key = group_key();
        let first = encrypt("backend", 1, "config/db.yml", &key, b"password: hunter2\n");
        let second = encrypt("backend", 1, "config/db.yml", &key, b"password: hunter2\n");
        assert_eq!(first, second);
        let other_path = encrypt("backend", 1, "config/db2.yml", &key, b"password: hunter2\n");
        assert_ne!(first, other_path);
        let other_content = encrypt("backend", 1, "config/db.yml", &key, b"password: hunter3\n");
        assert_ne!(first, other_content);
    }

    #[test]
    fn empty_binary_and_utf8_files_round_trip() {
        let key = group_key();
        let binary: Vec<u8> = (0..=255_u8).cycle().take(4099).collect();
        let utf8 = "caf\u{e9} \u{1f512}\r\nline two\n".as_bytes();
        for plaintext in [&b""[..], &binary, utf8] {
            let blob = encrypt("backend", 2, "a/b.bin", &key, plaintext);
            assert!(is_encrypted_file(&blob));
            assert_eq!(
                blob.len(),
                FIXED_HEADER_BYTES + "backend".len() + SIV_TAG_BYTES + plaintext.len()
            );
            match parse_encrypted_file_header(&blob) {
                Ok(header) => assert_eq!(
                    header,
                    EncryptedFileHeader {
                        version: FILE_FORMAT_VERSION,
                        group: "backend".to_owned(),
                        generation: 2,
                    }
                ),
                Err(error) => panic!("header should parse: {error}"),
            }
            match decrypt_file("backend", 2, "a/b.bin", &key, &blob) {
                Ok(decrypted) => assert_eq!(decrypted.as_slice(), plaintext),
                Err(error) => panic!("decryption should succeed: {error}"),
            }
        }
    }

    #[test]
    fn tampered_ciphertext_or_tag_fails() {
        let key = group_key();
        let blob = encrypt("backend", 1, "f.txt", &key, b"top secret");
        let header_len = FIXED_HEADER_BYTES + "backend".len();
        for index in [header_len, header_len + SIV_TAG_BYTES, blob.len() - 1] {
            let mut tampered = blob.clone();
            if let Some(byte) = tampered.get_mut(index) {
                *byte ^= 0x01;
            }
            expect_decrypt_error(
                decrypt_file("backend", 1, "f.txt", &key, &tampered),
                is_decryption_failure,
            );
        }
    }

    #[test]
    fn blob_copied_to_another_path_fails() {
        let key = group_key();
        let blob = encrypt("backend", 1, "prod/secret.env", &key, b"KEY=1");
        expect_decrypt_error(
            decrypt_file("backend", 1, "dev/secret.env", &key, &blob),
            is_decryption_failure,
        );
        expect_decrypt_error(
            decrypt_file("backend", 1, "../prod/secret.env", &key, &blob),
            |e| matches!(e, CryptoError::InvalidFilePath { .. }),
        );
    }

    #[test]
    fn relabelled_group_or_generation_fails() {
        let key = group_key();
        let blob = encrypt("backend", 3, "f.txt", &key, b"data");
        expect_decrypt_error(decrypt_file("finance", 3, "f.txt", &key, &blob), |e| {
            matches!(e, CryptoError::GroupMismatch { .. })
        });
        expect_decrypt_error(decrypt_file("backend", 4, "f.txt", &key, &blob), |e| {
            matches!(e, CryptoError::GenerationMismatch { .. })
        });

        // Rewriting the header's group (same length) or generation is caught
        // by the associated data even when the caller expects the new label.
        let mut regrouped = blob.clone();
        let group_start = FIXED_HEADER_BYTES;
        regrouped.splice(group_start..group_start + 7, b"finance".iter().copied());
        expect_decrypt_error(
            decrypt_file("finance", 3, "f.txt", &key, &regrouped),
            is_decryption_failure,
        );
        let mut regenerated = blob.clone();
        let generation_start = ENCRYPTED_FILE_MAGIC.len() + 4;
        regenerated.splice(
            generation_start..generation_start + 8,
            4_u64.to_be_bytes().iter().copied(),
        );
        expect_decrypt_error(
            decrypt_file("backend", 4, "f.txt", &key, &regenerated),
            is_decryption_failure,
        );
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt("backend", 1, "f.txt", &group_key(), b"data");
        expect_decrypt_error(
            decrypt_file("backend", 1, "f.txt", &group_key(), &blob),
            is_decryption_failure,
        );
    }

    #[test]
    fn encrypt_rejects_bad_inputs() {
        let key = group_key();
        let cases: [(&str, u64, &str, ErrorCheck); 3] = [
            ("../x", 1, "f", |e| {
                matches!(e, CryptoError::InvalidGroupName { .. })
            }),
            ("backend", 0, "f", |e| {
                matches!(e, CryptoError::InvalidGeneration)
            }),
            ("backend", 1, "/f", |e| {
                matches!(e, CryptoError::InvalidFilePath { .. })
            }),
        ];
        for (group, generation, path, is_expected) in cases {
            match encrypt_file(group, generation, path, &key, b"x") {
                Err(error) if is_expected(&error) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        }
        let oversized = vec![0_u8; MAX_PRIVATE_FILE_BYTES + 1];
        match encrypt_file("backend", 1, "big.bin", &key, &oversized) {
            Err(CryptoError::FileTooLarge { .. }) => {}
            other => panic!("expected FileTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn malformed_blobs_are_rejected_cleanly() {
        let key = group_key();
        let blob = encrypt("backend", 1, "f.txt", &key, b"");
        let header_len = FIXED_HEADER_BYTES + "backend".len();

        let mut bad_magic = blob.clone();
        if let Some(byte) = bad_magic.first_mut() {
            *byte = b'X';
        }
        let mut bad_version = blob.clone();
        bad_version.splice(10..14, 2_u32.to_be_bytes().iter().copied());
        let mut zero_generation = blob.clone();
        zero_generation.splice(14..22, 0_u64.to_be_bytes().iter().copied());
        let mut zero_group_len = blob.clone();
        zero_group_len.splice(22..24, 0_u16.to_be_bytes().iter().copied());
        let mut long_group_len = blob.clone();
        long_group_len.splice(22..24, 65_u16.to_be_bytes().iter().copied());
        let mut bad_group = blob.clone();
        bad_group.splice(24..31, b"../evil".iter().copied());
        let mut non_utf8_group = blob.clone();
        non_utf8_group.splice(24..25, [0xff]);
        let Some(truncated_header) = blob.get(..20).map(<[u8]>::to_vec) else {
            panic!("blob should be longer than 20 bytes");
        };
        let Some(truncated_tag) = blob
            .get(..header_len + SIV_TAG_BYTES - 1)
            .map(<[u8]>::to_vec)
        else {
            panic!("blob should hold a full tag");
        };
        let mut oversized = Vec::with_capacity(MAX_ENCRYPTED_FILE_BYTES + 1);
        oversized.extend_from_slice(&blob);
        oversized.resize(MAX_ENCRYPTED_FILE_BYTES + 1, 0);

        let cases: [(Vec<u8>, ErrorCheck); 10] = [
            (bad_magic, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
            (bad_version, |e| {
                matches!(e, CryptoError::UnsupportedVersion { found: 2 })
            }),
            (zero_generation, |e| {
                matches!(e, CryptoError::InvalidGeneration)
            }),
            (zero_group_len, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
            (long_group_len, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
            (bad_group, |e| {
                matches!(e, CryptoError::InvalidGroupName { .. })
            }),
            (non_utf8_group, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
            (truncated_header, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
            (truncated_tag, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
            (oversized, |e| {
                matches!(e, CryptoError::InvalidEncryptedFile { .. })
            }),
        ];
        for (case, is_expected) in cases {
            match parse_encrypted_file_header(&case) {
                Err(error) if is_expected(&error) => {}
                other => panic!("unexpected header result: {other:?}"),
            }
            expect_decrypt_error(
                decrypt_file("backend", 1, "f.txt", &key, &case),
                is_expected,
            );
        }
        assert!(!is_encrypted_file(b"SCRIMFILE"));
        assert!(!is_encrypted_file(b"plain text"));
    }
}
