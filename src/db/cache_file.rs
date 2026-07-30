use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const CACHE_KEY_ENV: &str = "SAFE_MIGRATE_CACHE_KEY";
pub const MAX_CACHE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CACHE_DECODE_BYTES: usize = 256 * 1024 * 1024;
const ENCRYPTED_CACHE_MAGIC: &[u8] = b"SMENC001";
const NONCE_LENGTH: usize = 24;

pub fn read_cache_bytes(cache_path: &Path) -> Result<Vec<u8>> {
    read_cache_bytes_with_limit(cache_path, MAX_CACHE_FILE_BYTES)
}

fn read_cache_bytes_with_limit(cache_path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = File::open(cache_path)
        .with_context(|| format!("Failed to read cache file: {}", cache_path.display()))?;
    let initial_size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    let initial_capacity = initial_size.min(max_bytes) as usize;
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read cache file: {}", cache_path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "Cache file '{}' exceeds the {} MiB encoded-size limit",
            cache_path.display(),
            max_bytes / (1024 * 1024)
        );
    }
    Ok(bytes)
}

/// Identifies the safe-migrate encryption envelope without attempting to
/// decrypt it. This supports safe metadata inspection without exposing key
/// material or payload contents.
pub fn is_encrypted_cache_bytes(cache_bytes: &[u8]) -> bool {
    cache_bytes.starts_with(ENCRYPTED_CACHE_MAGIC)
}

/// Encrypts an encoded cache when cache encryption is enabled. The on-disk
/// envelope includes only a format marker and random nonce; the authenticated
/// ciphertext contains all cache metadata.
pub fn protect_cache_bytes(cache_bytes: Vec<u8>, encryption_enabled: bool) -> Result<Vec<u8>> {
    if !encryption_enabled {
        return Ok(cache_bytes);
    }

    let cipher = cipher_from_environment()?;
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, cache_bytes.as_ref())
        .map_err(|_| anyhow!("Failed to encrypt cache payload"))?;

    let mut envelope =
        Vec::with_capacity(ENCRYPTED_CACHE_MAGIC.len() + NONCE_LENGTH + ciphertext.len());
    envelope.extend_from_slice(ENCRYPTED_CACHE_MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Returns plaintext encoded cache bytes. Encrypted files require both an
/// enabled configuration and the environment-only key; authentication failures
/// intentionally do not distinguish a wrong key from modified ciphertext.
pub fn unprotect_cache_bytes(cache_bytes: Vec<u8>, encryption_enabled: bool) -> Result<Vec<u8>> {
    if !is_encrypted_cache_bytes(&cache_bytes) {
        if encryption_enabled {
            bail!(
                "Cache file is not encrypted, but cache_encryption = true. Run `safe-migrate sync` to create an encrypted cache."
            );
        }
        return Ok(cache_bytes);
    }

    if !encryption_enabled {
        bail!(
            "Cache file is encrypted. Set cache_encryption = true and provide {} to read it.",
            CACHE_KEY_ENV
        );
    }

    let nonce_end = ENCRYPTED_CACHE_MAGIC.len() + NONCE_LENGTH;
    if cache_bytes.len() <= nonce_end {
        bail!("Encrypted cache file is truncated");
    }

    let cipher = cipher_from_environment()?;
    let nonce = XNonce::try_from(&cache_bytes[ENCRYPTED_CACHE_MAGIC.len()..nonce_end])
        .map_err(|_| anyhow!("Encrypted cache has an invalid nonce"))?;
    cipher
        .decrypt(&nonce, &cache_bytes[nonce_end..])
        .map_err(|_| anyhow!("Failed to decrypt cache: key is incorrect or the file was modified"))
}

fn cipher_from_environment() -> Result<XChaCha20Poly1305> {
    let raw_key = std::env::var(CACHE_KEY_ENV).with_context(|| {
        format!(
            "{} must contain a 64-character hexadecimal key when cache_encryption is enabled",
            CACHE_KEY_ENV
        )
    })?;
    let key = decode_hex_key(raw_key.trim())?;
    XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("{} must contain exactly 32 key bytes", CACHE_KEY_ENV))
}

fn decode_hex_key(input: &str) -> Result<[u8; 32]> {
    if input.len() != 64 {
        bail!(
            "{} must be exactly 64 hexadecimal characters",
            CACHE_KEY_ENV
        );
    }

    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(input.as_bytes()[offset])?;
        let low = hex_nibble(input.as_bytes()[offset + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(key)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("{} must contain only hexadecimal characters", CACHE_KEY_ENV),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvironmentValueGuard;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn with_test_key(test: impl FnOnce()) {
        let _guard = EnvironmentValueGuard::set(CACHE_KEY_ENV, &"42".repeat(32));
        test();
    }

    #[test]
    fn decode_hex_key_requires_exact_hex_key_material() {
        assert!(decode_hex_key(&"a1".repeat(32)).is_ok());
        assert!(decode_hex_key("not-a-key").is_err());
        assert!(decode_hex_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn cache_file_reader_rejects_data_beyond_its_limit() {
        let mut cache = NamedTempFile::new().unwrap();
        cache.write_all(b"12345").unwrap();

        let error = read_cache_bytes_with_limit(cache.path(), 4).unwrap_err();
        assert!(error.to_string().contains("encoded-size limit"));
    }

    #[test]
    fn encrypted_cache_round_trip_authenticates_the_payload() {
        with_test_key(|| {
            let plaintext = b"cache payload".to_vec();
            let encrypted = protect_cache_bytes(plaintext.clone(), true).unwrap();
            assert_ne!(encrypted, plaintext);
            assert_eq!(
                unprotect_cache_bytes(encrypted.clone(), true).unwrap(),
                plaintext
            );

            let mut modified = encrypted;
            let last = modified.len() - 1;
            modified[last] ^= 1;
            assert!(unprotect_cache_bytes(modified, true).is_err());
        });
    }

    #[test]
    fn encryption_required_rejects_plaintext_cache_bytes() {
        let error = unprotect_cache_bytes(b"plaintext cache".to_vec(), true)
            .expect_err("encryption-enabled configuration must reject plaintext caches");
        assert!(error.to_string().contains("not encrypted"));
    }
}
