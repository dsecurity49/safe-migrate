use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};

pub const CACHE_KEY_ENV: &str = "SAFE_MIGRATE_CACHE_KEY";
const ENCRYPTED_CACHE_MAGIC: &[u8] = b"SMENC001";
const NONCE_LENGTH: usize = 24;

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
    if !cache_bytes.starts_with(ENCRYPTED_CACHE_MAGIC) {
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
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_test_key(test: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous = std::env::var(CACHE_KEY_ENV).ok();
        unsafe {
            std::env::set_var(CACHE_KEY_ENV, "42".repeat(32));
        }
        test();
        unsafe {
            if let Some(previous) = previous {
                std::env::set_var(CACHE_KEY_ENV, previous);
            } else {
                std::env::remove_var(CACHE_KEY_ENV);
            }
        }
    }

    #[test]
    fn decode_hex_key_requires_exact_hex_key_material() {
        assert!(decode_hex_key(&"a1".repeat(32)).is_ok());
        assert!(decode_hex_key("not-a-key").is_err());
        assert!(decode_hex_key(&"zz".repeat(32)).is_err());
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
}
