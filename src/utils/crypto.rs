use ring::digest::{Context, SHA256, SHA384, SHA512};
use ring::hmac::{self, Key, HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::pbkdf2;
use std::num::NonZeroU32;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(data);
    let result = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(result.as_ref());
    out
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut ctx = Context::new(&SHA384);
    ctx.update(data);
    let result = ctx.finish();
    let mut out = [0u8; 48];
    out.copy_from_slice(result.as_ref());
    out
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut ctx = Context::new(&SHA512);
    ctx.update(data);
    let result = ctx.finish();
    let mut out = [0u8; 64];
    out.copy_from_slice(result.as_ref());
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let signing_key = Key::new(HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let signing_key = Key::new(HMAC_SHA256, key);
    hmac::verify(&signing_key, data, expected).is_ok()
}

pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf).map_err(|e| format!("RNG: {}", e))?;
    Ok(buf)
}

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap_or(NonZeroU32::new(100_000).unwrap()),
        salt,
        password,
        &mut out,
    );
    out
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

pub fn hex_encode(data: &[u8]) -> String {
    let hex_chars = b"0123456789abcdef";
    let mut out = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(hex_chars[(byte >> 4) as usize]);
        out.push(hex_chars[(byte & 0x0f) as usize]);
    }
    unsafe { String::from_utf8_unchecked(out) }
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    (0..hex.len()).step_by(2).map(|i| {
        u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|e| format!("Hex decode error at position {}: {}", i, e))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = sha256(b"hello");
        assert_eq!(hex_encode(&result), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"secret";
        let data = b"message";
        let tag = hmac_sha256(key, data);
        assert!(verify_hmac_sha256(key, data, &tag));
        assert!(!verify_hmac_sha256(key, b"wrong", &tag));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"\x00\xff\xab\xcd";
        let hex = hex_encode(data);
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_pbkdf2_sha256() {
        let result = pbkdf2_sha256(b"password", b"salt", 1000);
        assert_eq!(result.len(), 32);
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_secure_random() {
        let bytes = secure_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_ne!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("xyz").is_err());
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn test_sha384() {
        let result = sha384(b"test");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512() {
        let result = sha512(b"test");
        assert_eq!(result.len(), 64);
    }
}
