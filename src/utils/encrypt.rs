use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::RngCore;

use crate::core::error::AttackError;

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], AttackError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| AttackError::internal(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

pub fn encrypt_data(data: &[u8], passphrase: &str) -> Result<Vec<u8>, AttackError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AttackError::internal(format!("Cipher init error: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| AttackError::internal(format!("Encryption error: {}", e)))?;

    // Format: salt(16) + nonce(12) + ciphertext
    let mut result = Vec::with_capacity(16 + 12 + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_data(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, AttackError> {
    if encrypted.len() < 28 {
        return Err(AttackError::internal(String::from("Encrypted data too short")));
    }

    let salt = &encrypted[..16];
    let nonce_bytes = &encrypted[16..28];
    let ciphertext = &encrypted[28..];

    let key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AttackError::internal(format!("Cipher init error: {}", e)))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AttackError::internal(format!("Decryption error: {}. Wrong passphrase?", e)))
}

pub fn encrypt_file(input_path: &std::path::Path, passphrase: &str) -> Result<Vec<u8>, AttackError> {
    let data = std::fs::read(input_path)
        .map_err(|e| AttackError::io("read", format!("Cannot read {}: {}", input_path.display(), e)))?;
    encrypt_data(&data, passphrase)
}

pub fn decrypt_to_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    passphrase: &str,
) -> Result<(), AttackError> {
    let data = std::fs::read(input_path)
        .map_err(|e| AttackError::io("read", format!("Cannot read {}: {}", input_path.display(), e)))?;
    let decrypted = decrypt_data(&data, passphrase)?;
    std::fs::write(output_path, &decrypted)
        .map_err(|e| AttackError::io("write", format!("Cannot write {}: {}", output_path.display(), e)))?;
    Ok(())
}

pub fn write_encrypted(output_path: &std::path::Path, data: &[u8], passphrase: &str) -> Result<(), AttackError> {
    let encrypted = encrypt_data(data, passphrase)?;
    std::fs::write(output_path, &encrypted)
        .map_err(|e| AttackError::io("write", format!("Cannot write {}: {}", output_path.display(), e)))?;
    Ok(())
}

pub fn read_decrypted(input_path: &std::path::Path, passphrase: &str) -> Result<Vec<u8>, AttackError> {
    let data = std::fs::read(input_path)
        .map_err(|e| AttackError::io("read", format!("Cannot read {}: {}", input_path.display(), e)))?;
    decrypt_data(&data, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"hello world, this is secret!";
        let passphrase = "correct-horse-battery-staple";
        let encrypted = encrypt_data(data, passphrase).unwrap();
        let decrypted = decrypt_data(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let data = b"";
        let passphrase = "test-pass";
        let encrypted = encrypt_data(data, passphrase).unwrap();
        let decrypted = decrypt_data(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let data = b"secret data";
        let encrypted = encrypt_data(data, "correct-pass").unwrap();
        let result = decrypt_data(&encrypted, "wrong-pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_data_structure() {
        let data = b"test";
        let encrypted = encrypt_data(data, "pass").unwrap();
        // Format: 16 bytes salt + 12 bytes nonce + ciphertext
        assert!(encrypted.len() > 28);
        assert_eq!(&encrypted[..16].len(), &16); // salt
        assert_eq!(&encrypted[16..28].len(), &12); // nonce
    }

    #[test]
    fn test_decrypt_too_short() {
        let result = decrypt_data(&[0u8; 10], "pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_passphrases_different_output() {
        let data = b"same data";
        let e1 = encrypt_data(data, "pass1").unwrap();
        let e2 = encrypt_data(data, "pass2").unwrap();
        // Different passphrases + random salt give different output
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_same_data_different_salt() {
        let data = b"same data";
        let e1 = encrypt_data(data, "pass").unwrap();
        let e2 = encrypt_data(data, "pass").unwrap();
        // Same data+pass but random salt/nonce gives different output
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_long_data() {
        let data = vec![0xABu8; 10000];
        let passphrase = "a".repeat(100);
        let encrypted = encrypt_data(&data, &passphrase).unwrap();
        let decrypted = decrypt_data(&encrypted, &passphrase).unwrap();
        assert_eq!(decrypted.len(), 10000);
        assert_eq!(decrypted, data);
    }
}
