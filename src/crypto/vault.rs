// src/crypto/vault.rs
//
// Cifrado zero-access de tokens de cuenta.
// - KDF: Argon2id (memory-hard)
// - AEAD: XChaCha20-Poly1305 (24-byte random nonce per operation)
// - La clave derivada se guarda en `VaultKey`, que se zeroiza al drop.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

const VERIFIER_PLAINTEXT: &[u8] = b"BuzzHeavierVaultVerifier_v1";

/// Clave derivada de la contraseña maestra. Se zeroiza al drop.
pub struct VaultKey(Zeroizing<[u8; KEY_LEN]>);

impl VaultKey {
    fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

fn os_random(buf: &mut [u8]) {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(buf);
}

pub fn new_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    os_random(&mut salt);
    salt
}

pub fn derive_key(
    password: &str,
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<VaultKey, String> {
    let params =
        Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| format!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(VaultKey(key))
}

pub fn encrypt(key: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|e| format!("cipher init: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    os_random(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encrypt: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &VaultKey, blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < NONCE_LEN {
        return Err("blob too short".into());
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|e| format!("cipher init: {e}"))?;

    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ct)
        .map_err(|_| "decrypt failed (wrong password or corrupted data)".to_string())
}

pub fn make_verifier(key: &VaultKey) -> Result<Vec<u8>, String> {
    encrypt(key, VERIFIER_PLAINTEXT)
}

pub fn check_verifier(key: &VaultKey, verifier: &[u8]) -> Result<(), String> {
    let pt = decrypt(key, verifier)?;
    if pt == VERIFIER_PLAINTEXT {
        Ok(())
    } else {
        Err("verifier mismatch".into())
    }
}

#[cfg(test)]
mod tests {
    //! Tests del núcleo criptográfico. Params de Argon2 muy bajos para que
    //! la suite sea rápida; los params reales (65536/3/1) ya se prueban en
    //! integración manual al arrancar la app por primera vez.
    use super::*;

    const T_M: u32 = 1024;
    const T_T: u32 = 1;
    const T_P: u32 = 1;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let salt = new_salt();
        let key =
            derive_key("correct horse battery staple", &salt, T_M, T_T, T_P).expect("derive_key");
        let ct = encrypt(&key, b"hello world").expect("encrypt");
        let pt = decrypt(&key, &ct).expect("decrypt");
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn wrong_password_fails_decrypt() {
        let salt = new_salt();
        let good = derive_key("password-1", &salt, T_M, T_T, T_P).expect("derive_key");
        let ct = encrypt(&good, b"secret").expect("encrypt");
        let bad = derive_key("password-2", &salt, T_M, T_T, T_P).expect("derive_key");
        assert!(decrypt(&bad, &ct).is_err());
    }

    #[test]
    fn verifier_accepts_correct_password() {
        let salt = new_salt();
        let key = derive_key("pw", &salt, T_M, T_T, T_P).expect("derive_key");
        let v = make_verifier(&key).expect("make_verifier");
        assert!(check_verifier(&key, &v).is_ok());
    }

    #[test]
    fn verifier_rejects_wrong_password() {
        let salt = new_salt();
        let key = derive_key("pw", &salt, T_M, T_T, T_P).expect("derive_key");
        let v = make_verifier(&key).expect("make_verifier");
        let bad = derive_key("other", &salt, T_M, T_T, T_P).expect("derive_key");
        assert!(check_verifier(&bad, &v).is_err());
    }

    #[test]
    fn decrypt_short_blob_errors() {
        let salt = new_salt();
        let key = derive_key("pw", &salt, T_M, T_T, T_P).expect("derive_key");
        assert!(decrypt(&key, &[0u8; 5]).is_err());
    }

    #[test]
    fn nonce_is_unique_per_encrypt() {
        let salt = new_salt();
        let key = derive_key("pw", &salt, T_M, T_T, T_P).expect("derive_key");
        let a = encrypt(&key, b"x").expect("encrypt a");
        let b = encrypt(&key, b"x").expect("encrypt b");
        assert_ne!(&a[..NONCE_LEN], &b[..NONCE_LEN]);
    }

    #[test]
    fn wrong_password_rejects_and_aead_authenticates() {
        // Un solo bit cambiado en el ciphertext debe fallar la verificación AEAD.
        let salt = new_salt();
        let key = derive_key("pw", &salt, T_M, T_T, T_P).expect("derive_key");
        let mut ct = encrypt(&key, b"hi").expect("encrypt");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&key, &ct).is_err());
    }
}
