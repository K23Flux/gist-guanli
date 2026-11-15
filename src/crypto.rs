use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Crypto([u8; 32]);

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut value = [0; N];
    OsRng.fill_bytes(&mut value);
    value
}
pub fn random_token() -> String {
    B64.encode(random_bytes::<32>())
}
pub fn digest(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}
pub fn matches(value: &str, expected: &[u8]) -> bool {
    digest(value).as_slice().ct_eq(expected).into()
}
fn argon() -> Result<Argon2<'static>> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, Some(32)).map_err(|_| anyhow!("口令参数错误"))?,
    ))
}
pub fn hash_secret(secret: &str) -> Result<String> {
    let salt = random_bytes::<16>();
    let mut output = [0; 32];
    argon()?
        .hash_password_into(secret.as_bytes(), &salt, &mut output)
        .map_err(|_| anyhow!("口令处理失败"))?;
    Ok(format!("v1${}${}", B64.encode(salt), B64.encode(output)))
}
pub fn verify_secret(secret: &str, stored: &str) -> bool {
    let parts: Vec<_> = stored.split('$').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return false;
    }
    let Ok(salt) = B64.decode(parts[1]) else {
        return false;
    };
    let Ok(expected) = B64.decode(parts[2]) else {
        return false;
    };
    if salt.len() != 16 || expected.len() != 32 {
        return false;
    }
    let mut output = [0; 32];
    argon().is_ok_and(|a| {
        a.hash_password_into(secret.as_bytes(), &salt, &mut output)
            .is_ok()
    }) && bool::from(output.as_slice().ct_eq(&expected))
}
impl Crypto {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    pub fn seal(&self, value: &str) -> Result<String> {
        let nonce = random_bytes::<24>();
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let body = cipher
            .encrypt(XNonce::from_slice(&nonce), value.as_bytes())
            .map_err(|_| anyhow!("令牌加密失败"))?;
        let mut all = nonce.to_vec();
        all.extend_from_slice(&body);
        Ok(B64.encode(all))
    }
    pub fn open(&self, value: &str) -> Result<String> {
        let all = B64.decode(value).map_err(|_| anyhow!("令牌数据损坏"))?;
        if all.len() < 40 {
            return Err(anyhow!("令牌数据损坏"));
        }
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let bytes = cipher
            .decrypt(XNonce::from_slice(&all[..24]), &all[24..])
            .map_err(|_| anyhow!("密钥不匹配或令牌损坏"))?;
        String::from_utf8(bytes).map_err(|_| anyhow!("令牌数据损坏"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_encryption_detects_tampering_and_wrong_key() {
        let a = Crypto::new([1; 32]);
        let token = random_token();
        let encrypted = a.seal(&token).unwrap();
        assert_eq!(a.open(&encrypted).unwrap(), token);
        assert!(Crypto::new([2; 32]).open(&encrypted).is_err());
        assert!(a.open("bad").is_err());
        assert!(matches(&token, &digest(&token)));
        assert!(!matches("wrong", &digest(&token)));
    }
    #[test]
    fn argon_verifies_secret_and_rejects_corruption() {
        let stored = hash_secret("a long local test phrase").unwrap();
        assert!(verify_secret("a long local test phrase", &stored));
        assert!(!verify_secret("wrong", &stored));
        assert!(!verify_secret("x", "v1$bad$bad"));
    }
}
