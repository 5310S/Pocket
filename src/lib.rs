use std::fs;
use std::path::PathBuf;

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use bech32::{encode, ToBase32, Variant};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PocketError {
    #[error("invalid hrp: {0}")]
    InvalidHrp(String),
    #[error("mnemonic error: {0}")]
    Mnemonic(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("rpc error: {0}")]
    Rpc(String),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyInfo {
    pub mnemonic: String,
    pub public_key_hex: String,
    pub address: String,
}

#[derive(Serialize, Deserialize)]
struct Keystore {
    cipher: String,
    salt: String,
    nonce: String,
    hrp: String,
    kdf: String,
}

const KEYSTORE_PATH: &str = "~/.pocket/keystore.json";

fn hrp_valid(hrp: &str) -> bool {
    matches!(hrp, "pc" | "tpc")
}

fn bech32_address(hrp: &str, vk: &VerifyingKey) -> Result<String, PocketError> {
    if !hrp_valid(hrp) {
        return Err(PocketError::InvalidHrp(hrp.to_string()));
    }
    let data = vk.as_bytes().to_base32();
    encode(hrp, data, Variant::Bech32).map_err(|e| PocketError::Mnemonic(e.to_string()))
}

pub fn gen_key(words: usize, hrp: &str) -> Result<KeyInfo, PocketError> {
    let mnemonic = Mnemonic::generate_in(Language::English, words)
        .map_err(|e| PocketError::Mnemonic(e.to_string()))?;
    let seed_bytes = mnemonic.to_seed("");
    let signing = SigningKey::from_bytes(&seed_bytes[0..32].try_into().unwrap());
    let verifying = signing.verifying_key();
    let addr = bech32_address(hrp, &verifying)?;
    Ok(KeyInfo {
        mnemonic: mnemonic.to_string(),
        public_key_hex: hex::encode(verifying.as_bytes()),
        address: addr,
    })
}

pub fn addr_from_mnemonic(mnemonic: &str, hrp: &str) -> Result<KeyInfo, PocketError> {
    let m = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| PocketError::Mnemonic(e.to_string()))?;
    let seed_bytes = m.to_seed("");
    let signing = SigningKey::from_bytes(&seed_bytes[0..32].try_into().unwrap());
    let verifying = signing.verifying_key();
    let addr = bech32_address(hrp, &verifying)?;
    Ok(KeyInfo {
        mnemonic: m.to_string(),
        public_key_hex: hex::encode(verifying.as_bytes()),
        address: addr,
    })
}

fn expand_path(p: &str) -> PathBuf {
    if let Some(stripped) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(p)
}

fn keystore_path() -> PathBuf {
    expand_path(KEYSTORE_PATH)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], PocketError> {
    let argon = Argon2::default();
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| PocketError::Crypto(e.to_string()))?;
    Ok(key)
}

fn encrypt_mnemonic(mnemonic: &str, password: &str, hrp: &str) -> Result<Keystore, PocketError> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| PocketError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| PocketError::Crypto(e.to_string()))?;
    Ok(Keystore {
        cipher: general_purpose::STANDARD.encode(ciphertext),
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        hrp: hrp.to_string(),
        kdf: "argon2id".into(),
    })
}

fn decrypt_mnemonic(ks: &Keystore, password: &str) -> Result<String, PocketError> {
    let salt = general_purpose::STANDARD
        .decode(&ks.salt)
        .map_err(|e| PocketError::Crypto(e.to_string()))?;
    let nonce_bytes = general_purpose::STANDARD
        .decode(&ks.nonce)
        .map_err(|e| PocketError::Crypto(e.to_string()))?;
    let cipher_bytes = general_purpose::STANDARD
        .decode(&ks.cipher)
        .map_err(|e| PocketError::Crypto(e.to_string()))?;
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| PocketError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| PocketError::Crypto(e.to_string()))?;
    String::from_utf8(plaintext).map_err(|e| PocketError::Crypto(e.to_string()))
}

pub fn init_keystore(password: &str, hrp: &str) -> Result<KeyInfo, PocketError> {
    let info = gen_key(24, hrp)?;
    let ks = encrypt_mnemonic(&info.mnemonic, password, hrp)?;
    let path = keystore_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| PocketError::Io(e.to_string()))?;
    }
    let data = serde_json::to_vec_pretty(&ks).map_err(|e| PocketError::Io(e.to_string()))?;
    fs::write(&path, data).map_err(|e| PocketError::Io(e.to_string()))?;
    Ok(info)
}

pub fn load_keystore(password: &str) -> Result<KeyInfo, PocketError> {
    let path = keystore_path();
    let data = fs::read_to_string(&path).map_err(|e| PocketError::Io(e.to_string()))?;
    let ks: Keystore = serde_json::from_str(&data).map_err(|e| PocketError::Io(e.to_string()))?;
    let mnemonic = decrypt_mnemonic(&ks, password)?;
    addr_from_mnemonic(&mnemonic, &ks.hrp)
}

pub fn balance(password: &str, rpc: Option<String>, token: Option<String>) -> Result<String, PocketError> {
    let info = load_keystore(password)?;
    let rpc_base = rpc.unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let url = format!("{}/getBalance", rpc_base.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    let mut req = client.post(url).json(&serde_json::json!({"addr": info.address}));
    if let Some(t) = token.or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok()) {
        req = req.bearer_auth(t);
    }
    let resp = req.send().map_err(|e| PocketError::Rpc(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(PocketError::Rpc(format!("http {}", resp.status())));
    }
    let txt = resp.text().map_err(|e| PocketError::Rpc(e.to_string()))?;
    Ok(txt)
}
