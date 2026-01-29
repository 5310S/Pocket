use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use bech32::{encode, ToBase32, Variant};
use bip39::{Language, Mnemonic};
use ed25519_dalek::Signer;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum::{Display, EnumString};
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
const CONFIG_PATH: &str = "~/.pocket/config.json";
const PROFILE_PATH: &str = "~/.pocket/profile.json";
const ENV_TLS_INSECURE: &str = "POCKET_TLS_INSECURE";
const ENV_PENDING_POOL: &str = "PENDING_POOL_PATH";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub rpc_base: Option<String>,
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Profile {
    pub payout_address: Option<String>,
    pub attestation_token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BalanceInfo {
    pub addr: String,
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxEnvelope {
    pub tx: serde_json::Value,
    pub tx_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxBuildRequest {
    pub kind: BuildKind,
    pub fee: u64,
    pub nonce: Option<u64>,
    pub timestamp: Option<u64>,
    pub chain_id: Option<String>,
    pub memo: Option<String>,
    pub pending_pool: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum BuildKind {
    Transfer {
        to: String,
        amount: u64,
    },
    Stake {
        amount: u64,
        payout: String,
        commission_bps: u16,
    },
    Unbond {
        amount: u64,
    },
    UpdateValidator {
        payout: Option<String>,
        commission_bps: Option<u16>,
    },
}

fn address_matches_chain(addr: &str, chain_id: &str) -> bool {
    let hrp = if chain_id.starts_with("peace-mainnet") {
        "pc"
    } else if chain_id.starts_with("peace-testnet") {
        "tpc"
    } else {
        ""
    };
    addr.starts_with(hrp)
}

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

fn config_path() -> PathBuf {
    expand_path(CONFIG_PATH)
}

fn profile_path() -> PathBuf {
    expand_path(PROFILE_PATH)
}

pub fn save_config(cfg: &Config) -> Result<(), PocketError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| PocketError::Io(e.to_string()))?;
    }
    let data = serde_json::to_vec_pretty(cfg).map_err(|e| PocketError::Io(e.to_string()))?;
    fs::write(&path, data).map_err(|e| PocketError::Io(e.to_string()))
}

pub fn load_config() -> Result<Config, PocketError> {
    let path = config_path();
    match fs::read_to_string(&path) {
        Ok(txt) => serde_json::from_str(&txt).map_err(|e| PocketError::Io(e.to_string())),
        Err(_) => Ok(Config::default()),
    }
}

pub fn save_profile(profile: &Profile) -> Result<(), PocketError> {
    let path = profile_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| PocketError::Io(e.to_string()))?;
    }
    let data = serde_json::to_vec_pretty(profile).map_err(|e| PocketError::Io(e.to_string()))?;
    fs::write(&path, data).map_err(|e| PocketError::Io(e.to_string()))
}

pub fn load_profile() -> Result<Profile, PocketError> {
    let path = profile_path();
    match fs::read_to_string(&path) {
        Ok(txt) => serde_json::from_str(&txt).map_err(|e| PocketError::Io(e.to_string())),
        Err(_) => Ok(Profile::default()),
    }
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

pub fn export_mnemonic(password: &str) -> Result<String, PocketError> {
    let path = keystore_path();
    let data = fs::read_to_string(&path).map_err(|e| PocketError::Io(e.to_string()))?;
    let ks: Keystore = serde_json::from_str(&data).map_err(|e| PocketError::Io(e.to_string()))?;
    decrypt_mnemonic(&ks, password)
}

pub fn import_mnemonic(password: &str, mnemonic: &str, hrp: &str) -> Result<KeyInfo, PocketError> {
    let _ = addr_from_mnemonic(mnemonic, hrp)?;
    let ks = encrypt_mnemonic(mnemonic, password, hrp)?;
    let path = keystore_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| PocketError::Io(e.to_string()))?;
    }
    let data = serde_json::to_vec_pretty(&ks).map_err(|e| PocketError::Io(e.to_string()))?;
    fs::write(&path, data).map_err(|e| PocketError::Io(e.to_string()))?;
    addr_from_mnemonic(mnemonic, hrp)
}

pub fn balance(
    password: &str,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<String, PocketError> {
    let info = load_keystore(password)?;
    let cfg = load_config().unwrap_or_default();
    let rpc_base = rpc
        .or(cfg.rpc_base.clone())
        .unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let client = rpc_client()?;
    let req = client
        .post(format!("{}/getBalance", rpc_base.trim_end_matches('/')))
        .json(&serde_json::json!({"addr": info.address}));
    rpc_send(req, token.or(cfg.token))
}

pub fn fetch_balance(
    addr: &str,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<BalanceInfo, PocketError> {
    let cfg = load_config().unwrap_or_default();
    let rpc_base = rpc
        .or(cfg.rpc_base.clone())
        .unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let client = rpc_client()?;
    let mut req = client
        .post(format!("{}/getBalance", rpc_base.trim_end_matches('/')))
        .json(&serde_json::json!({"addr": addr}));
    if let Some(t) = token
        .or(cfg.token)
        .or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok())
    {
        req = req.bearer_auth(t);
    }
    let resp = req.send().map_err(|e| PocketError::Rpc(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(PocketError::Rpc(format!("http {}", resp.status())));
    }
    let txt = resp.text().map_err(|e| PocketError::Rpc(e.to_string()))?;
    serde_json::from_str(&txt).map_err(|e| PocketError::Rpc(e.to_string()))
}

pub fn chain_head(rpc: Option<String>, token: Option<String>) -> Result<String, PocketError> {
    let cfg = load_config().unwrap_or_default();
    let rpc_base = rpc
        .or(cfg.rpc_base.clone())
        .unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let client = rpc_client()?;
    let req = client.get(format!(
        "{}/weave/chain/head",
        rpc_base.trim_end_matches('/')
    ));
    rpc_send(req, token.or(cfg.token))
}

pub fn difficulty(rpc: Option<String>, token: Option<String>) -> Result<String, PocketError> {
    let cfg = load_config().unwrap_or_default();
    let rpc_base = rpc
        .or(cfg.rpc_base.clone())
        .unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let client = rpc_client()?;
    let req = client.get(format!("{}/getDifficulty", rpc_base.trim_end_matches('/')));
    rpc_send(req, token.or(cfg.token))
}

fn rpc_client() -> Result<Client, PocketError> {
    let insecure = std::env::var(ENV_TLS_INSECURE)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut builder = Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| PocketError::Rpc(e.to_string()))
}

fn rpc_send(
    req: reqwest::blocking::RequestBuilder,
    token: Option<String>,
) -> Result<String, PocketError> {
    let mut last_err = None;
    for attempt in 0..3 {
        let mut req = req
            .try_clone()
            .ok_or_else(|| PocketError::Rpc("clone req failed".into()))?;
        if let Some(t) = token
            .as_ref()
            .cloned()
            .or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok())
        {
            req = req.bearer_auth(t);
        }
        match req.send() {
            Ok(resp) => {
                if !resp.status().is_success() {
                    last_err = Some(PocketError::Rpc(format!("http {}", resp.status())));
                } else {
                    return resp.text().map_err(|e| PocketError::Rpc(e.to_string()));
                }
            }
            Err(e) => last_err = Some(PocketError::Rpc(e.to_string())),
        }
        std::thread::sleep(std::time::Duration::from_millis(50 * (attempt + 1) as u64));
    }
    Err(last_err.unwrap_or_else(|| PocketError::Rpc("request failed".into())))
}

fn pending_nonce_from_pool(path: &str, addr: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Pools {
        txs: Vec<PoolTx>,
    }
    #[derive(Deserialize)]
    struct PoolTx {
        from: String,
        nonce: u64,
    }
    let data = fs::read_to_string(path).ok()?;
    let parsed: Pools = serde_json::from_str(&data).ok()?;
    parsed
        .txs
        .iter()
        .filter(|tx| tx.from == addr)
        .map(|tx| tx.nonce)
        .max()
        .map(|m| m.saturating_add(1))
}

// --- Tx build/sign (offline) ---

fn tx_signing_bytes(tx: &serde_json::Value) -> Result<Vec<u8>, PocketError> {
    let mut map = tx
        .as_object()
        .cloned()
        .ok_or_else(|| PocketError::Crypto("tx not object".into()))?;
    map.remove("signature");
    let without_sig = serde_json::Value::Object(map);
    serde_json::to_vec(&without_sig).map_err(|e| PocketError::Crypto(e.to_string()))
}

fn tx_id_bytes(tx: &serde_json::Value) -> Result<[u8; 32], PocketError> {
    let bytes = serde_json::to_vec(tx).map_err(|e| PocketError::Crypto(e.to_string()))?;
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_bytes_ignore_signature() {
        let mut tx = serde_json::json!({
            "from": "tpc1test",
            "nonce": 1,
            "fee": 1,
            "timestamp": 123,
            "chain_id": "peace-testnet",
            "kind": {"Transfer": {"to": "tpc1dest", "amount": 2}},
            "pubkey_hex": "00".repeat(32),
            "signature": "aa"
        });
        let a = tx_signing_bytes(&tx).unwrap();
        tx["signature"] = serde_json::json!("bb");
        let b = tx_signing_bytes(&tx).unwrap();
        assert_eq!(a, b, "signature must not affect signing bytes");
    }
}

pub fn build_and_sign_transfer(
    password: &str,
    req: TxBuildRequest,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<TxEnvelope, PocketError> {
    let info = load_keystore(password)?;
    let chain_id = req.chain_id.unwrap_or_else(|| "peace-testnet".into());
    if !address_matches_chain(&info.address, &chain_id) {
        return Err(PocketError::Crypto("hrp/chain_id mismatch".into()));
    }
    let pool_path = req
        .pending_pool
        .clone()
        .or_else(|| std::env::var(ENV_PENDING_POOL).ok());
    let ledger_nonce = fetch_balance(&info.address, rpc.clone(), token.clone())?.nonce;
    let chosen_nonce = match req.nonce {
        Some(n) => n,
        None => pool_path
            .as_deref()
            .and_then(|p| pending_nonce_from_pool(p, &info.address))
            .unwrap_or(ledger_nonce),
    };
    // Construct minimal tx map per spec.
    let mut tx_map = serde_json::Map::new();
    tx_map.insert(
        "from".into(),
        serde_json::Value::String(info.address.clone()),
    );
    tx_map.insert(
        "nonce".into(),
        serde_json::Value::Number(serde_json::Number::from(chosen_nonce)),
    );
    tx_map.insert(
        "fee".into(),
        serde_json::Value::Number(serde_json::Number::from(req.fee)),
    );
    tx_map.insert(
        "timestamp".into(),
        serde_json::Value::Number(serde_json::Number::from(
            req.timestamp.unwrap_or_else(|| now_ts()),
        )),
    );
    tx_map.insert(
        "chain_id".into(),
        serde_json::Value::String(chain_id.clone()),
    );
    tx_map.insert(
        "pubkey_hex".into(),
        serde_json::Value::String(info.public_key_hex.clone()),
    );
    let kind_val = match req.kind {
        BuildKind::Transfer { to, amount } => {
            serde_json::json!({"Transfer": {"to": to, "amount": amount}})
        }
        BuildKind::Stake {
            amount,
            payout,
            commission_bps,
        } => {
            serde_json::json!({"Stake": {"amount": amount, "payout": payout, "commission_bps": commission_bps}})
        }
        BuildKind::Unbond { amount } => serde_json::json!({"Unbond": {"amount": amount}}),
        BuildKind::UpdateValidator {
            payout,
            commission_bps,
        } => {
            serde_json::json!({"UpdateValidator": {"payout": payout, "commission_bps": commission_bps}})
        }
    };
    tx_map.insert("kind".into(), kind_val);

    let mut tx_val = serde_json::Value::Object(tx_map);
    let msg = tx_signing_bytes(&tx_val)?;
    let seed_bytes = Mnemonic::parse_in_normalized(Language::English, &info.mnemonic)
        .map_err(|e| PocketError::Mnemonic(e.to_string()))?
        .to_seed("");
    let sk = SigningKey::from_bytes(&seed_bytes[0..32].try_into().unwrap());
    let sig = sk.sign(&msg);
    tx_val
        .as_object_mut()
        .ok_or_else(|| PocketError::Crypto("tx not object".into()))?
        .insert(
            "signature".into(),
            serde_json::Value::String(hex::encode(sig.to_bytes())),
        );
    let txid = tx_id_bytes(&tx_val)?;
    Ok(TxEnvelope {
        tx: tx_val,
        tx_id: hex::encode(txid),
    })
}

pub fn submit_tx(
    rpc: Option<String>,
    token: Option<String>,
    signed: &serde_json::Value,
) -> Result<String, PocketError> {
    let cfg = load_config().unwrap_or_default();
    let rpc_base = rpc
        .or(cfg.rpc_base.clone())
        .unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let client = rpc_client()?;
    let mut reqb = client
        .post(format!("{}/weave/chain/tx", rpc_base.trim_end_matches('/')))
        .json(&serde_json::json!({"tx": signed}));
    if let Some(t) = token
        .or(cfg.token)
        .or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok())
    {
        reqb = reqb.bearer_auth(t);
    }
    let resp = reqb.send().map_err(|e| PocketError::Rpc(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(PocketError::Rpc(format!("http {}", resp.status())));
    }
    resp.text().map_err(|e| PocketError::Rpc(e.to_string()))
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
