use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use bech32::{encode, ToBase32, Variant};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum::{Display, EnumString};
use thiserror::Error;
use tiny_http::{Header, Method, Response, Server, StatusCode};

mod p2p;

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
    #[error("proof error: {0}")]
    Proof(String),
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
const ENV_PROFILE_TOKEN: &str = "POCKET_PROFILE_TOKEN";
const DEFAULT_P2P_BOOTSTRAP: &[&str] = &["93.127.216.241:3737"];

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub rpc_base: Option<String>,
    pub token: Option<String>,
    #[serde(default)]
    pub p2p_bootstrap: Vec<String>,
    #[serde(default)]
    pub external_signer_command: Option<String>,
    #[serde(default)]
    pub external_signer_address: Option<String>,
    #[serde(default)]
    pub external_signer_pubkey_hex: Option<String>,
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
pub struct StakeLock {
    pub amount: u128,
    pub start_height: u64,
    pub unlock_height: u64,
    pub payout: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    pub stakes: Vec<StakeLock>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountProofItem {
    pub hash: Vec<u8>,
    pub position: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountProofResponse {
    pub addr: String,
    pub account: AccountState,
    pub proof: Vec<AccountProofItem>,
    pub root: String,
    pub index: usize,
    pub chain_id: String,
    pub height: u64,
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

// Transaction wire format (must match Lantern consensus/RPC types).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TxKind {
    Transfer {
        to: String,
        amount: u128,
    },
    Stake {
        amount: u128,
        payout: String,
        #[serde(default)]
        commission_bps: u16,
    },
    Unbond {
        amount: u128,
    },
    Slash {
        target: String,
        amount: u128,
    },
    Unjail {
        validator: String,
    },
    UpdateValidator {
        payout: Option<String>,
        commission_bps: Option<u16>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Transaction {
    from: String,
    nonce: u64,
    kind: TxKind,
    fee: u128,
    #[serde(default)]
    timestamp: u64,
    #[serde(default)]
    chain_id: String,
    #[serde(default)]
    signature: Option<Vec<u8>>,
    #[serde(default)]
    pubkey_hex: Option<String>,
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

fn hrp_for_chain(chain_id: &str) -> Result<&'static str, PocketError> {
    if chain_id.starts_with("peace-mainnet") {
        Ok("pc")
    } else if chain_id.starts_with("peace-testnet") {
        Ok("tpc")
    } else {
        Err(PocketError::Crypto(format!(
            "unsupported chain_id for address derivation: {chain_id}"
        )))
    }
}

fn bech32_address(hrp: &str, vk: &VerifyingKey) -> Result<String, PocketError> {
    if !hrp_valid(hrp) {
        return Err(PocketError::InvalidHrp(hrp.to_string()));
    }
    let data = vk.as_bytes().to_base32();
    encode(hrp, data, Variant::Bech32).map_err(|e| PocketError::Mnemonic(e.to_string()))
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn state_leaf_hash(key: &str, value: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(key.len() + 1 + value.len());
    buf.extend_from_slice(key.as_bytes());
    buf.push(0);
    buf.extend_from_slice(value);
    hash_bytes(&buf)
}

fn account_leaf_hash(addr: &str, account: &AccountState) -> Result<[u8; 32], PocketError> {
    #[derive(Serialize)]
    struct AccountLeaf<'a> {
        addr: &'a str,
        account: &'a AccountState,
    }
    let leaf = AccountLeaf { addr, account };
    let bytes = serde_json::to_vec(&leaf).map_err(|e| PocketError::Proof(e.to_string()))?;
    Ok(state_leaf_hash(&format!("account:{}", addr), &bytes))
}

fn verify_account_proof(proof: &AccountProofResponse) -> bool {
    let mut hash = match account_leaf_hash(&proof.addr, &proof.account) {
        Ok(h) => h,
        Err(_) => return false,
    };
    for item in &proof.proof {
        if item.hash.len() != 32 {
            return false;
        }
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&item.hash[..32]);
        let mut buf = Vec::with_capacity(64);
        if item.position == "left" {
            buf.extend_from_slice(&sibling);
            buf.extend_from_slice(&hash);
        } else if item.position == "right" {
            buf.extend_from_slice(&hash);
            buf.extend_from_slice(&sibling);
        } else {
            return false;
        }
        hash = hash_bytes(&buf);
    }
    let root_bytes = match hex::decode(&proof.root) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if root_bytes.len() != 32 {
        return false;
    }
    hash.as_slice() == root_bytes.as_slice()
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

fn p2p_bootstrap(cfg: &Config) -> Vec<String> {
    if let Ok(raw) = std::env::var("POCKET_P2P_BOOTSTRAP") {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("off") {
            return Vec::new();
        }
        let list: Vec<String> = trimmed
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    if !cfg.p2p_bootstrap.is_empty() {
        return cfg.p2p_bootstrap.clone();
    }
    DEFAULT_P2P_BOOTSTRAP
        .iter()
        .map(|s| s.to_string())
        .collect()
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

fn profile_payload(include_attestation: bool) -> Result<String, PocketError> {
    let profile = load_profile().unwrap_or_default();
    let body = if include_attestation {
        serde_json::json!({
            "payout_address": profile.payout_address,
            "attestation_token": profile.attestation_token,
        })
    } else {
        serde_json::json!({
            "payout_address": profile.payout_address,
        })
    };
    serde_json::to_string_pretty(&body).map_err(|e| PocketError::Io(e.to_string()))
}

fn has_profile_auth(headers: &[Header], required_token: &str) -> bool {
    if required_token.is_empty() {
        return true;
    }
    headers.iter().any(|header| {
        header.field.equiv("Authorization")
            && header.value.as_str().trim() == format!("Bearer {required_token}")
    })
}

pub fn serve_profile_http(
    bind: &str,
    token: Option<String>,
    once: bool,
) -> Result<String, PocketError> {
    let server = Server::http(bind).map_err(|e| PocketError::Io(e.to_string()))?;
    let actual_bind = server
        .server_addr()
        .to_ip()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| bind.to_string());
    let required_token = token
        .or_else(|| std::env::var(ENV_PROFILE_TOKEN).ok())
        .unwrap_or_default();
    eprintln!("Pocket profile API listening on http://{actual_bind}");

    loop {
        let request = server.recv().map_err(|e| PocketError::Io(e.to_string()))?;
        let url = request.url().split('?').next().unwrap_or("/");
        let method = request.method().clone();

        let send_json =
            |request: tiny_http::Request, status: u16, body: String| -> Result<(), PocketError> {
                let mut response = Response::from_string(body).with_status_code(StatusCode(status));
                if let Ok(header) = Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"application/json; charset=utf-8"[..],
                ) {
                    response = response.with_header(header);
                }
                request
                    .respond(response)
                    .map_err(|e| PocketError::Io(e.to_string()))
            };

        match (method, url) {
            (Method::Get, "/health") => {
                send_json(request, 200, "{\"status\":\"ok\"}".to_string())?;
            }
            (Method::Get, "/payout") => {
                send_json(request, 200, profile_payload(false)?)?;
            }
            (Method::Get, "/profile") => {
                if !has_profile_auth(request.headers(), &required_token) {
                    send_json(request, 401, "{\"error\":\"unauthorized\"}".to_string())?;
                } else {
                    send_json(request, 200, profile_payload(true)?)?;
                }
            }
            _ => {
                send_json(request, 404, "{\"error\":\"not_found\"}".to_string())?;
            }
        }

        if once {
            break;
        }
    }

    Ok(actual_bind)
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

pub fn change_password(old_password: &str, new_password: &str) -> Result<(), PocketError> {
    let path = keystore_path();
    let data = fs::read_to_string(&path).map_err(|e| PocketError::Io(e.to_string()))?;
    let ks: Keystore = serde_json::from_str(&data).map_err(|e| PocketError::Io(e.to_string()))?;
    let mnemonic = decrypt_mnemonic(&ks, old_password)?;
    let new_ks = encrypt_mnemonic(&mnemonic, new_password, &ks.hrp)?;
    let data = serde_json::to_vec_pretty(&new_ks).map_err(|e| PocketError::Io(e.to_string()))?;
    fs::write(&path, data).map_err(|e| PocketError::Io(e.to_string()))
}

pub fn balance(
    password: &str,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<String, PocketError> {
    let info = load_keystore(password)?;
    let verified = fetch_balance(&info.address, rpc, token)?;
    serde_json::to_string(&verified).map_err(|e| PocketError::Rpc(e.to_string()))
}

pub fn fetch_balance(
    addr: &str,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<BalanceInfo, PocketError> {
    let cfg = load_config().unwrap_or_default();
    let peers = p2p_bootstrap(&cfg);
    if !peers.is_empty() {
        match p2p::fetch_balance_p2p(addr, &peers) {
            Ok(info) => return Ok(info),
            Err(e) => {
                if rpc.is_none() && cfg.rpc_base.is_none() {
                    return Err(e);
                }
            }
        }
    }
    fetch_balance_rpc(addr, rpc, token, &cfg)
}

fn fetch_balance_rpc(
    addr: &str,
    rpc: Option<String>,
    token: Option<String>,
    cfg: &Config,
) -> Result<BalanceInfo, PocketError> {
    let rpc_base = rpc
        .or(cfg.rpc_base.clone())
        .unwrap_or_else(|| "https://127.0.0.1:8645".to_string());
    let client = rpc_client()?;
    let mut head_req = client.get(format!(
        "{}/weave/chain/head",
        rpc_base.trim_end_matches('/')
    ));
    if let Some(t) = token
        .clone()
        .or(cfg.token.clone())
        .or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok())
    {
        head_req = head_req.bearer_auth(t);
    }
    let head_resp = head_req
        .send()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    if !head_resp.status().is_success() {
        return Err(PocketError::Rpc(format!("http {}", head_resp.status())));
    }
    let head_txt = head_resp
        .text()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    let head_json: serde_json::Value =
        serde_json::from_str(&head_txt).map_err(|e| PocketError::Rpc(e.to_string()))?;
    let head_hash = head_json
        .get("head_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PocketError::Rpc("missing head hash".into()))?;
    let mut block_req = client.get(format!(
        "{}/weave/chain/block?hash={}",
        rpc_base.trim_end_matches('/'),
        head_hash
    ));
    if let Some(t) = token
        .clone()
        .or(cfg.token.clone())
        .or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok())
    {
        block_req = block_req.bearer_auth(t);
    }
    let block_resp = block_req
        .send()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    if !block_resp.status().is_success() {
        return Err(PocketError::Rpc(format!("http {}", block_resp.status())));
    }
    let block_txt = block_resp
        .text()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    let block_json: serde_json::Value =
        serde_json::from_str(&block_txt).map_err(|e| PocketError::Rpc(e.to_string()))?;
    let state_root_hex = block_json
        .get("header")
        .and_then(|h| h.get("state_root"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|n| n.as_u64().map(|u| u as u8))
                .collect();
            hex::encode(bytes)
        })
        .ok_or_else(|| PocketError::Rpc("missing state_root".into()))?;

    let mut proof_req = client.get(format!(
        "{}/weave/chain/account_proof?addr={}",
        rpc_base.trim_end_matches('/'),
        addr
    ));
    if let Some(t) = token
        .clone()
        .or(cfg.token.clone())
        .or_else(|| std::env::var("LANTERN_HTTP_TOKEN").ok())
    {
        proof_req = proof_req.bearer_auth(t);
    }
    let proof_resp = proof_req
        .send()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    if !proof_resp.status().is_success() {
        return Err(PocketError::Rpc(format!("http {}", proof_resp.status())));
    }
    let proof_txt = proof_resp
        .text()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    let proof: AccountProofResponse =
        serde_json::from_str(&proof_txt).map_err(|e| PocketError::Rpc(e.to_string()))?;
    if proof.root != state_root_hex {
        return Err(PocketError::Proof("state_root mismatch".into()));
    }
    if !verify_account_proof(&proof) {
        return Err(PocketError::Proof("invalid account proof".into()));
    }
    Ok(BalanceInfo {
        addr: proof.addr,
        balance: proof.account.balance as u64,
        nonce: proof.account.nonce,
    })
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

#[derive(Serialize)]
struct CanonicalTx<'a> {
    chain_id: &'a str,
    from: &'a str,
    nonce: u64,
    fee: u128,
    timestamp: u64,
    kind: &'a TxKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey_hex: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a Vec<u8>>,
}

fn canonical_tx_bytes(tx: &Transaction, include_signature: bool) -> Result<Vec<u8>, PocketError> {
    let view = CanonicalTx {
        chain_id: tx.chain_id.as_str(),
        from: tx.from.as_str(),
        nonce: tx.nonce,
        fee: tx.fee,
        timestamp: tx.timestamp,
        kind: &tx.kind,
        pubkey_hex: tx.pubkey_hex.as_ref(),
        signature: if include_signature {
            tx.signature.as_ref()
        } else {
            None
        },
    };
    serde_json::to_vec(&view).map_err(|e| PocketError::Crypto(e.to_string()))
}

fn tx_signing_bytes(tx: &Transaction) -> Result<Vec<u8>, PocketError> {
    canonical_tx_bytes(tx, false)
}

pub(crate) fn tx_id_bytes(tx: &Transaction) -> Result<[u8; 32], PocketError> {
    let bytes = canonical_tx_bytes(tx, true)?;
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn build_unsigned_tx(
    from: &str,
    pubkey_hex: &str,
    req: TxBuildRequest,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<Transaction, PocketError> {
    let chain_id = req.chain_id.unwrap_or_else(|| "peace-testnet".into());
    if !address_matches_chain(from, &chain_id) {
        return Err(PocketError::Crypto("hrp/chain_id mismatch".into()));
    }
    let pool_path = req
        .pending_pool
        .clone()
        .or_else(|| std::env::var(ENV_PENDING_POOL).ok());
    let ledger_nonce = fetch_balance(from, rpc.clone(), token.clone())?.nonce;
    let chosen_nonce = match req.nonce {
        Some(n) => n,
        None => pool_path
            .as_deref()
            .and_then(|p| pending_nonce_from_pool(p, from))
            .unwrap_or(ledger_nonce),
    };
    let kind = match req.kind {
        BuildKind::Transfer { to, amount } => TxKind::Transfer {
            to,
            amount: amount as u128,
        },
        BuildKind::Stake {
            amount,
            payout,
            commission_bps,
        } => TxKind::Stake {
            amount: amount as u128,
            payout,
            commission_bps,
        },
        BuildKind::Unbond { amount } => TxKind::Unbond {
            amount: amount as u128,
        },
        BuildKind::UpdateValidator {
            payout,
            commission_bps,
        } => TxKind::UpdateValidator {
            payout,
            commission_bps,
        },
    };

    Ok(Transaction {
        from: from.to_string(),
        nonce: chosen_nonce,
        kind,
        fee: req.fee as u128,
        timestamp: req.timestamp.unwrap_or_else(now_ts),
        chain_id: chain_id.clone(),
        signature: None,
        pubkey_hex: Some(pubkey_hex.to_string()),
    })
}

fn envelope_from_signed_tx(tx: &Transaction) -> Result<TxEnvelope, PocketError> {
    let txid = tx_id_bytes(tx)?;
    let tx_val = serde_json::to_value(tx).map_err(|e| PocketError::Crypto(e.to_string()))?;
    Ok(TxEnvelope {
        tx: tx_val,
        tx_id: hex::encode(txid),
    })
}

fn run_external_signer(command: &str, msg: &[u8]) -> Result<Vec<u8>, PocketError> {
    let mut cmd = if cfg!(windows) {
        let mut inner = Command::new("cmd");
        inner.arg("/C").arg(command);
        inner
    } else {
        let mut inner = Command::new("sh");
        inner.arg("-lc").arg(command);
        inner
    };
    cmd.env("POCKET_SIGN_BYTES_HEX", hex::encode(msg))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd
        .spawn()
        .map_err(|e| PocketError::Crypto(format!("external signer spawn failed: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        stdin
            .write_all(hex::encode(msg).as_bytes())
            .map_err(|e| PocketError::Crypto(format!("external signer stdin failed: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| PocketError::Crypto(format!("external signer wait failed: {e}")))?;
    if !output.status.success() {
        return Err(PocketError::Crypto(format!(
            "external signer exited with status {}",
            output.status
        )));
    }
    let sig_hex = String::from_utf8(output.stdout)
        .map_err(|e| PocketError::Crypto(format!("external signer output was not utf8: {e}")))?;
    hex::decode(sig_hex.trim())
        .map_err(|e| PocketError::Crypto(format!("external signer returned invalid hex: {e}")))
}

fn verify_external_signer_identity(
    chain_id: &str,
    address: &str,
    pubkey_hex: &str,
) -> Result<VerifyingKey, PocketError> {
    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|e| PocketError::Crypto(format!("invalid pubkey hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PocketError::Crypto("pubkey must be 32 bytes".into()))?;
    let verifying =
        VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| PocketError::Crypto(e.to_string()))?;
    let expected_addr = bech32_address(hrp_for_chain(chain_id)?, &verifying)?;
    if expected_addr != address {
        return Err(PocketError::Crypto(format!(
            "external signer address mismatch ({expected_addr} != {address})"
        )));
    }
    Ok(verifying)
}

pub fn build_and_sign_transfer(
    password: &str,
    req: TxBuildRequest,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<TxEnvelope, PocketError> {
    let info = load_keystore(password)?;
    let mut tx = build_unsigned_tx(
        &info.address,
        &info.public_key_hex,
        req,
        rpc,
        token,
    )?;
    let msg = tx_signing_bytes(&tx)?;
    let seed_bytes = Mnemonic::parse_in_normalized(Language::English, &info.mnemonic)
        .map_err(|e| PocketError::Mnemonic(e.to_string()))?
        .to_seed("");
    let sk = SigningKey::from_bytes(&seed_bytes[0..32].try_into().unwrap());
    let sig = sk.sign(&msg);
    tx.signature = Some(sig.to_bytes().to_vec());
    envelope_from_signed_tx(&tx)
}

pub fn build_and_sign_external(
    req: TxBuildRequest,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<TxEnvelope, PocketError> {
    let cfg = load_config().unwrap_or_default();
    let command = cfg
        .external_signer_command
        .ok_or_else(|| PocketError::Crypto("external signer command not configured".into()))?;
    let address = cfg
        .external_signer_address
        .ok_or_else(|| PocketError::Crypto("external signer address not configured".into()))?;
    let pubkey_hex = cfg
        .external_signer_pubkey_hex
        .ok_or_else(|| PocketError::Crypto("external signer pubkey not configured".into()))?;
    let chain_id = req
        .chain_id
        .clone()
        .unwrap_or_else(|| "peace-testnet".into());
    let verifying = verify_external_signer_identity(&chain_id, &address, &pubkey_hex)?;
    let mut tx = build_unsigned_tx(&address, &pubkey_hex, req, rpc, token)?;
    let msg = tx_signing_bytes(&tx)?;
    let sig = run_external_signer(&command, &msg)?;
    let sig_arr: [u8; 64] = sig
        .as_slice()
        .try_into()
        .map_err(|_| PocketError::Crypto("external signer signature must be 64 bytes".into()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying
        .verify(&msg, &signature)
        .map_err(|e| PocketError::Crypto(format!("external signer verification failed: {e}")))?;
    tx.signature = Some(sig);
    envelope_from_signed_tx(&tx)
}

pub fn submit_tx(
    rpc: Option<String>,
    token: Option<String>,
    signed: &serde_json::Value,
) -> Result<String, PocketError> {
    let cfg = load_config().unwrap_or_default();

    let peers = p2p_bootstrap(&cfg);
    if !peers.is_empty() {
        if let Ok(tx) = serde_json::from_value::<Transaction>(signed.clone()) {
            let chain_id = if tx.chain_id.is_empty() {
                "peace-testnet".to_string()
            } else {
                tx.chain_id.clone()
            };
            match p2p::submit_tx_p2p(&tx, &chain_id, &peers) {
                Ok(res) => return Ok(res),
                Err(e) => {
                    // Fall back to HTTP if configured.
                    if rpc.is_none() && cfg.rpc_base.is_none() {
                        return Err(e);
                    }
                }
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_bytes_ignore_signature() {
        let tx = Transaction {
            from: "tpc1test".to_string(),
            nonce: 1,
            kind: TxKind::Transfer {
                to: "tpc1dest".to_string(),
                amount: 2,
            },
            fee: 1,
            timestamp: 123,
            chain_id: "peace-testnet".to_string(),
            signature: Some(vec![0xaa; 64]),
            pubkey_hex: Some("00".repeat(32)),
        };
        let a = tx_signing_bytes(&tx).unwrap();
        let mut tx2 = tx.clone();
        tx2.signature = Some(vec![0xbb; 64]);
        let b = tx_signing_bytes(&tx2).unwrap();
        assert_eq!(a, b, "signature must not affect signing bytes");
    }

    #[test]
    fn peace_spec_transfer_vector_matches() {
        // Keep in sync with lantern/docs/peace-spec.md canonical vectors.
        let mut tx = Transaction {
            from: "tpc1wvt60fl2y8cvzfwdf6fvdfhf9qavzn63jpdzqsy7xjvvgvzgthxs9gmanq".to_string(),
            nonce: 0,
            kind: TxKind::Transfer {
                to: "tpc1k3avtp53c5r53q8ny295n7806l23t02zcn75cqaf6jmxe4kvxmaqudz4xe".to_string(),
                amount: 25,
            },
            fee: 5,
            timestamp: 1700000005,
            chain_id: "peace-testnet".to_string(),
            signature: None,
            pubkey_hex: Some(
                "7317a7a7ea21f0c125cd4e92c6a6e9283ac14f51905a20409e3498c430485dcd".to_string(),
            ),
        };

        let expected_sign_hex = "7b22636861696e5f6964223a2270656163652d746573746e6574222c2266726f6d223a22747063317776743630666c32793863767a6677646636667664666866397161767a6e36336a70647a71737937786a767667767a677468787339676d616e71222c226e6f6e6365223a302c22666565223a352c2274696d657374616d70223a313730303030303030352c226b696e64223a7b225472616e73666572223a7b22746f223a22747063316b33617674703533633572353371386e793239356e373830366c32337430327a636e373563716166366a6d7865346b76786d617175647a347865222c22616d6f756e74223a32357d7d2c227075626b65795f686578223a2237333137613761376561323166306331323563643465393263366136653932383361633134663531393035613230343039653334393863343330343835646364227d";
        let sign_bytes = canonical_tx_bytes(&tx, false).unwrap();
        assert_eq!(
            hex::encode(sign_bytes),
            expected_sign_hex,
            "signing bytes must match Peace spec vector"
        );

        // Now include the signature and validate tx_id.
        let sig = hex::decode("81c8aeae5d72cfe490b051ec8416a62aebcafbef470f78150fa2a39893414f426c26d704f0e7346b115d711dc660dfd2cbf1b720c039c6267c78849177787808")
            .unwrap();
        tx.signature = Some(sig);
        let txid = tx_id_bytes(&tx).unwrap();
        assert_eq!(
            hex::encode(txid),
            "ac7888121ac4d8602f78f8513bebb41fc1d44324bb3314cadceca9015993e1b0",
            "tx_id must match Peace spec vector"
        );
    }

    #[test]
    fn profile_payload_hides_attestation_for_payout_route() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        save_profile(&Profile {
            payout_address: Some("tpc1payout".into()),
            attestation_token: Some("secret-token".into()),
        })
        .unwrap();
        let body = profile_payload(false).unwrap();
        assert!(body.contains("tpc1payout"));
        assert!(!body.contains("secret-token"));
    }

    #[test]
    fn profile_auth_accepts_matching_bearer() {
        let header = Header::from_bytes(&b"Authorization"[..], &b"Bearer token123"[..]).unwrap();
        assert!(has_profile_auth(&[header], "token123"));
    }
}
