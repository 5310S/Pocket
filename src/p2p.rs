use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bech32::{decode, FromBase32};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{AccountState, BalanceInfo, PocketError, Transaction};

const PROTOCOL_VERSION: u32 = 2;
const DEFAULT_P2P_PORT: u16 = 3000;
const READ_TIMEOUT_SECS: u64 = 5;
const MAX_FRAME_BYTES: usize = 512 * 1024;
const FEATURE_MINING_ATTESTATION: &str = "mining-attestation";
const FEATURE_CHAIN_ID_PREFIX: &str = "chain-id:";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NodeRole {
    Full,
    Validator,
    Light,
}

fn default_chain_id() -> String {
    "peace-testnet".to_string()
}

fn default_difficulty_bits() -> u32 {
    18
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockHeader {
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    height: u64,
    proposer: String,
    #[serde(default)]
    miner: Option<String>,
    timestamp: u64,
    #[serde(default = "default_chain_id")]
    chain_id: String,
    #[serde(default)]
    nonce: u64,
    #[serde(default = "default_difficulty_bits")]
    difficulty: u32,
    #[serde(default)]
    signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HeaderBundle {
    hash: [u8; 32],
    header: BlockHeader,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HelloPayload {
    node_id: u64,
    role: NodeRole,
    listen_port: u16,
    pub_key: Vec<u8>,
    chain_id: String,
    head_height: u64,
    head_hash: Option<[u8; 32]>,
    #[serde(default = "default_protocol_version")]
    protocol_version: u32,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    binary_hash: Option<String>,
    #[serde(default)]
    vpn_addr: Option<String>,
    #[serde(default)]
    vpn_cidr: Option<String>,
    #[serde(default)]
    vpn_pubkey: Option<String>,
    #[serde(default)]
    vpn_endpoint: Option<String>,
    #[serde(default)]
    vpn_kernel: Option<bool>,
}

fn default_protocol_version() -> u32 {
    PROTOCOL_VERSION
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum P2PMessage {
    Hello {
        node_id: u64,
        role: NodeRole,
        listen_port: u16,
        pub_key: Vec<u8>,
        signature: Vec<u8>,
        chain_id: String,
        head_height: u64,
        head_hash: Option<[u8; 32]>,
        #[serde(default = "default_protocol_version")]
        protocol_version: u32,
        #[serde(default)]
        features: Vec<String>,
        #[serde(default)]
        binary_hash: Option<String>,
        #[serde(default)]
        vpn_addr: Option<String>,
        #[serde(default)]
        vpn_cidr: Option<String>,
        #[serde(default)]
        vpn_pubkey: Option<String>,
        #[serde(default)]
        vpn_endpoint: Option<String>,
        #[serde(default)]
        vpn_kernel: Option<bool>,
    },
    Ping(u64),
    Pong(u64),
    InvTx(Vec<[u8; 32]>),
    GetTx(Vec<[u8; 32]>),
    Headers(Vec<HeaderBundle>),
    GetHeaders {
        from: u64,
        to: Option<u64>,
    },
    GetAccountProof {
        addr: String,
    },
    AccountProof {
        proof: AccountProof,
        height: u64,
        chain_id: String,
    },
    Gossip {
        payload: GossipPayload,
        pub_key: Vec<u8>,
        signature: Vec<u8>,
    },
    Disconnect {
        reason: String,
    },
    Ignored,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum GossipPayload {
    Tx(Transaction),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountProof {
    addr: String,
    account: AccountState,
    proof: Vec<AccountProofItem>,
    root: [u8; 32],
    index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountProofItem {
    hash: [u8; 32],
    position: String,
}

pub fn fetch_balance_p2p(addr: &str, peers: &[String]) -> Result<BalanceInfo, PocketError> {
    if peers.is_empty() {
        return Err(PocketError::Rpc("p2p peer list empty".into()));
    }
    let chain_id = chain_id_from_addr(addr).unwrap_or("peace-testnet");
    let mut last_err: Option<PocketError> = None;
    for peer in peers {
        match fetch_balance_from_peer(addr, peer, chain_id) {
            Ok(info) => return Ok(info),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| PocketError::Rpc("p2p failed".into())))
}

pub fn submit_tx_p2p(
    tx: &Transaction,
    chain_id: &str,
    peers: &[String],
) -> Result<String, PocketError> {
    if peers.is_empty() {
        return Err(PocketError::Rpc("p2p peer list empty".into()));
    }
    let tx_id = crate::tx_id_bytes(tx)?;
    let mut last_err: Option<PocketError> = None;
    for peer in peers {
        match submit_tx_to_peer(tx, chain_id, peer, &tx_id) {
            Ok(()) => {
                let resp = serde_json::json!({
                    "status": "gossiped",
                    "peer": peer,
                    "tx_id": hex::encode(tx_id),
                });
                return Ok(resp.to_string());
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| PocketError::Rpc("p2p submit failed".into())))
}

fn fetch_balance_from_peer(
    addr: &str,
    peer: &str,
    chain_id: &str,
) -> Result<BalanceInfo, PocketError> {
    let mut stream = connect_peer(peer)?;
    let (hello, _signing) = perform_handshake(&mut stream, chain_id)?;
    if hello.chain_id != chain_id {
        return Err(PocketError::Rpc("p2p chain_id mismatch".into()));
    }
    let head_height = hello.head_height;
    let header = request_header(&mut stream, head_height)?;
    if header.chain_id != chain_id {
        return Err(PocketError::Proof("header chain_id mismatch".into()));
    }
    verify_header_signature(&header)?;
    let proof = request_account_proof(&mut stream, addr)?;
    if proof.addr != addr {
        return Err(PocketError::Proof("proof addr mismatch".into()));
    }
    if proof.root != header.state_root {
        return Err(PocketError::Proof("state_root mismatch".into()));
    }
    if !verify_account_proof_bytes(&proof) {
        return Err(PocketError::Proof("invalid account proof".into()));
    }
    if proof.account.balance > u64::MAX as u128 {
        return Err(PocketError::Proof("balance overflow".into()));
    }
    Ok(BalanceInfo {
        addr: proof.addr,
        balance: proof.account.balance as u64,
        nonce: proof.account.nonce,
    })
}

fn submit_tx_to_peer(
    tx: &Transaction,
    chain_id: &str,
    peer: &str,
    tx_id: &[u8; 32],
) -> Result<(), PocketError> {
    let mut stream = connect_peer(peer)?;
    let (_hello, signing) = perform_handshake(&mut stream, chain_id)?;
    write_msg(&mut stream, &P2PMessage::InvTx(vec![*tx_id]))?;
    let start = Instant::now();
    let mut scratch = Vec::new();
    loop {
        if start.elapsed() > Duration::from_secs(READ_TIMEOUT_SECS) {
            return Err(PocketError::Rpc("p2p gettx timeout".into()));
        }
        let msg = read_msg(&mut stream, &mut scratch)?;
        match msg {
            Some(P2PMessage::GetTx(ids)) => {
                if ids.iter().any(|id| id == tx_id) {
                    let payload = GossipPayload::Tx(tx.clone());
                    let sig = signing.sign(
                        &serde_json::to_vec(&payload)
                            .map_err(|e| PocketError::Rpc(e.to_string()))?,
                    );
                    let response = P2PMessage::Gossip {
                        payload,
                        pub_key: signing.verifying_key().to_bytes().to_vec(),
                        signature: sig.to_bytes().to_vec(),
                    };
                    write_msg(&mut stream, &response)?;
                    return Ok(());
                }
            }
            Some(P2PMessage::Ping(ts)) => write_msg(&mut stream, &P2PMessage::Pong(ts))?,
            Some(P2PMessage::Disconnect { reason }) => {
                return Err(PocketError::Rpc(format!("p2p disconnect: {reason}")))
            }
            Some(_) => continue,
            None => return Err(PocketError::Rpc("p2p closed".into())),
        }
    }
}

fn connect_peer(addr: &str) -> Result<TcpStream, PocketError> {
    let target = normalize_peer_addr(addr);
    let mut addrs = target
        .to_socket_addrs()
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    let first = addrs
        .next()
        .ok_or_else(|| PocketError::Rpc("no peer addr".into()))?;
    let stream = TcpStream::connect_timeout(&first, Duration::from_secs(READ_TIMEOUT_SECS))
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    Ok(stream)
}

fn normalize_peer_addr(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:{DEFAULT_P2P_PORT}")
    }
}

fn perform_handshake(
    stream: &mut TcpStream,
    chain_id: &str,
) -> Result<(HelloPayload, SigningKey), PocketError> {
    let signing = SigningKey::generate(&mut OsRng);
    let mut node_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut node_bytes);
    let node_id = u64::from_be_bytes(node_bytes);
    let pub_key = signing.verifying_key().to_bytes().to_vec();
    let hello_payload = HelloPayload {
        node_id,
        role: NodeRole::Light,
        listen_port: 0,
        pub_key: pub_key.clone(),
        chain_id: chain_id.to_string(),
        head_height: 0,
        head_hash: None,
        protocol_version: PROTOCOL_VERSION,
        features: hello_features(chain_id),
        binary_hash: None,
        vpn_addr: None,
        vpn_cidr: None,
        vpn_pubkey: None,
        vpn_endpoint: None,
        vpn_kernel: None,
    };
    let sig = signing
        .sign(&serde_json::to_vec(&hello_payload).map_err(|e| PocketError::Rpc(e.to_string()))?);
    let hello = P2PMessage::Hello {
        node_id,
        role: NodeRole::Light,
        listen_port: 0,
        pub_key,
        signature: sig.to_bytes().to_vec(),
        chain_id: chain_id.to_string(),
        head_height: 0,
        head_hash: None,
        protocol_version: PROTOCOL_VERSION,
        features: hello_payload.features.clone(),
        binary_hash: None,
        vpn_addr: None,
        vpn_cidr: None,
        vpn_pubkey: None,
        vpn_endpoint: None,
        vpn_kernel: None,
    };
    write_msg(stream, &hello)?;
    write_msg(stream, &P2PMessage::Ping(now_millis()))?;
    let start = Instant::now();
    let mut scratch = Vec::new();
    loop {
        if start.elapsed() > Duration::from_secs(READ_TIMEOUT_SECS) {
            return Err(PocketError::Rpc("p2p hello timeout".into()));
        }
        let msg = read_msg(stream, &mut scratch)?;
        match msg {
            Some(P2PMessage::Hello {
                node_id,
                role,
                listen_port,
                pub_key,
                signature,
                chain_id,
                head_height,
                head_hash,
                protocol_version,
                features,
                binary_hash,
                vpn_addr,
                vpn_cidr,
                vpn_pubkey,
                vpn_endpoint,
                vpn_kernel,
            }) => {
                let payload = HelloPayload {
                    node_id,
                    role,
                    listen_port,
                    pub_key: pub_key.clone(),
                    chain_id: chain_id.clone(),
                    head_height,
                    head_hash,
                    protocol_version,
                    features,
                    binary_hash,
                    vpn_addr,
                    vpn_cidr,
                    vpn_pubkey,
                    vpn_endpoint,
                    vpn_kernel,
                };
                verify_hello(&payload, &pub_key, &signature)?;
                return Ok((payload, signing));
            }
            Some(P2PMessage::Ping(ts)) => {
                write_msg(stream, &P2PMessage::Pong(ts))?;
            }
            Some(P2PMessage::Disconnect { reason }) => {
                return Err(PocketError::Rpc(format!("p2p disconnect: {reason}")));
            }
            Some(_) => continue,
            None => return Err(PocketError::Rpc("p2p closed".into())),
        }
    }
}

fn request_header(stream: &mut TcpStream, height: u64) -> Result<BlockHeader, PocketError> {
    let (from, to) = if height == 0 {
        (0, Some(512))
    } else {
        (height, Some(height))
    };
    write_msg(stream, &P2PMessage::GetHeaders { from, to })?;
    let start = Instant::now();
    let mut scratch = Vec::new();
    loop {
        if start.elapsed() > Duration::from_secs(READ_TIMEOUT_SECS) {
            return Err(PocketError::Rpc("p2p headers timeout".into()));
        }
        let msg = read_msg(stream, &mut scratch)?;
        match msg {
            Some(P2PMessage::Headers(list)) => {
                if list.is_empty() {
                    return Err(PocketError::Rpc("header not found".into()));
                }
                if height == 0 {
                    let best = list
                        .into_iter()
                        .max_by_key(|b| b.header.height)
                        .ok_or_else(|| PocketError::Rpc("header not found".into()))?;
                    return Ok(best.header);
                }
                let header = list
                    .into_iter()
                    .find(|b| b.header.height == height)
                    .ok_or_else(|| PocketError::Rpc("header not found".into()))?;
                return Ok(header.header);
            }
            Some(P2PMessage::Ping(ts)) => write_msg(stream, &P2PMessage::Pong(ts))?,
            Some(P2PMessage::Disconnect { reason }) => {
                return Err(PocketError::Rpc(format!("p2p disconnect: {reason}")))
            }
            Some(_) => continue,
            None => return Err(PocketError::Rpc("p2p closed".into())),
        }
    }
}

fn request_account_proof(stream: &mut TcpStream, addr: &str) -> Result<AccountProof, PocketError> {
    write_msg(
        stream,
        &P2PMessage::GetAccountProof {
            addr: addr.to_string(),
        },
    )?;
    let start = Instant::now();
    let mut scratch = Vec::new();
    loop {
        if start.elapsed() > Duration::from_secs(READ_TIMEOUT_SECS) {
            return Err(PocketError::Rpc("p2p proof timeout".into()));
        }
        let msg = read_msg(stream, &mut scratch)?;
        match msg {
            Some(P2PMessage::AccountProof { proof, .. }) => return Ok(proof),
            Some(P2PMessage::Ping(ts)) => write_msg(stream, &P2PMessage::Pong(ts))?,
            Some(P2PMessage::Disconnect { reason }) => {
                return Err(PocketError::Rpc(format!("p2p disconnect: {reason}")))
            }
            Some(_) => continue,
            None => return Err(PocketError::Rpc("p2p closed".into())),
        }
    }
}

fn read_msg(
    stream: &mut TcpStream,
    scratch: &mut Vec<u8>,
) -> Result<Option<P2PMessage>, PocketError> {
    let frame = match read_frame(stream, scratch)? {
        Some(f) => f,
        None => return Ok(None),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&frame).map_err(|e| PocketError::Rpc(e.to_string()))?;
    let key = value
        .as_object()
        .and_then(|obj| obj.keys().next().map(|k| k.as_str().to_string()))
        .unwrap_or_default();
    let msg = match key.as_str() {
        "Hello" | "Ping" | "Pong" | "InvTx" | "GetTx" | "Headers" | "GetHeaders"
        | "GetAccountProof" | "AccountProof" | "Gossip" | "Disconnect" => {
            serde_json::from_value(value).map_err(|e| PocketError::Rpc(e.to_string()))?
        }
        _ => P2PMessage::Ignored,
    };
    Ok(Some(msg))
}

fn read_frame(
    stream: &mut TcpStream,
    scratch: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, PocketError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(PocketError::Rpc(e.to_string())),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(PocketError::Rpc("invalid frame length".into()));
    }
    scratch.resize(len, 0);
    stream
        .read_exact(&mut scratch[..len])
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    Ok(Some(scratch[..len].to_vec()))
}

fn write_msg(stream: &mut TcpStream, msg: &P2PMessage) -> Result<(), PocketError> {
    let payload = serde_json::to_vec(msg).map_err(|e| PocketError::Rpc(e.to_string()))?;
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| PocketError::Rpc(e.to_string()))?;
    stream
        .write_all(&payload)
        .map_err(|e| PocketError::Rpc(e.to_string()))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn hello_features(chain_id: &str) -> Vec<String> {
    vec![
        format!("{FEATURE_CHAIN_ID_PREFIX}{chain_id}"),
        FEATURE_MINING_ATTESTATION.to_string(),
        "light-client".to_string(),
    ]
}

fn verify_hello(
    payload: &HelloPayload,
    pub_key: &[u8],
    signature: &[u8],
) -> Result<(), PocketError> {
    let key_bytes: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| PocketError::Rpc("bad_pub_key_len".into()))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| PocketError::Rpc("bad_sig_len".into()))?;
    let vk = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| PocketError::Rpc("invalid_pub_key".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = serde_json::to_vec(payload).map_err(|e| PocketError::Rpc(e.to_string()))?;
    vk.verify_strict(&msg, &sig)
        .map_err(|_| PocketError::Rpc("invalid_signature".into()))?;
    Ok(())
}

fn chain_id_from_addr(addr: &str) -> Option<&'static str> {
    if addr.starts_with("pc") {
        Some("peace-mainnet")
    } else if addr.starts_with("tpc") {
        Some("peace-testnet")
    } else {
        None
    }
}

fn chain_id_hrp(chain_id: &str) -> Option<&'static str> {
    if chain_id.starts_with("peace-mainnet") {
        Some("pc")
    } else if chain_id.starts_with("peace-testnet") {
        Some("tpc")
    } else {
        None
    }
}

fn address_to_pubkey_bytes(addr: &str, chain_id: &str) -> Result<[u8; 32], PocketError> {
    let (hrp, data, _) = decode(addr).map_err(|e| PocketError::Proof(e.to_string()))?;
    let expected =
        chain_id_hrp(chain_id).ok_or_else(|| PocketError::Proof("bad chain_id".into()))?;
    if hrp != expected {
        return Err(PocketError::Proof("hrp mismatch".into()));
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|e| PocketError::Proof(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(PocketError::Proof("invalid pubkey length".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Serialize)]
struct CanonicalHeader<'a> {
    parent_hash: &'a [u8; 32],
    state_root: &'a [u8; 32],
    height: u64,
    proposer: &'a String,
    #[serde(skip_serializing_if = "Option::is_none")]
    miner: Option<&'a String>,
    timestamp: u64,
    chain_id: &'a String,
    nonce: u64,
    difficulty: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a Vec<u8>>,
}

fn block_signing_bytes(header: &BlockHeader) -> Result<Vec<u8>, PocketError> {
    let unsigned = CanonicalHeader {
        parent_hash: &header.parent_hash,
        state_root: &header.state_root,
        height: header.height,
        proposer: &header.proposer,
        miner: header.miner.as_ref(),
        timestamp: header.timestamp,
        chain_id: &header.chain_id,
        nonce: header.nonce,
        difficulty: header.difficulty,
        signature: None,
    };
    serde_json::to_vec(&unsigned).map_err(|e| PocketError::Proof(e.to_string()))
}

fn verify_header_signature(header: &BlockHeader) -> Result<(), PocketError> {
    if header.height == 0 {
        return Ok(());
    }
    let sig_bytes = header
        .signature
        .as_ref()
        .ok_or_else(|| PocketError::Proof("missing_block_signature".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PocketError::Proof("invalid_block_signature".into()))?;
    let vk_bytes = address_to_pubkey_bytes(&header.proposer, &header.chain_id)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|_| PocketError::Proof("invalid_block_pubkey".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    let msg = block_signing_bytes(header)?;
    vk.verify_strict(&msg, &sig)
        .map_err(|_| PocketError::Proof("invalid_block_signature".into()))?;
    Ok(())
}

fn verify_account_proof_bytes(proof: &AccountProof) -> bool {
    let mut hash = match crate::account_leaf_hash(&proof.addr, &proof.account) {
        Ok(h) => h,
        Err(_) => return false,
    };
    for item in &proof.proof {
        let mut buf = Vec::with_capacity(64);
        if item.position == "left" {
            buf.extend_from_slice(&item.hash);
            buf.extend_from_slice(&hash);
        } else if item.position == "right" {
            buf.extend_from_slice(&hash);
            buf.extend_from_slice(&item.hash);
        } else {
            return false;
        }
        hash = crate::hash_bytes(&buf);
    }
    hash == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn verify_header_signature_roundtrip() {
        let signing = SigningKey::generate(&mut OsRng);
        let addr = crate::bech32_address("tpc", &signing.verifying_key()).unwrap();
        let mut header = BlockHeader {
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            height: 1,
            proposer: addr,
            miner: None,
            timestamp: 1,
            chain_id: "peace-testnet".to_string(),
            nonce: 0,
            difficulty: 18,
            signature: None,
        };
        let sig = signing.sign(&block_signing_bytes(&header).unwrap());
        header.signature = Some(sig.to_bytes().to_vec());
        assert!(verify_header_signature(&header).is_ok());
    }

    #[test]
    fn verify_account_proof_single_leaf() {
        let account = AccountState {
            balance: 5,
            nonce: 1,
            stakes: Vec::new(),
        };
        let leaf = crate::account_leaf_hash("tpc1test", &account).unwrap();
        let proof = AccountProof {
            addr: "tpc1test".to_string(),
            account,
            proof: Vec::new(),
            root: leaf,
            index: 0,
        };
        assert!(verify_account_proof_bytes(&proof));
    }
}
