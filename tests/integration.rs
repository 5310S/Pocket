use pocket_lib::{
    build_and_sign_transfer, fetch_balance, gen_key, init_keystore, AccountState, BuildKind,
    TxBuildRequest,
};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::{env, fs, thread};
use tempfile::tempdir;
use tiny_http::{Response, Server};

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Tests should not attempt real P2P connections (keeps them fast/deterministic).
    env::set_var("POCKET_P2P_BOOTSTRAP", "none");
    guard
}

fn sha256(data: &[u8]) -> [u8; 32] {
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
    sha256(&buf)
}

fn account_leaf_hash(addr: &str, account: &AccountState) -> [u8; 32] {
    #[derive(serde::Serialize)]
    struct AccountLeaf<'a> {
        addr: &'a str,
        account: &'a AccountState,
    }
    let leaf = AccountLeaf { addr, account };
    let bytes = serde_json::to_vec(&leaf).expect("serialize leaf");
    state_leaf_hash(&format!("account:{addr}"), &bytes)
}

fn start_mock_rpc(proof_addr: String, nonce: u64) -> String {
    let account = AccountState {
        balance: 123,
        nonce,
        stakes: Vec::new(),
    };
    let root = account_leaf_hash(&proof_addr, &account);
    let root_hex = hex::encode(root);
    let state_root_json: Vec<u64> = root.iter().map(|b| *b as u64).collect();

    // Bind on an ephemeral port.
    let server = Server::http("127.0.0.1:0").unwrap();
    let rpc_base = format!("http://{}", server.server_addr());
    thread::spawn(move || {
        // Handle a small fixed number of requests then exit.
        for rq in server.incoming_requests().take(10) {
            let url = rq.url().to_string();
            let (status, body) = if url.starts_with("/weave/chain/head") {
                (
                    200,
                    serde_json::json!({
                        "height": 42,
                        "head_hash": "headhash",
                    })
                    .to_string(),
                )
            } else if url.starts_with("/weave/chain/block?hash=") {
                (
                    200,
                    serde_json::json!({
                        "header": {
                            "state_root": state_root_json.clone(),
                        }
                    })
                    .to_string(),
                )
            } else if url.starts_with("/weave/chain/account_proof?addr=") {
                (
                    200,
                    serde_json::json!({
                        "addr": proof_addr.clone(),
                        "account": account.clone(),
                        "proof": [],
                        "root": root_hex.clone(),
                        "index": 0,
                        "chain_id": "peace-testnet",
                        "height": 42,
                    })
                    .to_string(),
                )
            } else if url.starts_with("/getDifficulty") {
                (200, r#"{"difficulty":18}"#.to_string())
            } else if url.starts_with("/weave/chain/tx") {
                (200, r#"{"status":"queued"}"#.to_string())
            } else {
                (404, r#"{"error":"not found"}"#.to_string())
            };
            let resp = Response::from_string(body).with_status_code(status);
            let _ = rq.respond(resp);
        }
    });
    rpc_base
}

#[test]
fn pending_pool_nonce_overrides_ledger() {
    let _g = env_guard();
    let tmp = tempdir().unwrap();
    // Isolate HOME so keystore writes into temp space.
    env::set_var("HOME", tmp.path());
    let password = "pw";
    let info = init_keystore(password, "tpc").expect("init keystore");

    // Mock RPC reports ledger nonce = 1.
    let rpc = start_mock_rpc(info.address.clone(), 1);

    // Pool file has a higher pending nonce (2), expecting next = 3.
    let pool_path = tmp.path().join("pool.json");
    let pool_json = serde_json::json!({
        "txs": [
            { "from": info.address, "nonce": 2, "kind": {"Transfer": {"to": info.address, "amount": 1}}, "fee": 1, "timestamp": 1, "chain_id": "peace-testnet" }
        ]
    });
    fs::write(&pool_path, serde_json::to_string(&pool_json).unwrap()).unwrap();

    let env = build_and_sign_transfer(
        password,
        TxBuildRequest {
            kind: BuildKind::Transfer {
                to: info.address.clone(),
                amount: 1,
            },
            fee: 1,
            nonce: None,
            timestamp: Some(1),
            chain_id: Some("peace-testnet".into()),
            memo: None,
            pending_pool: Some(pool_path.to_string_lossy().to_string()),
        },
        Some(rpc),
        None,
    )
    .expect("build");

    let chosen = env.tx.get("nonce").and_then(|n| n.as_u64()).unwrap();
    assert_eq!(chosen, 3, "pending pool should bump nonce");
}

#[test]
fn mock_rpc_round_trip() {
    let _g = env_guard();
    let tmp = tempdir().unwrap();
    env::set_var("HOME", tmp.path());
    let password = "pw2";
    let info = init_keystore(password, "tpc").expect("init keystore");
    let rpc = start_mock_rpc(info.address.clone(), 0);

    // Build simple transfer and submit to mock RPC.
    let env = build_and_sign_transfer(
        password,
        TxBuildRequest {
            kind: BuildKind::Transfer {
                to: info.address.clone(),
                amount: 5,
            },
            fee: 1,
            nonce: None,
            timestamp: Some(1),
            chain_id: Some("peace-testnet".into()),
            memo: None,
            pending_pool: None,
        },
        Some(rpc.clone()),
        None,
    )
    .expect("build");

    // Submit should succeed (mock returns queued).
    let res = pocket_lib::submit_tx(Some(rpc), None, &env.tx).expect("submit");
    assert!(res.contains("queued"));

    // Allow background server thread to finish.
    thread::sleep(Duration::from_millis(50));
}

#[test]
fn rpc_balance_rejects_mismatched_proof_addr() {
    let _g = env_guard();
    let wallet = gen_key(12, "tpc").expect("wallet");
    let other = gen_key(12, "tpc").expect("other wallet");
    let rpc = start_mock_rpc(other.address, 0);

    let err = fetch_balance(&wallet.address, Some(rpc), None).expect_err("mismatched proof");
    assert!(err.to_string().contains("proof addr mismatch"));
}
