use pocket_lib::{build_and_sign_transfer, init_keystore, BuildKind, TxBuildRequest};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::{env, fs, thread};
use tempfile::tempdir;
use tiny_http::{Response, Server};

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn start_mock_rpc(nonce: u64) -> String {
    // Bind on an ephemeral port.
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", server.server_addr());
    thread::spawn(move || {
        // Handle a small fixed number of requests then exit.
        for rq in server.incoming_requests().take(5) {
            let url = rq.url().to_string();
            let (status, body) = if url.starts_with("/getBalance") {
                (
                    200,
                    format!(r#"{{"addr":"tpc1test","balance":123,"nonce":{nonce}}}"#),
                )
            } else if url.starts_with("/weave/chain/head") {
                (200, r#"{"height":42}"#.to_string())
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
    addr
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
    let rpc = start_mock_rpc(1);

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
    let rpc = start_mock_rpc(0);

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
