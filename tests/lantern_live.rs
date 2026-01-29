//! Live integration against a Lantern RPC endpoint.
//! Skips unless LANTERN_RPC is set; use --ignored to run.

use pocket_lib::{
    build_and_sign_transfer, fetch_balance, init_keystore, submit_tx, BuildKind, TxBuildRequest,
};

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[test]
#[ignore]
fn live_submit_smoke() {
    let rpc = match env_or_skip("LANTERN_RPC") {
        Some(v) => v,
        None => {
            eprintln!("skipping live_submit_smoke: set LANTERN_RPC");
            return;
        }
    };
    let token = env_or_skip("LANTERN_TOKEN");

    // Use an isolated keystore; requires funds to exist at this mnemonic.
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", tmp.path());
    let password = "livepw";
    let info = init_keystore(password, "tpc").expect("init");

    // Fetch balance/nonce; will fail if rpc is unreachable.
    let bal = fetch_balance(&info.address, Some(rpc.clone()), token.clone()).expect("get balance");

    // Build self-transfer with tiny amount; requires funds >= fee+amount.
    let env = build_and_sign_transfer(
        password,
        TxBuildRequest {
            kind: BuildKind::Transfer {
                to: info.address.clone(),
                amount: 1,
            },
            fee: 1,
            nonce: Some(bal.nonce),
            timestamp: None,
            chain_id: Some("peace-testnet".into()),
            memo: None,
            pending_pool: None,
        },
        Some(rpc.clone()),
        token.clone(),
    )
    .expect("build");

    let res = submit_tx(Some(rpc), token, &env.tx).expect("submit");
    assert!(
        res.contains("queued") || res.contains("ok"),
        "unexpected submit response: {res}"
    );
}
