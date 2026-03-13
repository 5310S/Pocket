#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use pocket_lib::{
    addr_from_mnemonic, balance, build_and_sign_external, build_and_sign_transfer, chain_head,
    change_password, difficulty, export_mnemonic, gen_key, import_mnemonic, init_keystore,
    load_config, load_keystore, load_profile, save_config, save_profile, serve_profile_http,
    spawn_profile_http, submit_tx, BuildKind, PocketError, Profile, TxBuildRequest,
};

fn map_err(e: PocketError) -> String {
    e.to_string()
}

fn parse_build_kind(
    kind: String,
    to: Option<String>,
    amount: Option<u64>,
    payout: Option<String>,
    commission_bps: Option<u16>,
) -> Result<BuildKind, String> {
    match kind.as_str() {
        "transfer" => Ok(BuildKind::Transfer {
            to: to.ok_or_else(|| "missing to".to_string())?,
            amount: amount.ok_or_else(|| "missing amount".to_string())?,
        }),
        "stake" => Ok(BuildKind::Stake {
            amount: amount.ok_or_else(|| "missing amount".to_string())?,
            payout: payout.ok_or_else(|| "missing payout".to_string())?,
            commission_bps: commission_bps.unwrap_or(0),
        }),
        "unbond" => Ok(BuildKind::Unbond {
            amount: amount.ok_or_else(|| "missing amount".to_string())?,
        }),
        "update-validator" => Ok(BuildKind::UpdateValidator {
            payout,
            commission_bps,
        }),
        other => Err(format!("unsupported kind {other}")),
    }
}

fn tx_reply(env: pocket_lib::TxEnvelope, res: String) -> Result<String, String> {
    Ok(
        serde_json::to_string_pretty(&serde_json::json!({"tx_id": env.tx_id, "submit": res}))
            .unwrap(),
    )
}

#[tauri::command]
fn cmd_init(password: String, hrp: String) -> Result<String, String> {
    init_keystore(&password, &hrp)
        .map(|info| serde_json::to_string_pretty(&info).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_show(password: String) -> Result<String, String> {
    load_keystore(&password)
        .map(|info| serde_json::to_string_pretty(&info).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_keygen(words: usize, hrp: String) -> Result<String, String> {
    gen_key(words, &hrp)
        .map(|info| serde_json::to_string_pretty(&info).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_addr(mnemonic: String, hrp: String) -> Result<String, String> {
    addr_from_mnemonic(&mnemonic, &hrp)
        .map(|info| serde_json::to_string_pretty(&info).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_balance(
    password: String,
    rpc: Option<String>,
    token: Option<String>,
) -> Result<String, String> {
    balance(&password, rpc, token).map_err(map_err)
}

#[tauri::command]
fn cmd_head(rpc: Option<String>, token: Option<String>) -> Result<String, String> {
    chain_head(rpc, token).map_err(map_err)
}

#[tauri::command]
fn cmd_difficulty(rpc: Option<String>, token: Option<String>) -> Result<String, String> {
    difficulty(rpc, token).map_err(map_err)
}

#[tauri::command]
fn cmd_export(password: String) -> Result<String, String> {
    export_mnemonic(&password)
        .map(|m| serde_json::to_string_pretty(&serde_json::json!({"mnemonic": m})).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_import(password: String, mnemonic: String, hrp: String) -> Result<String, String> {
    import_mnemonic(&password, &mnemonic, &hrp)
        .map(|info| serde_json::to_string_pretty(&info).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_change_password(old_password: String, new_password: String) -> Result<String, String> {
    change_password(&old_password, &new_password)
        .map(|_| "{\"status\":\"ok\"}".into())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_set_config(
    rpc: Option<String>,
    token: Option<String>,
    p2p_bootstrap: Option<Vec<String>>,
) -> Result<String, String> {
    let mut cfg = load_config().unwrap_or_default();
    cfg.rpc_base = rpc;
    cfg.token = token;
    if let Some(list) = p2p_bootstrap {
        cfg.p2p_bootstrap = list;
    }
    save_config(&cfg)
        .map(|_| "{\"status\":\"ok\"}".into())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_set_external_signer(
    command: Option<String>,
    address: Option<String>,
    pubkey_hex: Option<String>,
    clear: bool,
) -> Result<String, String> {
    let mut cfg = load_config().unwrap_or_default();
    if clear {
        cfg.external_signer_command = None;
        cfg.external_signer_address = None;
        cfg.external_signer_pubkey_hex = None;
    } else {
        if let Some(value) = command {
            cfg.external_signer_command = Some(value);
        }
        if let Some(value) = address {
            cfg.external_signer_address = Some(value);
        }
        if let Some(value) = pubkey_hex {
            cfg.external_signer_pubkey_hex = Some(value);
        }
    }
    save_config(&cfg)
        .map(|_| "{\"status\":\"ok\"}".into())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_show_config() -> Result<String, String> {
    load_config()
        .map(|c| serde_json::to_string_pretty(&c).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_set_profile(address: String, attestation: Option<String>) -> Result<String, String> {
    save_profile(&Profile {
        payout_address: Some(address),
        attestation_token: attestation,
    })
    .map(|_| "{\"status\":\"ok\"}".into())
    .map_err(map_err)
}

#[tauri::command]
fn cmd_show_profile() -> Result<String, String> {
    load_profile()
        .map(|p| serde_json::to_string_pretty(&p).unwrap())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_get_payout() -> Result<String, String> {
    let profile = load_profile().unwrap_or_default();
    Ok(serde_json::to_string_pretty(&profile).unwrap())
}

#[tauri::command]
fn cmd_serve_profile(bind: String, token: Option<String>, once: bool) -> Result<String, String> {
    let served = if once {
        serve_profile_http(&bind, token, true)
    } else {
        spawn_profile_http(&bind, token)
    }
    .map_err(map_err)?;
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "status": if once { "served-once" } else { "serving" },
        "bind": served,
        "routes": ["/health", "/payout", "/profile"]
    }))
    .unwrap())
}

#[tauri::command]
fn cmd_send(
    password: String,
    kind: String,
    to: Option<String>,
    amount: Option<u64>,
    payout: Option<String>,
    commission_bps: Option<u16>,
    fee: u64,
    nonce: Option<u64>,
    timestamp: Option<u64>,
    chain_id: Option<String>,
    rpc: Option<String>,
    token: Option<String>,
    pending_pool: Option<String>,
) -> Result<String, String> {
    let kind_enum = parse_build_kind(kind, to, amount, payout, commission_bps)?;

    let env = build_and_sign_transfer(
        &password,
        TxBuildRequest {
            kind: kind_enum,
            fee,
            nonce,
            timestamp,
            chain_id,
            memo: None,
            pending_pool,
        },
        rpc.clone(),
        token.clone(),
    )
    .map_err(map_err)?;
    let res = submit_tx(rpc, token, &env.tx).map_err(map_err)?;
    tx_reply(env, res)
}

#[tauri::command]
fn cmd_send_external(
    kind: String,
    to: Option<String>,
    amount: Option<u64>,
    payout: Option<String>,
    commission_bps: Option<u16>,
    fee: u64,
    nonce: Option<u64>,
    timestamp: Option<u64>,
    chain_id: Option<String>,
    rpc: Option<String>,
    token: Option<String>,
    pending_pool: Option<String>,
) -> Result<String, String> {
    let kind_enum = parse_build_kind(kind, to, amount, payout, commission_bps)?;

    let env = build_and_sign_external(
        TxBuildRequest {
            kind: kind_enum,
            fee,
            nonce,
            timestamp,
            chain_id,
            memo: None,
            pending_pool,
        },
        rpc.clone(),
        token.clone(),
    )
    .map_err(map_err)?;
    let res = submit_tx(rpc, token, &env.tx).map_err(map_err)?;
    tx_reply(env, res)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            cmd_init,
            cmd_show,
            cmd_keygen,
            cmd_addr,
            cmd_balance,
            cmd_head,
            cmd_difficulty,
            cmd_export,
            cmd_import,
            cmd_change_password,
            cmd_set_config,
            cmd_set_external_signer,
            cmd_show_config,
            cmd_set_profile,
            cmd_show_profile,
            cmd_get_payout,
            cmd_serve_profile,
            cmd_send,
            cmd_send_external,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
