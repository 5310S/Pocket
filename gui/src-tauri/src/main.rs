#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use pocket_lib::{
    balance, chain_head, difficulty, export_mnemonic, import_mnemonic, init_keystore, load_config,
    load_keystore, load_profile, save_config, save_profile, submit_tx, build_and_sign_transfer,
    BuildKind, Config, PocketError, Profile, TxBuildRequest,
};

fn map_err(e: PocketError) -> String { e.to_string() }

#[tauri::command]
fn cmd_init(password: String, hrp: String) -> Result<String, String> {
    init_keystore(&password, &hrp).map(|info| serde_json::to_string_pretty(&info).unwrap()).map_err(map_err)
}

#[tauri::command]
fn cmd_show(password: String) -> Result<String, String> {
    load_keystore(&password).map(|info| serde_json::to_string_pretty(&info).unwrap()).map_err(map_err)
}

#[tauri::command]
fn cmd_balance(password: String, rpc: Option<String>, token: Option<String>) -> Result<String, String> {
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
    export_mnemonic(&password).map(|m| serde_json::to_string_pretty(&serde_json::json!({"mnemonic": m})).unwrap()).map_err(map_err)
}

#[tauri::command]
fn cmd_import(password: String, mnemonic: String, hrp: String) -> Result<String, String> {
    import_mnemonic(&password, &mnemonic, &hrp).map(|info| serde_json::to_string_pretty(&info).unwrap()).map_err(map_err)
}

#[tauri::command]
fn cmd_set_config(rpc: Option<String>, token: Option<String>) -> Result<String, String> {
    save_config(&Config { rpc_base: rpc, token }).map(|_| "{\"status\":\"ok\"}".into()).map_err(map_err)
}

#[tauri::command]
fn cmd_show_config() -> Result<String, String> {
    load_config().map(|c| serde_json::to_string_pretty(&c).unwrap()).map_err(map_err)
}

#[tauri::command]
fn cmd_set_profile(address: String, attestation: Option<String>) -> Result<String, String> {
    save_profile(&Profile { payout_address: Some(address), attestation_token: attestation })
        .map(|_| "{\"status\":\"ok\"}".into())
        .map_err(map_err)
}

#[tauri::command]
fn cmd_show_profile() -> Result<String, String> {
    load_profile().map(|p| serde_json::to_string_pretty(&p).unwrap()).map_err(map_err)
}

#[tauri::command]
fn cmd_get_payout() -> Result<String, String> {
    let profile = load_profile().unwrap_or_default();
    Ok(serde_json::to_string_pretty(&profile).unwrap())
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
    let kind_enum = match kind.as_str() {
        "transfer" => BuildKind::Transfer {
            to: to.ok_or_else(|| "missing to".to_string())?,
            amount: amount.ok_or_else(|| "missing amount".to_string())?,
        },
        "stake" => BuildKind::Stake {
            amount: amount.ok_or_else(|| "missing amount".to_string())?,
            payout: payout.ok_or_else(|| "missing payout".to_string())?,
            commission_bps: commission_bps.unwrap_or(0),
        },
        "unbond" => BuildKind::Unbond {
            amount: amount.ok_or_else(|| "missing amount".to_string())?,
        },
        "update-validator" => BuildKind::UpdateValidator {
            payout,
            commission_bps,
        },
        other => return Err(format!("unsupported kind {other}")),
    };

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
    Ok(serde_json::to_string_pretty(&serde_json::json!({"tx_id": env.tx_id, "submit": res})).unwrap())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            cmd_init,
            cmd_show,
            cmd_balance,
            cmd_head,
            cmd_difficulty,
            cmd_export,
            cmd_import,
            cmd_set_config,
            cmd_show_config,
            cmd_set_profile,
            cmd_show_profile,
            cmd_get_payout,
            cmd_send,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
