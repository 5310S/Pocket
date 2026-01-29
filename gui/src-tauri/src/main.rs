#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use pocket_lib::{balance, chain_head, difficulty, init_keystore, load_keystore, PocketError};

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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            cmd_init,
            cmd_show,
            cmd_balance,
            cmd_head,
            cmd_difficulty
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
