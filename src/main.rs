use std::path::PathBuf;

use bech32::{encode, ToBase32, Variant};
use bip39::{Language, Mnemonic};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use thiserror::Error;

#[derive(Parser)]
#[command(name = "pocket", version, about = "Pocket wallet for Peace/Weave")] 
struct Cli {
    /// Network HRP (pc for mainnet, tpc for testnet)
    #[arg(long, default_value = "tpc")]
    hrp: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair and mnemonic
    Keygen {
        /// Optional number of words (12|24)
        #[arg(long, default_value_t = 24)]
        words: usize,
        /// Output file to save the secret seed (encrypted storage TBD)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show address/public key for a mnemonic (offline)
    Addr {
        /// Mnemonic words (quoted string)
        mnemonic: String,
    },
}

#[derive(Debug, Error)]
enum PocketError {
    #[error("invalid hrp: {0}")]
    InvalidHrp(String),
    #[error("mnemonic error: {0}")]
    Mnemonic(String),
}

#[derive(Serialize)]
struct KeyInfo {
    mnemonic: String,
    public_key_hex: String,
    address: String,
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

fn gen_key(words: usize, hrp: &str) -> Result<KeyInfo, PocketError> {
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

fn addr_from_mnemonic(mnemonic: &str, hrp: &str) -> Result<KeyInfo, PocketError> {
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

fn main() {
    let cli = Cli::parse();
    let hrp = cli.hrp.as_str();
    let res = match cli.command {
        Commands::Keygen { words, out: _ } => gen_key(words, hrp),
        Commands::Addr { mnemonic } => addr_from_mnemonic(&mnemonic, hrp),
    };

    match res {
        Ok(info) => println!("{}", serde_json::to_string_pretty(&info).unwrap()),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
