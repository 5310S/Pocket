use clap::{Parser, Subcommand};
use pocket_lib::{
    addr_from_mnemonic, balance, build_and_sign_transfer, chain_head, difficulty, export_mnemonic,
    gen_key, import_mnemonic, init_keystore, load_config, load_keystore, load_profile, save_config,
    save_profile, submit_tx, BuildKind, PocketError, Profile, TxBuildRequest,
};

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
    },
    /// Show address/public key for a mnemonic (offline)
    Addr {
        /// Mnemonic words (quoted string)
        mnemonic: String,
    },
    /// Import mnemonic into keystore
    Import {
        #[arg(long)]
        password: String,
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "tpc")]
        hrp: String,
    },
    /// Export mnemonic from keystore
    Export {
        #[arg(long)]
        password: String,
    },
    /// Save RPC/token config
    SetConfig {
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Save mining payout profile
    SetPayout {
        #[arg(long)]
        address: String,
        #[arg(long)]
        attestation: Option<String>,
    },
    /// Show saved config
    ShowConfig,
    /// Show saved profile
    ShowProfile,
    /// Initialize an encrypted keystore
    Init {
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "tpc")]
        hrp: String,
    },
    /// Show address/public key from the keystore
    Show {
        #[arg(long)]
        password: String,
    },
    /// Check RPC health and balance using the keystore address
    Balance {
        #[arg(long)]
        password: String,
        /// RPC base URL (default https://127.0.0.1:8645)
        #[arg(long)]
        rpc: Option<String>,
        /// Bearer token for Lantern RPC
        #[arg(long)]
        token: Option<String>,
    },
    /// Show chain head via Lantern RPC
    Head {
        /// RPC base URL (default https://127.0.0.1:8645)
        #[arg(long)]
        rpc: Option<String>,
        /// Bearer token for Lantern RPC
        #[arg(long)]
        token: Option<String>,
    },
    /// Show difficulty via Lantern RPC
    Difficulty {
        /// RPC base URL (default https://127.0.0.1:8645)
        #[arg(long)]
        rpc: Option<String>,
        /// Bearer token for Lantern RPC
        #[arg(long)]
        token: Option<String>,
    },
    /// Build, sign, and submit a transaction
    Send {
        #[arg(long)]
        password: String,
        /// Tx kind: transfer | stake | unbond | update-validator
        #[arg(long, default_value = "transfer")]
        kind: String,
        /// Destination for transfers
        #[arg(long)]
        to: Option<String>,
        /// Amount (transfer / stake / unbond)
        #[arg(long)]
        amount: Option<u64>,
        /// Payout address (stake / update-validator)
        #[arg(long)]
        payout: Option<String>,
        /// Commission basis points (stake / update-validator)
        #[arg(long)]
        commission_bps: Option<u16>,
        #[arg(long, default_value_t = 1)]
        fee: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        timestamp: Option<u64>,
        #[arg(long)]
        chain_id: Option<String>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        token: Option<String>,
        /// Optional path to Lantern tx pool file to include pending nonces
        #[arg(long)]
        pending_pool: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let hrp = cli.hrp.as_str();
    let res: Result<String, PocketError> = match cli.command {
        Commands::Keygen { words } => {
            gen_key(words, hrp).map(|i| serde_json::to_string_pretty(&i).unwrap())
        }
        Commands::Addr { mnemonic } => {
            addr_from_mnemonic(&mnemonic, hrp).map(|i| serde_json::to_string_pretty(&i).unwrap())
        }
        Commands::Init { password, hrp } => {
            init_keystore(&password, &hrp).map(|i| serde_json::to_string_pretty(&i).unwrap())
        }
        Commands::Show { password } => {
            load_keystore(&password).map(|i| serde_json::to_string_pretty(&i).unwrap())
        }
        Commands::Import {
            password,
            mnemonic,
            hrp,
        } => import_mnemonic(&password, &mnemonic, &hrp)
            .map(|i| serde_json::to_string_pretty(&i).unwrap()),
        Commands::Export { password } => export_mnemonic(&password)
            .map(|m| serde_json::to_string_pretty(&serde_json::json!({"mnemonic": m})).unwrap()),
        Commands::SetConfig { rpc, token } => {
            let mut cfg = load_config().unwrap_or_default();
            cfg.rpc_base = rpc;
            cfg.token = token;
            save_config(&cfg).map(|_| "{\"status\":\"ok\"}".into())
        }
        Commands::ShowConfig => load_config().map(|c| serde_json::to_string_pretty(&c).unwrap()),
        Commands::SetPayout {
            address,
            attestation,
        } => save_profile(&Profile {
            payout_address: Some(address),
            attestation_token: attestation,
        })
        .map(|_| "{\"status\":\"ok\"}".into()),
        Commands::ShowProfile => load_profile().map(|p| serde_json::to_string_pretty(&p).unwrap()),
        Commands::Balance {
            password,
            rpc,
            token,
        } => balance(&password, rpc, token),
        Commands::Head { rpc, token } => chain_head(rpc, token),
        Commands::Difficulty { rpc, token } => difficulty(rpc, token),
        Commands::Send {
            password,
            kind,
            to,
            amount,
            payout,
            commission_bps,
            fee,
            nonce,
            timestamp,
            chain_id,
            rpc,
            token,
            pending_pool,
        } => {
            let kind_enum = match kind.as_str() {
                "transfer" => BuildKind::Transfer {
                    to: to.ok_or_else(|| PocketError::Rpc("missing --to for transfer".into()))?,
                    amount: amount
                        .ok_or_else(|| PocketError::Rpc("missing --amount for transfer".into()))?,
                },
                "stake" => BuildKind::Stake {
                    amount: amount
                        .ok_or_else(|| PocketError::Rpc("missing --amount for stake".into()))?,
                    payout: payout
                        .ok_or_else(|| PocketError::Rpc("missing --payout for stake".into()))?,
                    commission_bps: commission_bps.unwrap_or(0),
                },
                "unbond" => BuildKind::Unbond {
                    amount: amount
                        .ok_or_else(|| PocketError::Rpc("missing --amount for unbond".into()))?,
                },
                "update-validator" => BuildKind::UpdateValidator {
                    payout,
                    commission_bps,
                },
                other => Err(PocketError::Rpc(format!("unsupported kind {other}")))?,
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
            )?;
            let submit = submit_tx(rpc, token, &env.tx)?;
            Ok(serde_json::to_string_pretty(
                &serde_json::json!({"tx_id": env.tx_id, "submit": submit}),
            )
            .unwrap())
        }
    };

    match res {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
