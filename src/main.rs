use clap::{Parser, Subcommand};
use pocket_lib::{addr_from_mnemonic, balance, gen_key, init_keystore, load_keystore, chain_head, difficulty, PocketError};

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
}

fn main() {
    let cli = Cli::parse();
    let hrp = cli.hrp.as_str();
    let res: Result<String, PocketError> = match cli.command {
        Commands::Keygen { words } => gen_key(words, hrp).map(|i| serde_json::to_string_pretty(&i).unwrap()),
        Commands::Addr { mnemonic } => addr_from_mnemonic(&mnemonic, hrp).map(|i| serde_json::to_string_pretty(&i).unwrap()),
        Commands::Init { password, hrp } => init_keystore(&password, &hrp).map(|i| serde_json::to_string_pretty(&i).unwrap()),
        Commands::Show { password } => load_keystore(&password).map(|i| serde_json::to_string_pretty(&i).unwrap()),
        Commands::Balance { password, rpc, token } => balance(&password, rpc, token),
        Commands::Head { rpc, token } => chain_head(rpc, token),
        Commands::Difficulty { rpc, token } => difficulty(rpc, token),
    };

    match res {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
