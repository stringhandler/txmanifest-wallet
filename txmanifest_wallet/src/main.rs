use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tx_manifest_lib::lifecycle::OutpointOverride;
use tx_manifest_lib::target::Target;
use tx_manifest_lib::{config, describe, instance, lifecycle, manifest, prepare, validate, wallet};

/// Build the input-override map from `--input id=txid:vout` flags and an optional
/// `--inputs-file` JSON. File entries load first; `--input` flags override them.
fn build_provided_inputs(
    inputs: &[String],
    inputs_file: Option<&Path>,
) -> Result<HashMap<String, OutpointOverride>> {
    let mut map: HashMap<String, OutpointOverride> = HashMap::new();

    if let Some(path) = inputs_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read inputs file: {}", path.display()))?;
        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)
            .with_context(|| format!("inputs file must be a JSON object: {}", path.display()))?;
        for (id, value) in obj {
            let ov = match value {
                // Shorthand string form "txid:vout".
                serde_json::Value::String(s) => OutpointOverride::parse_outpoint(&s)
                    .with_context(|| format!("inputs file entry '{id}'"))?,
                // Full object form { txid, vout, amount_sat?, asset? }.
                other => serde_json::from_value(other)
                    .with_context(|| format!("inputs file entry '{id}' is not a valid override"))?,
            };
            map.insert(id, ov);
        }
    }

    for spec in inputs {
        let (id, outpoint) = spec
            .split_once('=')
            .with_context(|| format!("--input must be <id>=<txid>:<vout>, got '{spec}'"))?;
        let ov = OutpointOverride::parse_outpoint(outpoint)
            .with_context(|| format!("--input '{id}'"))?;
        map.insert(id.trim().to_string(), ov);
    }

    Ok(map)
}

#[derive(Parser)]
#[command(name = "tx-manifest-wallet")]
#[command(version)]
#[command(about = "tx-manifest wallet CLI — execute actions interactively")]
struct Cli {
    /// Config file to read instead of the one in the platform data directory.
    ///
    /// Separate from `--data-dir`, which says where wallet *state* is persisted: a config
    /// naming a network and a node is a different thing from a directory of derived state,
    /// and one flag governing both would change the meaning of `--data-dir` for anyone
    /// already passing it. To move both together, set TX_MANIFEST_DATA_DIR.
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Walk through the lifecycle of a manifest action interactively
    Run {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
        /// Name of the action to execute (e.g. CreateMarket)
        action_name: String,
        /// Network for param-file auto-discovery (defaults to config default_network)
        #[arg(long)]
        network: Option<String>,
        /// Explicit params override file (flat JSON string→string object).
        /// Takes precedence over the auto-discovered network file.
        #[arg(long)]
        params: Option<PathBuf>,
        /// Wallet file used for input auto-selection and signing
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Directory where wallet state is persisted (for UTXO auto-selection)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Instance file to LOAD (input): pre-populates compile_params locked at deploy
        /// time. Never auto-discovered — pass it explicitly for methods that read
        /// instance fields. Not used by constructors (they create the instance).
        #[arg(long)]
        instance: Option<PathBuf>,
        /// Instance file to WRITE (output) on constructor/deploy actions. When omitted,
        /// defaults to a fresh numbered file <manifest-stem>.instance.N.json alongside the
        /// manifest (never overwriting the input instance).
        #[arg(long)]
        instance_out: Option<PathBuf>,
        /// State file to LOAD (input): live on-chain UTXOs for this contract instance.
        /// Never auto-discovered — pass it explicitly to locate covenant UTXOs.
        #[arg(long)]
        state: Option<PathBuf>,
        /// State file to WRITE (output) after broadcast. When omitted, defaults to a fresh
        /// numbered file <manifest-stem>.state.N.json alongside the manifest (never
        /// overwriting --state); the append-only <manifest-stem>.state.history.json is
        /// always updated regardless.
        #[arg(long)]
        state_out: Option<PathBuf>,
        /// Pin a manifest input to a specific outpoint: `--input <input_id>=<txid>:<vout>`.
        /// Repeatable. Takes priority over instance.provided_inputs and the state file;
        /// amount/asset are derived from the manifest input spec. Example:
        /// `--input factory_covenant_in=fd6c…ac90:1`.
        #[arg(long = "input", value_name = "ID=TXID:VOUT")]
        inputs: Vec<String>,
        /// JSON file of input overrides: `{ "<input_id>": "<txid>:<vout>" }` or
        /// `{ "<input_id>": { "txid": "…", "vout": 0, "amount_sat": 1, "asset": "…" } }`.
        /// Merged with (and overridden by) any `--input` flags.
        #[arg(long)]
        inputs_file: Option<PathBuf>,
        /// Skip auto-selection and prompt for every input manually
        #[arg(long)]
        manual_inputs: bool,
        /// Write the signed PSET (and finalized tx) to this JSON file instead of broadcasting.
        /// Useful for offline inspection with e.g. elements-cli or a PSET decoder.
        #[arg(long)]
        export_pset: Option<PathBuf>,
        /// Print every Simplicity jet call (name, inputs, outputs) during covenant dry-runs.
        /// Equality jets show lhs vs rhs so mismatches are immediately visible.
        #[arg(long)]
        debug_jets: bool,
        /// Run a manifest whose programs are not all pinned: missing a hash or a compiler
        /// version, or edited since they were pinned. Each is a warning instead of an
        /// error. For development only: a wallet refuses such a manifest.
        #[arg(long)]
        allow_unpinned: bool,
        /// Development mode. Currently the same as --allow-unpinned; it may turn on more
        /// development-only behaviour in future, so don't use it where that would matter.
        #[arg(long)]
        debug: bool,
    },

    /// Validate a manifest file's schema and report any obvious problems
    Validate {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
        /// Treat unpinned programs as errors: the bar for publishing a manifest or
        /// handing it to a wallet
        #[arg(long)]
        strict: bool,
    },

    /// Write the current hash of every Simplicity program into a manifest
    Pin {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
        /// Change nothing; exit non-zero if any hash is missing or out of date
        #[arg(long)]
        check: bool,
    },

    /// Report what a wallet must support to execute a manifest, or check a given wallet
    /// against it
    Capabilities {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
        /// Comma-separated capabilities your wallet implements, e.g.
        /// `simplicity,custom::my-feature`. With this, the command exits non-zero when the
        /// manifest is unsupported, so it can gate CI.
        #[arg(long, value_name = "LIST")]
        supports: Option<String>,
        /// Chain your wallet implements. Defaults to the manifest's own `chain`, which
        /// makes `--supports` a pure capability check.
        #[arg(long, value_name = "CHAIN")]
        chain: Option<String>,
        /// Emit JSON instead of prose.
        #[arg(long)]
        json: bool,
    },

    /// Interactively explore a manifest file's contract_templates and actions
    Describe {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
        /// Optional action or class method (e.g. ClaimPrincipal) to show the docs for
        /// directly, skipping the menu.
        action_name: Option<String>,
    },

    /// Create a new wallet and save it to a JSON file
    CreateWallet {
        /// Output wallet file path (default: wallet.json)
        #[arg(long, default_value = "wallet.json")]
        out: PathBuf,
        /// Create a mainnet wallet (defaults to config default_network)
        #[arg(long)]
        mainnet: Option<bool>,
    },

    /// Show wallet info: fingerprint, master xpub, oracle public key, and receive address
    Info {
        /// Wallet file to load (default: wallet.json)
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
    },

    /// Sync wallet state against an Esplora server and show balance
    Sync {
        /// Wallet file to load (default: wallet.json)
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Esplora HTTP URL (overrides the active backend URL; default from config)
        #[arg(long)]
        esplora: Option<String>,
        /// Directory to persist wallet state (default: platform data dir / tx-manifest-wallet)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Ensure the wallet has the UTXOs needed to execute a manifest action.
    /// Builds and broadcasts a split transaction if more UTXOs are required.
    Prepare {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
        /// Name of the action to prepare for (e.g. CreateMarket)
        action_name: String,
        /// Wallet file (default: wallet.json)
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Esplora URL for broadcasting (overrides the active backend URL; default from config)
        #[arg(long)]
        esplora: Option<String>,
        /// Directory where wallet state is persisted
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Satoshis to place in each prepared UTXO (default: 10000)
        #[arg(long, default_value_t = 10_000)]
        split_amount: u64,
    },

    /// Show last known wallet balance from persisted state (no network call; run sync first)
    GetBalance {
        /// Wallet file to load (default: wallet.json)
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Directory where wallet state is persisted
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Split a wallet asset into N equal-sized UTXOs and broadcast the transaction.
    /// Useful for pre-funding multiple action inputs.
    Split {
        /// Number of output UTXOs to create
        #[arg(long, short = 'n')]
        count: u32,
        /// Asset to split: hex asset ID or "lbtc" (default: lbtc)
        #[arg(long, default_value = "lbtc")]
        asset: String,
        /// Satoshis per output UTXO. If omitted, splits the available balance evenly.
        #[arg(long)]
        amount_each: Option<u64>,
        /// Wallet file (default: wallet.json)
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Esplora URL for broadcasting (overrides the active backend URL; default from config)
        #[arg(long)]
        esplora: Option<String>,
        /// Directory where wallet state is persisted
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Show or update configuration
    ///
    /// With no arguments: prints current config.
    /// With KEY VALUE: sets that config key.
    /// Valid keys: default_network (testnet|mainnet), default_backend (esplora|electrum),
    /// default_esplora (HTTP URL), default_electrum (e.g. ssl://host:50002)
    Config {
        /// Config key to set
        key: Option<String>,
        /// Value to assign to the key
        value: Option<String>,
    },
}

/// Refuse an Elements-only command on a Bitcoin config.
///
/// These read the LWK wallet database, which a Bitcoin run never populates — every scan
/// goes straight to the chain. Left alone they reported "Wallet has no UTXOs … run `sync`
/// first" against a wallet holding a hundred of them, which sends the reader off to fix
/// their funding instead of their expectations.
fn refuse_on_bitcoin(command: &str, target: &Target) -> Result<()> {
    if target.network.family() == tx_manifest_lib::chain::ChainFamily::Bitcoin {
        anyhow::bail!(
            "`{command}` is not implemented for Bitcoin yet — it works through the Elements \
             wallet database, which a Bitcoin run does not use. `sync` reports the balance; \
             `run` selects its own inputs."
        );
    }
    Ok(())
}

fn cmd_prepare(
    manifest_path: &Path,
    action_name: &str,
    wallet_path: &Path,
    esplora: Option<&str>,
    data_dir: Option<&std::path::Path>,
    split_amount: u64,
    target: &Target,
) -> Result<()> {
    refuse_on_bitcoin("prepare", target)?;
    let cfg = &target.config;
    let backend_kind = cfg.backend_kind();
    let server_url = esplora.unwrap_or_else(|| cfg.backend_url());
    use console::style;
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let manifest = manifest::Manifest::from_json_str(&raw)
        .with_context(|| format!("Cannot parse manifest file: {}", manifest_path.display()))?;
    let w = wallet::load_wallet(wallet_path)?;
    let data_dir = data_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(wallet::default_data_dir);

    println!();
    println!(
        "{}",
        style(format!("Preparing '{action_name}'…")).bold().cyan()
    );
    println!("  Manifest : {}", style(manifest_path.display()).dim());
    println!("  Wallet  : {}", style(wallet_path.display()).dim());
    println!();

    prepare::prepare(prepare::PrepareOpts {
        wallet: &w,
        manifest: &manifest,
        action_name,
        data_dir: &data_dir,
        backend_kind,
        server_url,
        split_amount,
    })
}

fn cmd_config(path: &Path, key: Option<&str>, value: Option<&str>) -> Result<()> {
    use console::style;
    let mut cfg = config::load_from(path)?.config;

    match (key, value) {
        (None, _) => {
            println!();
            println!("{}", style("Config").bold().cyan());
            println!("  File            : {}", style(path.display()).dim());
            println!("  default_network : {}", style(&cfg.default_network).yellow());
            println!(
                "  default_backend : {}",
                style(cfg.default_backend.as_deref().unwrap_or("esplora")).yellow()
            );
            println!(
                "  default_esplora : {}",
                style(cfg.default_esplora.as_deref().unwrap_or("(auto)")).yellow()
            );
            println!(
                "  default_electrum: {}",
                style(cfg.default_electrum.as_deref().unwrap_or("(auto)")).yellow()
            );
            // Which backend fields matter depends on the chain, and showing the Elements
            // ones for a Bitcoin config is worse than showing nothing: it reports an
            // Esplora URL that a Bitcoin run does not consult, next to a network that
            // cannot use it.
            match cfg.network().map(|n| n.family()) {
                Ok(tx_manifest_lib::chain::ChainFamily::Bitcoin) => {
                    println!(
                        "  bitcoin_backend : {}",
                        style(cfg.bitcoin_backend.as_deref().unwrap_or("esplora")).yellow()
                    );
                    println!(
                        "  bitcoin_rpc_url : {}",
                        style(cfg.bitcoin_rpc_url.as_deref().unwrap_or("(unset)")).yellow()
                    );
                    let auth = match (&cfg.bitcoin_rpc_cookie, &cfg.bitcoin_rpc_auth) {
                        (Some(path), _) => format!("cookie {path}"),
                        // The password is not printed. `config` is the command people paste
                        // into issues.
                        (None, Some(a)) => {
                            format!("user {}", a.split_once(':').map_or(a.as_str(), |(u, _)| u))
                        }
                        (None, None) => "(none)".to_string(),
                    };
                    println!("  bitcoin_rpc_auth: {}", style(auth).yellow());
                    println!(
                        "  checkpoint      : {}",
                        style(cfg.bitcoin_checkpoint.as_ref().map_or_else(
                            || "(none)".to_string(),
                            |c| format!("{} @ {}", c.hash, c.height)
                        ))
                        .yellow()
                    );
                    println!(
                        "  simplicity      : {}",
                        style(match cfg.simplicity_activated {
                            Some(true) => "activated",
                            Some(false) => "off",
                            None => "off (network default)",
                        })
                        .yellow()
                    );
                }
                _ => {
                    println!("  active backend  : {} {}", style(cfg.backend_kind().as_str()).cyan(), style(cfg.backend_url()).dim());
                }
            }
        }
        (Some("default_network"), Some(v)) => {
            // Validated by parsing rather than against a two-item list. The list predated
            // Bitcoin support and rejected every Bitcoin network, so the only way to
            // configure one was to edit the file by hand.
            v.parse::<tx_manifest_lib::chain::Network>()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            cfg.default_network = v.to_string();
            config::save_to(path, &cfg)?;
            println!("  default_network → {}", style(v).yellow());
        }
        (Some("default_backend"), Some(v)) => {
            if v != "esplora" && v != "electrum" {
                anyhow::bail!("default_backend must be 'esplora' or 'electrum'");
            }
            cfg.default_backend = if v.is_empty() { None } else { Some(v.to_string()) };
            config::save_to(path, &cfg)?;
            println!("  default_backend → {}", style(v).yellow());
        }
        (Some("default_esplora"), Some(v)) => {
            cfg.default_esplora = if v.is_empty() { None } else { Some(v.to_string()) };
            config::save_to(path, &cfg)?;
            println!(
                "  default_esplora → {}",
                style(cfg.default_esplora.as_deref().unwrap_or("(auto)")).yellow()
            );
        }
        (Some("default_electrum"), Some(v)) => {
            cfg.default_electrum = if v.is_empty() { None } else { Some(v.to_string()) };
            config::save_to(path, &cfg)?;
            println!(
                "  default_electrum → {}",
                style(cfg.default_electrum.as_deref().unwrap_or("(auto)")).yellow()
            );
        }
        (Some(k), _) => anyhow::bail!("Unknown config key '{k}'. Valid keys: default_network, default_backend, default_esplora, default_electrum"),
    }
    Ok(())
}

fn cmd_create_wallet(out: &Path, mainnet: Option<bool>, cfg: &config::Config) -> Result<()> {
    use console::style;
    // Take the configured network whole, not just its mainnet-ness. `--mainnet` still
    // overrides, but only to choose between Liquid and its testnet: it is a two-valued flag
    // and cannot name bitcoin-regtest, so it cannot express what the config already does.
    let w = match (mainnet, cfg.network()) {
        (Some(true), _) => wallet::create_wallet_for(tx_manifest_lib::chain::Network::Liquid)?,
        (Some(false), _) => {
            wallet::create_wallet_for(tx_manifest_lib::chain::Network::LiquidTestnet)?
        }
        (None, Ok(net)) => wallet::create_wallet_for(net)?,
        (None, Err(_)) => wallet::create_wallet(cfg.is_mainnet())?,
    };
    wallet::save_wallet(&w, out)?;
    println!();
    println!("{}", style("Wallet created successfully.").bold().green());
    println!("  Network : {}", style(&w.network).cyan());
    println!("  Saved to: {}", style(out.display()).cyan());
    println!();
    println!(
        "{}",
        style("MNEMONIC — back this up securely:").bold().yellow()
    );
    println!("  {}", style(&w.mnemonic).bold());
    println!();
    println!(
        "{}",
        style("WARNING: the mnemonic is stored in plaintext in the wallet file.").red()
    );
    println!("  Run `info` to see your oracle public key.");
    Ok(())
}

fn cmd_info(wallet_path: &Path, target: &Target) -> Result<()> {
    use console::style;
    let w = wallet::load_wallet(wallet_path)?;
    // The bound network, not the wallet file's mainnet flag: the receive address is the one
    // line a user acts on, and it has to name the chain this wallet is pointed at.
    let info = wallet::wallet_info_for(&w, target.network)?;
    println!();
    println!("{}", style("Wallet Info").bold().cyan());
    println!("  Network     : {}", style(&info.network).cyan());
    println!("  Fingerprint : {}", style(&info.fingerprint).cyan());
    println!("  Master xpub : {}", style(&info.master_xpub).dim());
    println!();
    println!("{}", style("Receive Address (index 0)").bold().cyan());
    println!("  {}", style(&info.receive_address).bold().green());
    println!();
    println!("{}", style("Wallet Signing Key").bold().cyan());
    println!("  Path   : {}", style(&info.wallet_key_path).dim());
    println!("  Pubkey : {}", style(&info.wallet_pubkey).bold().green());
    println!();
    // The oracle key is an Elements-protocol convention with no Bitcoin counterpart, so it
    // is omitted rather than printed empty.
    if !info.oracle_pubkey.is_empty() {
        println!("{}", style("Oracle Public Key").bold().cyan());
        println!("  Path   : {}", style(&info.oracle_path).dim());
        println!("  Pubkey : {}", style(&info.oracle_pubkey).bold().yellow());
        println!();
        println!("Use ORACLE_PUBLIC_KEY in your params file.");
    }
    Ok(())
}

fn cmd_sync(
    wallet_path: &Path,
    esplora: Option<&str>,
    data_dir: Option<&std::path::Path>,
    target: &Target,
) -> Result<()> {
    let cfg = &target.config;
    // Dispatch before anything else. Without this, a Bitcoin config took the Elements path
    // wholesale: an `elwpkh`/`slip77` descriptor, a `tex1q…` Liquid address, and a request
    // to whatever the Elements Esplora setting happened to name. Nothing about that failed
    // for a reason a reader could connect to the config they had written.
    if target.network.family() == tx_manifest_lib::chain::ChainFamily::Bitcoin {
        return cmd_sync_bitcoin(wallet_path, target);
    }
    let backend_kind = cfg.backend_kind();
    let server_url = esplora.unwrap_or_else(|| cfg.backend_url());
    use console::style;
    let w = wallet::load_wallet(wallet_path)?;
    let data_dir = data_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(wallet::default_data_dir);

    println!();
    println!("{}", style("Syncing wallet…").bold().cyan());
    println!("  Network  : {}", style(&w.network).cyan());
    println!(
        "  Backend  : {} {}",
        style(backend_kind.as_str()).cyan(),
        style(server_url).dim()
    );
    println!("  Data dir : {}", style(data_dir.display()).dim());
    println!();

    let result = wallet::sync(&w, backend_kind, server_url, &data_dir)?;

    println!("{}", style("Sync complete.").bold().green());
    println!("  Tip block: {}", style(result.tip).cyan());
    println!();
    print_balance(&result.utxos, &result.explicit_utxos);
    Ok(())
}

/// Sync for a Bitcoin config: scan and report, with nothing persisted.
///
/// The Elements path keeps a wallet database and syncs it forward, so `sync` there is a
/// distinct step from reading the balance. Bitcoin support has no such database — every
/// run scans from the descriptor — so this is a scan and a report, and nothing later
/// depends on having run it.
fn cmd_sync_bitcoin(wallet_path: &Path, target: &Target) -> Result<()> {
    use console::style;
    use tx_manifest_lib::bitcoin_backend::{BitcoinChain, DEFAULT_GAP_LIMIT};
    use tx_manifest_lib::bitcoin_wallet::BitcoinWallet;

    let w = wallet::load_wallet(wallet_path)?;
    let network = target.network;
    let btc = BitcoinWallet::from_mnemonic(&w.mnemonic, network)?;
    let chain: BitcoinChain = target.config.bitcoin_chain(network)?;

    println!();
    println!("{}", style("Scanning wallet…").bold().cyan());
    println!("  Network  : {}", style(network.to_string()).cyan());
    println!("  Backend  : {}", style(format!("{chain:?}")).dim());
    println!("  Descriptor: {}", style(btc.descriptor()?).dim());
    println!();

    let tip = chain.tip_height()?;
    let utxos = chain.scan(&btc, DEFAULT_GAP_LIMIT)?;

    println!("{}", style("Scan complete.").bold().green());
    println!("  Tip block: {}", style(tip).cyan());
    println!();

    let (spendable, immature): (Vec<_>, Vec<_>) = utxos.iter().partition(|u| u.is_spendable());
    let total: u64 = spendable.iter().map(|u| u.value).sum();
    let locked: u64 = immature.iter().map(|u| u.value).sum();

    println!("{}", style("Balance").bold().cyan());
    println!(
        "  spendable : {} sat  ({} utxo{})",
        style(total).yellow(),
        spendable.len(),
        if spendable.len() == 1 { "" } else { "s" }
    );
    if !immature.is_empty() {
        // Reported rather than hidden: these coins are genuinely the wallet's, they simply
        // cannot be spent yet, and a balance that omitted them would look like a loss.
        println!(
            "  immature  : {} sat  ({} coinbase output{}, need {} confirmations)",
            style(locked).dim(),
            immature.len(),
            if immature.len() == 1 { "" } else { "s" },
            tx_manifest_lib::bitcoin_backend::COINBASE_MATURITY,
        );
    }
    if utxos.is_empty() {
        println!();
        println!(
            "  {} Nothing found. Send to the address from `info`, or on regtest mine to it.",
            style("·").dim()
        );
    }
    println!();
    Ok(())
}

fn cmd_get_balance(
    wallet_path: &Path,
    data_dir: Option<&std::path::Path>,
    target: &Target,
) -> Result<()> {
    use console::style;
    // The Bitcoin path keeps no database, so there is no "last known" balance to read back
    // — the scan is the only source. Sending the user to `sync` is honest; printing an
    // empty Elements balance would not be.
    if target.network.family() == tx_manifest_lib::chain::ChainFamily::Bitcoin {
        return cmd_sync_bitcoin(wallet_path, target);
    }
    let w = wallet::load_wallet(wallet_path)?;
    let data_dir = data_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(wallet::default_data_dir);

    println!();
    println!("{}", style("Balance (last synced state)").bold().cyan());
    println!("  Network  : {}", style(&w.network).cyan());
    println!("  Data dir : {}", style(data_dir.display()).dim());
    println!();

    let utxos = wallet::utxos(&w, &data_dir)?;
    let explicit = wallet::explicit_utxos(&w, &data_dir).unwrap_or_default();
    if utxos.is_empty() && explicit.is_empty() {
        println!("  No UTXOs found. Run `sync` first.");
    } else {
        print_balance(&utxos, &explicit);
    }
    Ok(())
}

fn print_balance(utxos: &[lwk_wollet::WalletTxOut], explicit: &[lwk_wollet::ExternalUtxo]) {
    use console::style;
    use std::collections::BTreeMap;

    if utxos.is_empty() && explicit.is_empty() {
        println!("  Balance: (empty)");
        return;
    }

    // Aggregate per asset: total sats and UTXO count
    let mut totals: BTreeMap<lwk_wollet::elements::AssetId, (u64, usize)> = BTreeMap::new();
    for utxo in utxos {
        let entry = totals.entry(utxo.unblinded.asset).or_default();
        entry.0 += utxo.unblinded.value;
        entry.1 += 1;
    }
    for utxo in explicit {
        let entry = totals.entry(utxo.unblinded.asset).or_default();
        entry.0 += utxo.unblinded.value;
        entry.1 += 1;
    }

    println!("{}", style("Balance:").bold());
    for (asset, (total_sats, count)) in &totals {
        println!(
            "  {} sat  ({} UTXO{})  asset: {}",
            style(total_sats).bold().yellow(),
            style(count).cyan(),
            if *count == 1 { "" } else { "s" },
            style(asset).dim(),
        );
    }
}

fn cmd_split(
    count: u32,
    asset_str: &str,
    amount_each: Option<u64>,
    wallet_path: &Path,
    esplora: Option<&str>,
    data_dir: Option<&std::path::Path>,
    target: &Target,
) -> Result<()> {
    refuse_on_bitcoin("split", target)?;
    use console::style;
    use lwk_common::Signer;
    use lwk_wollet::FsPersister;
    use std::str::FromStr;

    if count == 0 {
        anyhow::bail!("--count must be at least 1");
    }

    let cfg = &target.config;
    let backend_kind = cfg.backend_kind();
    let server_url = esplora.unwrap_or_else(|| cfg.backend_url());
    let w = wallet::load_wallet(wallet_path)?;
    let network = wallet::elements_network(&w);
    let desc = wallet::descriptor(&w)?;
    let data_dir = data_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(wallet::default_data_dir);

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("Cannot create data dir: {}", data_dir.display()))?;

    let wollet = lwk_wollet::Wollet::new(
        network,
        FsPersister::new(&data_dir, network, &desc)
            .map_err(|e| anyhow::anyhow!("Cannot open wallet state: {e}"))?,
        desc.clone(),
    )
    .map_err(|e| anyhow::anyhow!("Cannot open wallet: {e}"))?;

    // Resolve asset
    let asset_id = match asset_str {
        "lbtc" | "bitcoin" => network.policy_asset(),
        other => lwk_wollet::elements::AssetId::from_str(other).with_context(|| {
            format!("Invalid asset '{other}': must be 'lbtc' or a hex asset ID")
        })?,
    };

    // Sum available balance of that asset across confidential + explicit UTXOs
    let conf_bal: u64 = wollet
        .utxos()
        .map_err(|e| anyhow::anyhow!("Cannot read UTXOs: {e}"))?
        .iter()
        .filter(|u| u.unblinded.asset == asset_id)
        .map(|u| u.unblinded.value)
        .sum();
    let expl_bal: u64 = wollet
        .explicit_utxos()
        .map_err(|e| anyhow::anyhow!("Cannot read explicit UTXOs: {e}"))?
        .iter()
        .filter(|u| u.unblinded.asset == asset_id)
        .map(|u| u.unblinded.value)
        .sum();
    let total_bal = conf_bal + expl_bal;

    let is_lbtc = asset_id == network.policy_asset();
    let asset_label = if is_lbtc {
        "lbtc".to_string()
    } else {
        asset_id.to_string()
    };

    println!();
    println!("{}", style("Split UTXO").bold().cyan());
    println!("  Asset   : {}", style(&asset_label).yellow());
    println!("  Balance : {} sat", style(total_bal).yellow());
    println!("  Count   : {}", style(count).yellow());

    if total_bal == 0 {
        anyhow::bail!(
            "No {} UTXOs in wallet. Run `sync` first or acquire the asset.",
            asset_label
        );
    }

    // Estimate a conservative fee buffer: 300 sat/output is more than enough at 0.1 sat/vb
    const FEE_BUFFER_PER_OUTPUT: u64 = 300;
    let fee_buffer = FEE_BUFFER_PER_OUTPUT * (count as u64 + 1);

    let per_utxo = match amount_each {
        Some(a) => {
            let total_needed = a * count as u64;
            if total_needed + fee_buffer > total_bal {
                anyhow::bail!(
                    "Insufficient balance: {} × {} = {} sat plus ~{} sat fee buffer exceeds available {} sat",
                    count, a, total_needed, fee_buffer, total_bal
                );
            }
            a
        }
        None => {
            let spendable = total_bal.saturating_sub(fee_buffer);
            if spendable == 0 {
                anyhow::bail!(
                    "Balance ({} sat) is too small to cover even the fee buffer ({} sat).",
                    total_bal,
                    fee_buffer
                );
            }
            spendable / count as u64
        }
    };

    if per_utxo == 0 {
        anyhow::bail!("Computed per-UTXO amount is 0 — lower --count or increase balance.");
    }

    println!("  Per UTXO: {} sat", style(per_utxo).bold().yellow());
    println!(
        "  Total out: {} sat",
        style(per_utxo * count as u64).yellow()
    );
    println!();

    // Build transaction: N outputs back to wallet, each with per_utxo sats of asset_id
    let mut builder = wollet.tx_builder().fee_rate(Some(100.0));
    for i in 0..count {
        let addr = wollet
            .address(Some(i))
            .map_err(|e| anyhow::anyhow!("Cannot derive address {i}: {e}"))?;
        if is_lbtc {
            builder = builder
                .add_lbtc_recipient(addr.address(), per_utxo)
                .map_err(|e| anyhow::anyhow!("Failed to add lbtc recipient: {e}"))?;
        } else {
            builder = builder
                .add_recipient(addr.address(), per_utxo, asset_id)
                .map_err(|e| anyhow::anyhow!("Failed to add recipient: {e}"))?;
        }
    }

    let mut pset = builder
        .finish()
        .map_err(|e| anyhow::anyhow!("Failed to build PSET: {e}"))?;

    let fee = prepare::pset_fee(&pset);
    println!("{}", style("Transaction preview:").bold());
    println!(
        "  {} × {} sat {}  →  your wallet",
        count, per_utxo, asset_label
    );
    println!("  Fee: {} sat", style(fee).yellow());
    println!();

    let confirmed = dialoguer::Confirm::new()
        .with_prompt("Sign and broadcast?")
        .default(false)
        .interact()
        .map_err(|e| anyhow::anyhow!("Prompt error: {e}"))?;

    if !confirmed {
        println!("Cancelled.");
        return Ok(());
    }

    let s = wallet::signer(&w)?;
    s.sign(&mut pset)
        .map_err(|e| anyhow::anyhow!("Failed to sign: {e}"))?;

    let tx = wollet
        .finalize(&mut pset)
        .map_err(|e| anyhow::anyhow!("Failed to finalize: {e}"))?;

    let client = tx_manifest_lib::backend::Backend::connect(backend_kind, server_url, network)?;
    let txid = client.broadcast(&tx)?;

    println!("{} txid: {}", style("Broadcast").green().bold(), txid);
    println!("Run `sync` after confirmation to update wallet state.");
    Ok(())
}

fn cmd_validate(manifest_path: &Path, strict: bool) -> Result<()> {
    use console::style;
    use tx_manifest_lib::validate::Severity;

    println!();
    println!(
        "{}",
        style(format!("Validating {}", manifest_path.display()))
            .bold()
            .cyan()
    );
    println!();

    // Parse first — a malformed file or a missing required field is reported here.
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let manifest = manifest::Manifest::from_json_str(&raw)
        .with_context(|| format!("Cannot parse manifest file: {}", manifest_path.display()))?;

    let mut report = validate::validate(&manifest);
    report.extend(validate::validate_programs(
        &manifest,
        manifest_path.parent().unwrap_or(Path::new(".")),
    ));
    if strict {
        report = report.strict();
    }

    for issue in &report.issues {
        let tag = match issue.severity {
            Severity::Error => style("[error]").red().bold(),
            Severity::Warning => style("[warn] ").yellow().bold(),
        };
        println!(
            "  {} {} — {}",
            tag,
            style(&issue.location).dim(),
            issue.message
        );
    }

    if report.issues.is_empty() {
        println!("  {} no issues found", style("✓").green().bold());
    }

    println!();
    let summary = format!(
        "{} error(s), {} warning(s)",
        report.errors(),
        report.warnings()
    );
    if report.is_ok() {
        println!("{} {}", style("OK:").green().bold(), summary);
        Ok(())
    } else {
        println!("{} {}", style("FAILED:").red().bold(), summary);
        anyhow::bail!("manifest file failed validation");
    }
}

fn cmd_pin(manifest_path: &Path, check: bool) -> Result<()> {
    use console::style;

    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let outcome = tx_manifest_lib::programs::pin_text(
        &text,
        manifest_path.parent().unwrap_or(Path::new(".")),
    )
    .with_context(|| format!("Cannot pin {}", manifest_path.display()))?;

    for change in &outcome.changes {
        println!("  {change}");
    }
    if outcome.changes.is_empty() {
        println!(
            "{} every program hash in {} is up to date",
            style("✓").green().bold(),
            manifest_path.display()
        );
        return Ok(());
    }
    if check {
        anyhow::bail!(
            "{} program hash(es) missing or out of date in {}",
            outcome.changes.len(),
            manifest_path.display()
        );
    }
    std::fs::write(manifest_path, &outcome.text)
        .with_context(|| format!("Cannot write {}", manifest_path.display()))?;
    println!(
        "{} pinned {} hash(es) in {}",
        style("✓").green().bold(),
        outcome.changes.len(),
        manifest_path.display()
    );
    Ok(())
}

fn cmd_describe(manifest_path: &Path, action_name: Option<&str>) -> Result<()> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let manifest = manifest::Manifest::from_json_str(&raw)
        .with_context(|| format!("Cannot parse manifest file: {}", manifest_path.display()))?;
    describe::describe(&manifest, action_name)
}

/// Bind a command to the wallet it operates on, returning the [`Target`] it runs against.
///
/// Chooses the config file — `--config`, else the `config.json` beside the wallet, else the
/// default — reads it strictly, and hands it to [`Target::bind`], which refuses a config or
/// `--network` naming a different chain from the wallet's. That refusal is what makes the
/// config-beside-the-wallet lookup safe: without it, a wallet created on one chain and a
/// config written for another combined silently — a Liquid address printed under a
/// `bitcoin-signet` label.
fn bind(
    explicit_config: Option<&Path>,
    wallet_path: &Path,
    network_flag: Option<&str>,
) -> Result<Target> {
    let path = match explicit_config {
        Some(p) => p.to_path_buf(),
        None => match config::config_beside(wallet_path) {
            Some(p) => {
                announce_config(&p);
                p
            }
            None => config::default_path(),
        },
    };
    let loaded = config::load_from(&path)?;
    // A missing wallet is left to the command, which reports it in context — and a `run`
    // that only previews has no need of one.
    let wallet = if wallet_path.is_file() {
        Some(wallet::load_wallet(wallet_path)?)
    } else {
        None
    };
    Target::bind(
        loaded,
        wallet.as_ref().map(|w| (wallet_path, w)),
        network_flag,
    )
}

/// Say which config was picked up implicitly. On stderr, so `--json` output stays clean.
fn announce_config(path: &Path) {
    use console::style;
    eprintln!(
        "{} {}",
        style("using config").dim(),
        style(path.display()).dim()
    );
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(path) = &cli.config {
        if !path.exists() {
            anyhow::bail!(
                "--config {} does not exist; refusing to fall back to the default config, \
                 which is not the one you asked for",
                path.display()
            );
        }
    }
    let explicit_config = cli.config.as_deref();

    match cli.command {
        Commands::Run {
            manifest_file,
            action_name,
            network,
            params,
            wallet,
            data_dir,
            instance,
            instance_out,
            state,
            state_out,
            inputs,
            inputs_file,
            manual_inputs,
            export_pset,
            debug_jets,
            allow_unpinned,
            debug,
        } => {
            let allow_unpinned = allow_unpinned || debug;
            let target = bind(explicit_config, &wallet, network.as_deref())?;
            let data_dir = data_dir.unwrap_or_else(wallet::default_data_dir);

            // Instance/state INPUT files are never auto-discovered from the manifest stem:
            // the caller must pass --instance / --state explicitly. This avoids a stale
            // on-disk instance silently overriding --params, and never continues from a
            // state the caller didn't ask for. OUTPUT files (--instance-out / --state-out),
            // when omitted, default to a FRESH numbered file derived from the manifest stem
            // (txmanifest.state.1.json, .2, …) inside `run` — never overwriting the input.
            let loaded_instance = instance
                .as_deref()
                .map(instance::InstanceFile::load)
                .transpose()?;

            let provided_inputs = build_provided_inputs(&inputs, inputs_file.as_deref())?;

            lifecycle::run(
                &manifest_file,
                &action_name,
                &target,
                params.as_deref(),
                loaded_instance.as_ref(),
                instance.as_deref(),     // instance_in_path
                instance_out.as_deref(), // instance_out_path
                state.as_deref(),        // state_in_path
                state_out.as_deref(),    // state_out_path
                &provided_inputs,
                &wallet,
                &data_dir,
                manual_inputs,
                export_pset.as_deref(),
                debug_jets,
                if allow_unpinned {
                    tx_manifest_lib::programs::Unpinned::Allow
                } else {
                    tx_manifest_lib::programs::Unpinned::Refuse
                },
            )
        }

        Commands::Validate {
            manifest_file,
            strict,
        } => cmd_validate(&manifest_file, strict),
        Commands::Pin {
            manifest_file,
            check,
        } => cmd_pin(&manifest_file, check),
        Commands::Capabilities {
            manifest_file,
            supports,
            chain,
            json,
        } => cmd_capabilities(&manifest_file, supports.as_deref(), chain.as_deref(), json),
        Commands::Describe {
            manifest_file,
            action_name,
        } => cmd_describe(&manifest_file, action_name.as_deref()),
        Commands::Config { key, value } => {
            let path = explicit_config.map_or_else(config::default_path, Path::to_path_buf);
            cmd_config(&path, key.as_deref(), value.as_deref())
        }
        Commands::Prepare {
            manifest_file,
            action_name,
            wallet,
            esplora,
            data_dir,
            split_amount,
        } => {
            let target = bind(explicit_config, &wallet, None)?;
            cmd_prepare(
                &manifest_file,
                &action_name,
                &wallet,
                esplora.as_deref(),
                data_dir.as_deref(),
                split_amount,
                &target,
            )
        }
        Commands::CreateWallet { out, mainnet } => {
            // The config in the directory the wallet is about to be written to, so a wallet is
            // made for the chain that config names.
            let path = match explicit_config {
                Some(p) => p.to_path_buf(),
                None => config::config_in_dir_of(&out)
                    .inspect(|p| announce_config(p))
                    .unwrap_or_else(config::default_path),
            };
            cmd_create_wallet(&out, mainnet, &config::load_from(&path)?.config)
        }
        Commands::Info { wallet } => {
            let target = bind(explicit_config, &wallet, None)?;
            cmd_info(&wallet, &target)
        }
        Commands::Sync {
            wallet,
            esplora,
            data_dir,
        } => {
            let target = bind(explicit_config, &wallet, None)?;
            cmd_sync(&wallet, esplora.as_deref(), data_dir.as_deref(), &target)
        }
        Commands::GetBalance { wallet, data_dir } => {
            let target = bind(explicit_config, &wallet, None)?;
            cmd_get_balance(&wallet, data_dir.as_deref(), &target)
        }
        Commands::Split {
            count,
            asset,
            amount_each,
            wallet,
            esplora,
            data_dir,
        } => {
            let target = bind(explicit_config, &wallet, None)?;
            cmd_split(
                count,
                &asset,
                amount_each,
                &wallet,
                esplora.as_deref(),
                data_dir.as_deref(),
                &target,
            )
        }
    }
}

/// Report a manifest's support contract, and optionally check a wallet against it.
///
/// This is the consumer `requires` is for: a wallet implementor asking "do I handle this
/// file". Without `--supports` it prints the contract; with it, the exit code is the
/// answer, so it can gate CI without parsing output.
fn cmd_capabilities(
    manifest_file: &Path,
    supports: Option<&str>,
    chain: Option<&str>,
    json: bool,
) -> Result<()> {
    use tx_manifest_lib::chain::{Capabilities, Capability, ChainFamily};
    use tx_manifest_lib::manifest::{Manifest, Support};

    let raw = std::fs::read_to_string(manifest_file)
        .with_context(|| format!("Failed to read manifest file: {}", manifest_file.display()))?;
    let manifest = Manifest::from_json_str(&raw)
        .with_context(|| format!("Failed to parse manifest file: {}", manifest_file.display()))?;

    // No `--supports` is a question about the manifest, not about a wallet: print the
    // contract and stop. Reporting "supported" against an unstated wallet would be
    // meaningless, and exiting 0 would read as a passing check.
    let Some(supports) = supports else {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "chain": manifest.chain_family().as_str(),
                    "requires": manifest.requires.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                }))?
            );
        } else {
            println!("chain    : {}", manifest.chain_family());
            println!("requires : {}", manifest.requires.describe());
            println!(
                "\nA wallet supporting {} on {} can execute this manifest's ledger \
                 requirements.\nCheck yours with: --supports <comma-separated list>",
                manifest.requires.describe(),
                manifest.chain_family(),
            );
        }
        return Ok(());
    };

    let mut wallet_caps = Capabilities::none();
    for entry in supports.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let cap: Capability = entry
            .parse()
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("bad --supports entry {entry:?}"))?;
        wallet_caps.insert(cap);
    }
    let wallet_chain = match chain {
        Some(c) => c
            .parse::<ChainFamily>()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        None => manifest.chain_family(),
    };

    let verdict = manifest.supported_by(wallet_chain, &wallet_caps);
    if json {
        let missing = match &verdict {
            Support::Missing(caps) => caps.iter().map(|c| c.to_string()).collect(),
            _ => Vec::<String>::new(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "supported": verdict.is_supported(),
                "verdict": verdict.describe(),
                "chain": manifest.chain_family().as_str(),
                "requires": manifest.requires.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "missing": missing,
            }))?
        );
    } else {
        match &verdict {
            Support::Yes => println!("{} {}", console::style("✓").green(), verdict.describe()),
            _ => println!("{} {}", console::style("✗").red(), verdict.describe()),
        }
    }

    if verdict.is_supported() {
        Ok(())
    } else {
        // A non-zero exit is the whole point of `--supports`; the message is already
        // printed, so keep the error itself terse.
        std::process::exit(1);
    }
}
