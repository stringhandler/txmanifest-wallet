use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tx_manifest_lib::{manifest, config, describe, instance, lifecycle, prepare, validate, wallet};

#[derive(Parser)]
#[command(name = "tx-manifest-wallet")]
#[command(version)]
#[command(about = "tx-manifest wallet CLI — execute actions interactively")]
struct Cli {
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
        /// Instance file to WRITE (output) on constructor/deploy actions. Defaults to
        /// <manifest-stem>.instance.json alongside the manifest file when omitted.
        #[arg(long)]
        instance_out: Option<PathBuf>,
        /// State file to LOAD (input): live on-chain UTXOs for this contract instance.
        /// Never auto-discovered — pass it explicitly to locate covenant UTXOs.
        #[arg(long)]
        state: Option<PathBuf>,
        /// State file to WRITE (output) after broadcast. Defaults to --state when given,
        /// else <manifest-stem>.state.json alongside the manifest file.
        #[arg(long)]
        state_out: Option<PathBuf>,
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
    },

    /// Validate a manifest file's schema and report any obvious problems
    Validate {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
    },

    /// Interactively explore a manifest file's classes and actions
    Describe {
        /// Path to the manifest (txmanifest.json) file
        manifest_file: PathBuf,
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

fn cmd_prepare(
    manifest_path: &Path,
    action_name: &str,
    wallet_path: &Path,
    esplora: Option<&str>,
    data_dir: Option<&std::path::Path>,
    split_amount: u64,
) -> Result<()> {
    let cfg = config::load();
    let backend_kind = cfg.backend_kind();
    let server_url = esplora.unwrap_or_else(|| cfg.backend_url());
    use console::style;
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let manifest: manifest::Manifest = serde_json::from_str(&raw)
        .with_context(|| format!("Cannot parse manifest file: {}", manifest_path.display()))?;
    let w = wallet::load_wallet(wallet_path)?;
    let data_dir = data_dir.map(|p| p.to_path_buf()).unwrap_or_else(wallet::default_data_dir);

    println!();
    println!("{}", style(format!("Preparing '{action_name}'…")).bold().cyan());
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

fn cmd_config(key: Option<&str>, value: Option<&str>) -> Result<()> {
    use console::style;
    let path = config::config_path();
    let mut cfg = config::load();

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
            println!("  active backend  : {} {}", style(cfg.backend_kind().as_str()).cyan(), style(cfg.backend_url()).dim());
        }
        (Some("default_network"), Some(v)) => {
            if v != "testnet" && v != "mainnet" {
                anyhow::bail!("default_network must be 'testnet' or 'mainnet'");
            }
            cfg.default_network = v.to_string();
            config::save(&cfg)?;
            println!("  default_network → {}", style(v).yellow());
        }
        (Some("default_backend"), Some(v)) => {
            if v != "esplora" && v != "electrum" {
                anyhow::bail!("default_backend must be 'esplora' or 'electrum'");
            }
            cfg.default_backend = if v.is_empty() { None } else { Some(v.to_string()) };
            config::save(&cfg)?;
            println!("  default_backend → {}", style(v).yellow());
        }
        (Some("default_esplora"), Some(v)) => {
            cfg.default_esplora = if v.is_empty() { None } else { Some(v.to_string()) };
            config::save(&cfg)?;
            println!(
                "  default_esplora → {}",
                style(cfg.default_esplora.as_deref().unwrap_or("(auto)")).yellow()
            );
        }
        (Some("default_electrum"), Some(v)) => {
            cfg.default_electrum = if v.is_empty() { None } else { Some(v.to_string()) };
            config::save(&cfg)?;
            println!(
                "  default_electrum → {}",
                style(cfg.default_electrum.as_deref().unwrap_or("(auto)")).yellow()
            );
        }
        (Some(k), _) => anyhow::bail!("Unknown config key '{k}'. Valid keys: default_network, default_backend, default_esplora, default_electrum"),
    }
    Ok(())
}

fn cmd_create_wallet(out: &Path, mainnet: Option<bool>) -> Result<()> {
    use console::style;
    let is_mainnet = mainnet.unwrap_or_else(|| config::load().is_mainnet());
    let w = wallet::create_wallet(is_mainnet)?;
    wallet::save_wallet(&w, out)?;
    println!();
    println!("{}", style("Wallet created successfully.").bold().green());
    println!("  Network : {}", style(&w.network).cyan());
    println!("  Saved to: {}", style(out.display()).cyan());
    println!();
    println!("{}", style("MNEMONIC — back this up securely:").bold().yellow());
    println!("  {}", style(&w.mnemonic).bold());
    println!();
    println!("{}", style("WARNING: the mnemonic is stored in plaintext in the wallet file.").red());
    println!("  Run `info` to see your oracle public key.");
    Ok(())
}

fn cmd_info(wallet_path: &Path) -> Result<()> {
    use console::style;
    let w = wallet::load_wallet(wallet_path)?;
    let info = wallet::wallet_info(&w)?;
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
    println!("{}", style("Oracle Public Key").bold().cyan());
    println!("  Path   : {}", style(&info.oracle_path).dim());
    println!("  Pubkey : {}", style(&info.oracle_pubkey).bold().yellow());
    println!();
    println!("Use ORACLE_PUBLIC_KEY in your params file.");
    Ok(())
}

fn cmd_sync(wallet_path: &Path, esplora: Option<&str>, data_dir: Option<&std::path::Path>) -> Result<()> {
    let cfg = config::load();
    let backend_kind = cfg.backend_kind();
    let server_url = esplora.unwrap_or_else(|| cfg.backend_url());
    use console::style;
    let w = wallet::load_wallet(wallet_path)?;
    let data_dir = data_dir.map(|p| p.to_path_buf()).unwrap_or_else(wallet::default_data_dir);

    println!();
    println!("{}", style("Syncing wallet…").bold().cyan());
    println!("  Network  : {}", style(&w.network).cyan());
    println!("  Backend  : {} {}", style(backend_kind.as_str()).cyan(), style(server_url).dim());
    println!("  Data dir : {}", style(data_dir.display()).dim());
    println!();

    let result = wallet::sync(&w, backend_kind, server_url, &data_dir)?;

    println!("{}", style("Sync complete.").bold().green());
    println!("  Tip block: {}", style(result.tip).cyan());
    println!();
    print_balance(&result.utxos, &result.explicit_utxos);
    Ok(())
}

fn cmd_get_balance(wallet_path: &Path, data_dir: Option<&std::path::Path>) -> Result<()> {
    use console::style;
    let w = wallet::load_wallet(wallet_path)?;
    let data_dir = data_dir.map(|p| p.to_path_buf()).unwrap_or_else(wallet::default_data_dir);

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
) -> Result<()> {
    use console::style;
    use lwk_common::Signer;
    use lwk_wollet::FsPersister;
    use std::str::FromStr;

    if count == 0 {
        anyhow::bail!("--count must be at least 1");
    }

    let cfg = config::load();
    let backend_kind = cfg.backend_kind();
    let server_url = esplora.unwrap_or_else(|| cfg.backend_url());
    let w = wallet::load_wallet(wallet_path)?;
    let network = wallet::elements_network(&w);
    let desc = wallet::descriptor(&w)?;
    let data_dir = data_dir.map(|p| p.to_path_buf()).unwrap_or_else(wallet::default_data_dir);

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
        other => lwk_wollet::elements::AssetId::from_str(other)
            .with_context(|| format!("Invalid asset '{other}': must be 'lbtc' or a hex asset ID"))?,
    };

    // Sum available balance of that asset across confidential + explicit UTXOs
    let conf_bal: u64 = wollet.utxos()
        .map_err(|e| anyhow::anyhow!("Cannot read UTXOs: {e}"))?
        .iter()
        .filter(|u| u.unblinded.asset == asset_id)
        .map(|u| u.unblinded.value)
        .sum();
    let expl_bal: u64 = wollet.explicit_utxos()
        .map_err(|e| anyhow::anyhow!("Cannot read explicit UTXOs: {e}"))?
        .iter()
        .filter(|u| u.unblinded.asset == asset_id)
        .map(|u| u.unblinded.value)
        .sum();
    let total_bal = conf_bal + expl_bal;

    let is_lbtc = asset_id == network.policy_asset();
    let asset_label = if is_lbtc { "lbtc".to_string() } else { asset_id.to_string() };

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
                    total_bal, fee_buffer
                );
            }
            spendable / count as u64
        }
    };

    if per_utxo == 0 {
        anyhow::bail!(
            "Computed per-UTXO amount is 0 — lower --count or increase balance."
        );
    }

    println!("  Per UTXO: {} sat", style(per_utxo).bold().yellow());
    println!("  Total out: {} sat", style(per_utxo * count as u64).yellow());
    println!();

    // Build transaction: N outputs back to wallet, each with per_utxo sats of asset_id
    let mut builder = wollet.tx_builder().fee_rate(Some(100.0));
    for i in 0..count {
        let addr = wollet.address(Some(i))
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

    let mut pset = builder.finish()
        .map_err(|e| anyhow::anyhow!("Failed to build PSET: {e}"))?;

    let fee = prepare::pset_fee(&pset);
    println!("{}", style("Transaction preview:").bold());
    println!("  {} × {} sat {}  →  your wallet", count, per_utxo, asset_label);
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

    let tx = wollet.finalize(&mut pset)
        .map_err(|e| anyhow::anyhow!("Failed to finalize: {e}"))?;

    let client = tx_manifest_lib::backend::Backend::connect(backend_kind, server_url, network)?;
    let txid = client.broadcast(&tx)?;

    println!("{} txid: {}", style("Broadcast").green().bold(), txid);
    println!("Run `sync` after confirmation to update wallet state.");
    Ok(())
}

fn cmd_validate(manifest_path: &Path) -> Result<()> {
    use tx_manifest_lib::validate::Severity;
    use console::style;

    println!();
    println!("{}", style(format!("Validating {}", manifest_path.display())).bold().cyan());
    println!();

    // Parse first — a malformed file or a missing required field is reported here.
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let manifest: manifest::Manifest = serde_json::from_str(&raw)
        .with_context(|| format!("Cannot parse manifest file: {}", manifest_path.display()))?;

    let report = validate::validate(&manifest);

    for issue in &report.issues {
        let tag = match issue.severity {
            Severity::Error => style("[error]").red().bold(),
            Severity::Warning => style("[warn] ").yellow().bold(),
        };
        println!("  {} {} — {}", tag, style(&issue.location).dim(), issue.message);
    }

    if report.issues.is_empty() {
        println!("  {} no issues found", style("✓").green().bold());
    }

    println!();
    let summary = format!("{} error(s), {} warning(s)", report.errors(), report.warnings());
    if report.is_ok() {
        println!("{} {}", style("OK:").green().bold(), summary);
        Ok(())
    } else {
        println!("{} {}", style("FAILED:").red().bold(), summary);
        anyhow::bail!("manifest file failed validation");
    }
}

fn cmd_describe(manifest_path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Cannot read manifest file: {}", manifest_path.display()))?;
    let manifest: manifest::Manifest = serde_json::from_str(&raw)
        .with_context(|| format!("Cannot parse manifest file: {}", manifest_path.display()))?;
    describe::describe(&manifest)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

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
            manual_inputs,
            export_pset,
            debug_jets,
        } => {
            let cfg = config::load();
            let network = network.as_deref().unwrap_or(&cfg.default_network).to_string();
            let data_dir = data_dir.unwrap_or_else(wallet::default_data_dir);

            // Instance/state INPUT files are never auto-discovered from the manifest stem:
            // the caller must pass --instance / --state explicitly. This avoids a stale
            // on-disk instance silently overriding --params. OUTPUT paths (--instance-out /
            // --state-out) auto-derive from the manifest stem inside `run` when omitted.
            let loaded_instance = instance
                .as_deref()
                .map(instance::InstanceFile::load)
                .transpose()?;

            lifecycle::run(
                &manifest_file,
                &action_name,
                Some(&network),
                params.as_deref(),
                loaded_instance.as_ref(),
                instance.as_deref(),       // instance_in_path
                instance_out.as_deref(),   // instance_out_path
                state.as_deref(),          // state_in_path
                state_out.as_deref(),      // state_out_path
                &wallet,
                &data_dir,
                manual_inputs,
                export_pset.as_deref(),
                debug_jets,
            )
        }

        Commands::Validate { manifest_file } => cmd_validate(&manifest_file),
        Commands::Describe { manifest_file } => cmd_describe(&manifest_file),
        Commands::Config { key, value } => cmd_config(key.as_deref(), value.as_deref()),
        Commands::Prepare { manifest_file, action_name, wallet, esplora, data_dir, split_amount } =>
            cmd_prepare(&manifest_file, &action_name, &wallet, esplora.as_deref(), data_dir.as_deref(), split_amount),
        Commands::CreateWallet { out, mainnet } => cmd_create_wallet(&out, mainnet),
        Commands::Info { wallet } => cmd_info(&wallet),
        Commands::Sync { wallet, esplora, data_dir } => cmd_sync(&wallet, esplora.as_deref(), data_dir.as_deref()),
        Commands::GetBalance { wallet, data_dir } => cmd_get_balance(&wallet, data_dir.as_deref()),
        Commands::Split { count, asset, amount_each, wallet, esplora, data_dir } =>
            cmd_split(count, &asset, amount_each, &wallet, esplora.as_deref(), data_dir.as_deref()),
    }
}
