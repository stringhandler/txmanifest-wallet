use std::path::Path;

use anyhow::{bail, Context, Result};
use lwk_common::Signer;
use lwk_wollet::{ElementsNetwork, FsPersister};

use console::style;
use dialoguer::Confirm;

use crate::manifest::{Action, Manifest};
use crate::wallet::{self, WalletFile};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub struct PrepareOpts<'a> {
    pub wallet: &'a WalletFile,
    pub manifest: &'a Manifest,
    pub action_name: &'a str,
    pub data_dir: &'a Path,
    pub backend_kind: crate::backend::BackendKind,
    pub server_url: &'a str,
    pub split_amount: u64,
}

pub fn prepare(opts: PrepareOpts<'_>) -> Result<()> {
    let action = opts.manifest.actions.get(opts.action_name).with_context(|| {
        let available: Vec<&str> = opts.manifest.actions.keys().map(String::as_str).collect();
        format!(
            "Action '{}' not found. Available: {}",
            opts.action_name,
            available.join(", ")
        )
    })?;

    // Step 1 — analyse what wallet inputs the action needs
    let needed = needed_wallet_inputs(action, opts.manifest)?;

    if needed.is_empty() {
        println!("  No wallet inputs required for '{}' — nothing to prepare.", opts.action_name);
        return Ok(());
    }

    println!("  Required wallet inputs:");
    for ni in &needed {
        println!("    {} (asset: {})", ni.input_id, ni.asset_label);
    }

    // Step 2 — open the persisted wollet and check what we already have
    let network = wallet::elements_network(opts.wallet);
    let desc = wallet::descriptor(opts.wallet)?;

    std::fs::create_dir_all(opts.data_dir)
        .with_context(|| format!("Cannot create data dir: {}", opts.data_dir.display()))?;

    let wollet = lwk_wollet::Wollet::new(
        network,
        FsPersister::new(opts.data_dir, network, &desc)
            .map_err(|e| anyhow::anyhow!("Cannot open wallet state: {e}"))?,
        desc.clone(),
    )
    .map_err(|e| anyhow::anyhow!("Cannot open wallet: {e}"))?;

    let utxos = wollet.utxos()
        .map_err(|e| anyhow::anyhow!("Cannot read UTXOs: {e}"))?;

    if utxos.is_empty() {
        bail!(
            "Wallet has no UTXOs. Fund the address shown by `info` then run `sync` first."
        );
    }

    // Step 3 — for each required asset, count how many UTXOs we already have
    let lbtc = network.policy_asset();

    // Group needed inputs by asset
    use std::collections::BTreeMap;
    let mut needed_by_asset: BTreeMap<String, Vec<&NeededInput>> = BTreeMap::new();
    for ni in &needed {
        needed_by_asset.entry(ni.asset_label.clone()).or_default().push(ni);
    }

    let mut splits_required: Vec<(String, usize)> = Vec::new(); // (asset_label, extra needed)

    for (asset_label, inputs) in &needed_by_asset {
        let required_count = inputs.len();
        let asset_id = resolve_asset(asset_label, network)?;
        let available_count = utxos.iter()
            .filter(|u| u.unblinded.asset == asset_id)
            .count();

        println!(
            "  {} — need {} UTXO(s), have {}",
            asset_label, required_count, available_count
        );

        if available_count < required_count {
            splits_required.push((asset_label.clone(), required_count - available_count));
        }
    }

    if splits_required.is_empty() {
        println!();
        println!("  Wallet already has enough UTXOs — no split needed.");
        return Ok(());
    }

    // Step 4 — build a split transaction for each asset that needs more UTXOs
    for (asset_label, extra) in &splits_required {
        println!();
        println!(
            "  Splitting to create {} extra {} UTXO(s) of {} sats each…",
            extra, asset_label, opts.split_amount
        );

        let asset_id = resolve_asset(asset_label, network)?;

        // Only L-BTC splits are supported via add_lbtc_recipient; other assets
        // would require a full asset-aware builder (future work).
        if asset_id != lbtc {
            bail!(
                "Splitting non-L-BTC assets is not yet supported. \
                 Please manually send {} {} UTXO(s) to your wallet address.",
                extra, asset_label
            );
        }

        let receive_addr = wollet.address(None)
            .map_err(|e| anyhow::anyhow!("Cannot derive address: {e}"))?;

        let mut builder = wollet.tx_builder()
            .fee_rate(Some(100.0)); // 0.1 sat/vb

        for _ in 0..*extra {
            builder = builder
                .add_lbtc_recipient(receive_addr.address(), opts.split_amount)
                .map_err(|e| anyhow::anyhow!("Failed to add recipient: {e}"))?;
        }

        let mut pset = builder.finish()
            .map_err(|e| anyhow::anyhow!("Failed to build PSET: {e}"))?;

        // Preview — extract fee from the built PSET before signing
        let fee = pset_fee(&pset);

        println!();
        println!("{}", style("  Transaction preview:").bold());
        println!("    Outputs : {} × {} sats {} each", extra, opts.split_amount, asset_label);
        println!("    Total   : {} sats", (*extra as u64) * opts.split_amount);
        println!("    Fee     : {} sats", fee);
        println!("    To      : {} (your wallet, index {})", receive_addr.address(), receive_addr.index());
        println!();

        let confirmed = Confirm::new()
            .with_prompt("  Sign and broadcast?")
            .default(false)
            .interact()
            .map_err(|e| anyhow::anyhow!("Prompt error: {e}"))?;

        if !confirmed {
            println!("  Cancelled.");
            continue;
        }

        // Sign
        let s = wallet::signer(opts.wallet)?;
        s.sign(&mut pset)
            .map_err(|e| anyhow::anyhow!("Failed to sign PSET: {e}"))?;

        // Finalize
        let tx = wollet.finalize(&mut pset)
            .map_err(|e| anyhow::anyhow!("Failed to finalize PSET: {e}"))?;

        // Broadcast
        let client = crate::backend::Backend::connect(opts.backend_kind, opts.server_url, network)?;

        let txid = client.broadcast(&tx)?;

        println!("  {} txid: {}", style("Broadcast").green().bold(), txid);
        println!("  Run `sync` after confirmation to update wallet state.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Input analysis
// ---------------------------------------------------------------------------

struct NeededInput {
    input_id: String,
    asset_label: String,
}

/// Walk the action's inputs and return all wallet-sourced inputs with their
/// required asset.  Errors if any input requires a Simplicity covenant UTXO
/// that cannot be auto-created.
fn needed_wallet_inputs(action: &Action, manifest: &Manifest) -> Result<Vec<NeededInput>> {
    let mut out = Vec::new();

    for input in action.inputs.as_deref().unwrap_or_default() {
        if input.is_wallet_source() {
            let asset_label = input
                .asset
                .as_ref()
                .and_then(|v| v.as_str())
                .unwrap_or("lbtc")
                .to_string();
            out.push(NeededInput { input_id: input.id.clone(), asset_label });
        } else if let Some(utxo_type_name) = input.utxo_type_name() {
            // Protocol UTXO — check if it has a Simplicity script
            let has_simplicity = manifest
                .utxo_types
                .as_ref()
                .and_then(|m| m.get(&utxo_type_name))
                .and_then(|ut| ut.script.as_ref())
                .map(|s| s.type_.as_str() == "simplicity")
                .unwrap_or(false);

            if has_simplicity {
                bail!(
                    "Input '{}' requires utxo_type '{}' which has a Simplicity program. \
                     This UTXO must be created by a prior action — it cannot be auto-prepared.",
                    input.id,
                    utxo_type_name
                );
            }
            // Non-Simplicity protocol UTXOs are skipped (treated as pre-existing on-chain)
        }
    }

    Ok(out)
}

/// Extract the explicit fee from the outputs of a built PSET.
/// LWK places the fee output last; it is an explicit value with empty script.
pub fn pset_fee(pset: &lwk_wollet::elements::pset::PartiallySignedTransaction) -> u64 {
    pset.outputs().iter().filter_map(|o| {
        // Fee output has no script (empty scriptpubkey in the PSET output)
        if o.script_pubkey.is_empty() {
            o.amount
        } else {
            None
        }
    }).sum()
}

/// Resolve an asset label ("lbtc" or a hex asset ID) to an `AssetId`.
fn resolve_asset(
    label: &str,
    network: ElementsNetwork,
) -> Result<lwk_wollet::elements::AssetId> {
    use std::str::FromStr;
    match label {
        "lbtc" | "bitcoin" => Ok(network.policy_asset()),
        other => lwk_wollet::elements::AssetId::from_str(other)
            .with_context(|| format!("Cannot parse asset ID '{other}'")),
    }
}
