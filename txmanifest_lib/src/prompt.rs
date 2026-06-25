#![allow(dead_code)]
#![allow(unused_variables)]

use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input};

use crate::manifest;
use crate::context::ResolvedInput;

// ---------------------------------------------------------------------------
// Generic param prompt
// ---------------------------------------------------------------------------

/// Prompt the user for a single named parameter.
///
/// `default` pre-fills the prompt; the user can press Enter to accept it or
/// type a new value to override it.  Pass `None` for no pre-fill.
///
/// Precedence of `default` (highest wins, resolved by the caller):
///   manifest file `default` field < network override file < explicit --params file
pub fn prompt_param(
    name: &str,
    type_: &str,
    description: Option<&str>,
    default: Option<&str>,
) -> Result<String> {
    println!();
    print!(
        "  {} {}",
        style(name).bold().cyan(),
        style(format!("({})", type_)).dim(),
    );
    if let Some(d) = description {
        print!("  {}", style(d).italic());
    }
    if let Some(dv) = default {
        print!("  {}", style(format!("[default: {dv}]")).dim().yellow());
    }
    println!();

    let value = match type_ {
        "bool" => {
            let def_bool = default.map(|v| v == "true").unwrap_or(false);
            let confirmed = Confirm::new()
                .with_prompt(format!("  {name}"))
                .default(def_bool)
                .interact()
                .map_err(|e| anyhow::anyhow!("prompt error for '{name}': {e}"))?;
            if confirmed { "true".to_string() } else { "false".to_string() }
        }
        "u8"  => prompt_integer::<u8>(name, type_, default)?,
        "u16" => prompt_integer::<u16>(name, type_, default)?,
        "u32" => prompt_integer::<u32>(name, type_, default)?,
        "u64" => prompt_integer::<u64>(name, type_, default)?,
        _ => {
            let hint = type_hint(type_);
            let mut input = Input::<String>::new()
                .with_prompt(format!("  {name}{hint}"));
            if let Some(dv) = default {
                input = input.default(dv.to_string()).show_default(false);
            }
            input
                .interact_text()
                .map_err(|e| anyhow::anyhow!("prompt error for '{name}': {e}"))?
        }
    };

    Ok(value)
}

/// Prompt with a typed hint appended to the prompt string.
fn type_hint(type_: &str) -> String {
    match type_ {
        "pubkey" => " [33-byte hex pubkey]".to_string(),
        "asset_id" => " [32-byte hex asset id]".to_string(),
        "address" => " [Liquid/Elements address]".to_string(),
        "bytes32" => " [64 hex chars]".to_string(),
        "u256" => " [64 hex chars / u256]".to_string(),
        _ => String::new(),
    }
}

/// Prompt for an integer type, validating the parse on every attempt.
fn prompt_integer<T>(name: &str, type_: &str, default: Option<&str>) -> Result<String>
where
    T: std::str::FromStr + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    loop {
        let mut input = Input::<String>::new()
            .with_prompt(format!("  {name} [{}]", type_));
        if let Some(dv) = default {
            input = input.default(dv.to_string()).show_default(false);
        }
        let raw: String = input
            .interact_text()
            .map_err(|e| anyhow::anyhow!("prompt error for '{name}': {e}"))?;

        match raw.trim().parse::<T>() {
            Ok(_) => return Ok(raw.trim().to_string()),
            Err(e) => {
                eprintln!(
                    "  {} '{}' is not a valid {type_}: {e}",
                    style("Error:").red().bold(),
                    raw.trim()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Input selection prompt
// ---------------------------------------------------------------------------

/// Prompt the user to resolve a manifest input to a concrete UTXO.
///
/// For `utxo_source = "wallet"`: prompts for txid and vout separately.
/// For protocol UTXO inputs: prints a note that the wallet would look these up
/// on-chain and returns a stub.
pub fn prompt_input_selection(input: &manifest::Input) -> Result<ResolvedInput> {
    println!();
    println!(
        "  {} {}",
        style(format!("Input: {}", input.id)).bold().cyan(),
        input
            .description
            .as_deref()
            .map(|d| format!("— {d}"))
            .unwrap_or_default()
    );

    if input.is_wallet_source() {
        // Wallet input: user supplies the UTXO outpoint.
        println!(
            "  {}",
            style("Wallet input — please provide the UTXO outpoint.").dim()
        );

        let txid: String = Input::<String>::new()
            .with_prompt(format!("  {}.txid", input.id))
            .interact_text()
            .map_err(|e| anyhow::anyhow!("prompt error for txid: {e}"))?;

        let vout_str: String = Input::<String>::new()
            .with_prompt(format!("  {}.vout", input.id))
            .interact_text()
            .map_err(|e| anyhow::anyhow!("prompt error for vout: {e}"))?;

        let vout: u32 = vout_str
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("vout must be a u32: {e}"))?;

        let amount_str: String = Input::<String>::new()
            .with_prompt(format!("  {}.amount_sat", input.id))
            .interact_text()
            .map_err(|e| anyhow::anyhow!("prompt error for amount_sat: {e}"))?;

        let amount_sat: u64 = amount_str
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("amount_sat must be a u64: {e}"))?;

        let asset: String = Input::<String>::new()
            .with_prompt(format!("  {}.asset [hex asset id or shorthand]", input.id))
            .interact_text()
            .map_err(|e| anyhow::anyhow!("prompt error for asset: {e}"))?;

        Ok(ResolvedInput {
            id: input.id.clone(),
            txid: txid.trim().to_string(),
            vout,
            amount_sat,
            asset: asset.trim().to_string(),
            issuance_entropy: None,
        })
    } else {
        // Protocol UTXO — the real wallet would query LWK for matching UTXOs.
        let utxo_type = input.utxo_type_name().unwrap_or_else(|| "[complex]".to_string());
        println!(
            "  {} utxo_type '{}' — a real wallet would auto-resolve this from the chain via LWK.",
            style("[protocol UTXO]").yellow(),
            utxo_type
        );
        println!(
            "  {} Returning stub UTXO for demonstration.",
            style("[stub]").yellow()
        );

        // Return a clearly-marked stub so the lifecycle can continue.
        Ok(ResolvedInput {
            id: input.id.clone(),
            txid: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            vout: 0,
            amount_sat: 0,
            asset: format!("STUB_ASSET_FOR_{}", utxo_type.to_uppercase()),
            issuance_entropy: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Fee rate prompt
// ---------------------------------------------------------------------------

/// Prompt for a fee rate in sat/vb.  Returns a positive f64.
pub fn prompt_fee_rate() -> Result<f64> {
    loop {
        let raw: String = Input::<String>::new()
            .with_prompt("  Fee rate (sat/vb)")
            .default("0.1".to_string())
            .interact_text()
            .map_err(|e| anyhow::anyhow!("prompt error for fee rate: {e}"))?;

        match raw.trim().parse::<f64>() {
            Ok(r) if r > 0.0 => return Ok(r),
            Ok(_) => eprintln!(
                "  {} fee rate must be greater than 0.",
                style("Error:").red().bold()
            ),
            Err(e) => eprintln!(
                "  {} '{}' is not a valid number: {e}",
                style("Error:").red().bold(),
                raw.trim()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Broadcast confirmation
// ---------------------------------------------------------------------------

/// Ask the user whether to broadcast the transaction.
pub fn confirm_broadcast() -> Result<bool> {
    Confirm::new()
        .with_prompt("  Broadcast transaction?")
        .default(false)
        .interact()
        .map_err(|e| anyhow::anyhow!("prompt error: {e}"))
}
