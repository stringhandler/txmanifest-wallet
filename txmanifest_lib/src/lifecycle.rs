use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use console::style;
use lwk_common::Signer;
use lwk_wollet::{ElementsNetwork, FsPersister, Wollet};

use crate::manifest::{Manifest, Input, Validation};
use crate::context::{ExecutionContext, ResolvedInput};
use crate::instance::InstanceFile;
use crate::state::{history_path, ContractState, HistoryEntry, StateHistory, StateUtxo};
use crate::params::ParamOverrides;
use crate::prompt;
use crate::wallet::{self, WalletFile};
use crate::{config, covenant, eval, pset_builder};

// BIP68 nSequence encoding bits.
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// Resolve an input's `sequence` spec to a raw `nSequence` value.
///
/// Accepts `{"relative_blocks": <expr>}` (block-based BIP68 relative lock),
/// `{"relative_seconds": <expr>}` (time-based, rounded up to 512-second units),
/// or a bare integer / expression (used verbatim as the raw nSequence). Expressions
/// are evaluated in the standard language, so `instance.INHERIT_BLOCKS` etc. work.
fn encode_sequence(spec: &serde_json::Value, ctx: &ExecutionContext) -> Result<u32> {
    match spec {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get("relative_blocks") {
                let blocks = eval::eval_amount(v, ctx).context("evaluating sequence.relative_blocks")?;
                if blocks > SEQUENCE_LOCKTIME_MASK as u64 {
                    anyhow::bail!("relative_blocks {blocks} exceeds the 16-bit BIP68 maximum ({})", SEQUENCE_LOCKTIME_MASK);
                }
                // Type flag clear = block-based; disable flag clear = enabled.
                Ok(blocks as u32)
            } else if let Some(v) = map.get("relative_seconds") {
                let secs = eval::eval_amount(v, ctx).context("evaluating sequence.relative_seconds")?;
                let intervals = secs.div_ceil(512);
                if intervals > SEQUENCE_LOCKTIME_MASK as u64 {
                    anyhow::bail!("relative_seconds {secs} ({intervals} × 512s units) exceeds the 16-bit BIP68 maximum");
                }
                Ok(SEQUENCE_LOCKTIME_TYPE_FLAG | intervals as u32)
            } else {
                anyhow::bail!("sequence object must have a 'relative_blocks' or 'relative_seconds' key");
            }
        }
        // Bare integer or expression string → raw nSequence.
        serde_json::Value::Number(_) | serde_json::Value::String(_) => {
            let raw = eval::eval_amount(spec, ctx).context("evaluating raw sequence value")?;
            if raw > u32::MAX as u64 {
                anyhow::bail!("sequence value {raw} exceeds the 32-bit nSequence maximum");
            }
            Ok(raw as u32)
        }
        other => anyhow::bail!("unsupported sequence spec: {other}"),
    }
}

/// Resolve `inp.sequence` (if present) to a raw nSequence, warning loudly if it would
/// silently disable the relative timelock the user asked for.
fn resolve_input_sequence(inp: &Input, ctx: &ExecutionContext) -> Result<Option<u32>> {
    let Some(spec) = &inp.sequence else { return Ok(None) };
    let seq = encode_sequence(spec, ctx)?;
    if seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        println!(
            "  {} Input '{}' sequence 0x{seq:08x} has the BIP68 disable bit set — relative timelock will NOT be enforced",
            style("[warn]").yellow(), inp.id
        );
    }
    Ok(Some(seq))
}

// ---------------------------------------------------------------------------
// Run output
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct RunOutput<'a> {
    protocol: &'a str,
    action: &'a str,
    compile_params: &'a BTreeMap<String, String>,
    params: &'a BTreeMap<String, String>,
    args: &'a BTreeMap<String, String>,
    inputs: Vec<RunOutputInput>,
    fee_rate_sat_per_vb: f64,
    txid: Option<String>,
}

#[derive(serde::Serialize)]
struct RunOutputInput {
    id: String,
    txid: String,
    vout: u32,
    amount_sat: u64,
    asset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuance_entropy: Option<String>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the interactive wallet lifecycle for the given action in a manifest file.
#[allow(clippy::too_many_arguments)]
pub fn run(
    manifest_file: &Path,
    action_name: &str,
    network: Option<&str>,
    params_file: Option<&Path>,
    instance: Option<&InstanceFile>,
    // Path the instance was loaded from (INPUT). Never auto-discovered; recorded into the
    // state file so methods know which instance they belong to.
    instance_in_path: Option<&Path>,
    // Path to write the instance file on deploy (OUTPUT). Auto-derived from the manifest
    // stem (`<stem>.instance.json`) when not given.
    instance_out_path: Option<&Path>,
    // Path to load existing contract state from (INPUT). Never auto-discovered.
    state_in_path: Option<&Path>,
    // Path to write updated contract state to (OUTPUT). Defaults to `state_in_path` when
    // that is given, else auto-derived from the manifest stem (`<stem>.state.json`).
    state_out_path: Option<&Path>,
    wallet_path: &Path,
    data_dir: &Path,
    manual_inputs: bool,
    // If set, write signed PSET + finalized tx to this path as JSON instead of broadcasting.
    export_pset_path: Option<&Path>,
    // If true, run the jet debugger on every covenant dry-run and print each jet's I/O.
    debug_jets: bool,
) -> Result<()> {
    // ------------------------------------------------------------------
    // Step 0 — load and parse
    // ------------------------------------------------------------------
    let raw = std::fs::read_to_string(manifest_file).with_context(|| {
        format!("Failed to read manifest file: {}", manifest_file.display())
    })?;

    let manifest: Manifest = serde_json::from_str(&raw).with_context(|| {
        format!("Failed to parse manifest file: {}", manifest_file.display())
    })?;
    // INPUT paths (instance load, state load) are never auto-discovered: passing them
    // explicitly is what keeps a stale on-disk instance from silently overriding
    // `--params`. OUTPUT paths auto-derive from the manifest stem when not given, so
    // constructors and state tracking work without extra flags.
    let manifest_dir = manifest_file.parent().unwrap_or(Path::new("."));
    let manifest_stem = manifest_file
        .file_name().and_then(|n| n.to_str()).unwrap_or("contract")
        .trim_end_matches(".json");
    let auto_instance_out = manifest_dir.join(format!("{manifest_stem}.instance.json"));
    let auto_state_out    = manifest_dir.join(format!("{manifest_stem}.state.json"));
    let effective_instance_out: &Path = instance_out_path.unwrap_or(&auto_instance_out);
    let effective_state_out: &Path = match (state_out_path, state_in_path) {
        (Some(p), _) => p,
        (None, Some(p)) => p,
        (None, None) => &auto_state_out,
    };

    // Load existing contract state only from the explicitly-passed input file.
    let mut contract_state: Option<ContractState> = match state_in_path {
        Some(p) if p.exists() => match ContractState::load(p) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("  {} Could not load state file: {e}", style("[warn]").yellow());
                None
            }
        },
        _ => None,
    };

    let overrides = ParamOverrides::load(manifest_file, network, params_file, instance)?;

    let loaded_wallet: Option<WalletFile> = if wallet_path.exists() {
        Some(wallet::load_wallet(wallet_path)?)
    } else {
        eprintln!(
            "  {} No wallet file found at '{}' — run `create-wallet` first.",
            style("[warn]").yellow(),
            wallet_path.display()
        );
        None
    };

    // Load UTXOs from persisted wallet state for auto-selection.
    let available_utxos: Vec<lwk_wollet::WalletTxOut> = match &loaded_wallet {
        Some(w) if data_dir.exists() => {
            wallet::utxos(w, data_dir).unwrap_or_else(|_| vec![])
        }
        _ => vec![],
    };
    let available_explicit: Vec<lwk_wollet::ExternalUtxo> = match &loaded_wallet {
        Some(w) if data_dir.exists() => {
            wallet::explicit_utxos(w, data_dir).unwrap_or_else(|_| vec![])
        }
        _ => vec![],
    };

    // Dispatch: standalone actions first, then class methods.
    let action = if let Some(a) = manifest.actions.get(action_name) {
        a
    } else if let Some((_class_id, _class_def, method)) = manifest.find_class_and_method(action_name) {
        method
    } else {
        let mut available: Vec<String> = manifest.actions.keys().cloned().collect();
        if let Some(classes) = &manifest.classes {
            for cls in classes.values() {
                available.extend(cls.methods.keys().cloned());
            }
        }
        anyhow::bail!(
            "Action '{}' not found. Available: {}",
            action_name,
            available.join(", ")
        )
    };

    let mut ctx = ExecutionContext::new();
    let mut broadcast_txid: Option<String> = None;

    // ------------------------------------------------------------------
    // Protocol / action header
    // ------------------------------------------------------------------
    println!();
    println!("{}", style(format!("Protocol: {}", manifest.protocol)).bold().cyan());
    if let Some(desc) = &manifest.description {
        println!("  {}", style(desc).dim());
    }
    println!();
    println!("{}", style(format!("Action: {}", action_name)).bold().cyan());
    if let Some(desc) = &action.description {
        println!("  {}", style(desc).dim());
    }
    println!();
    match &loaded_wallet {
        Some(w) => {
            let info = wallet::wallet_info(w)?;
            println!(
                "  {} {} (fingerprint: {})",
                style("Wallet:").bold(),
                style(wallet_path.display()).cyan(),
                style(&info.fingerprint).dim(),
            );
        }
        None => {
            println!("  {}", style("Wallet: none").dim());
        }
    }

    // ------------------------------------------------------------------
    // Step 1 — Parameters
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 1: Parameters"));

    {
        let (user_provided, derived) = manifest.compile_param_sets();

        if !user_provided.is_empty() {
            println!("  {}", style("Compile params:").bold());
            for (name, def) in &user_provided {
                let is_wallet_key = def.source.as_ref().map(|s| s.type_ == "wallet_key").unwrap_or(false);
                // wallet_key params always derive from the current wallet — the instance file
                // must not override them, since that would use a stale key from a previous run.
                if !is_wallet_key {
                    if let Some(inst_val) = instance.and_then(|i| i.get_field(name)) {
                        println!(
                            "  {} {} = {}  {}",
                            style("✓").green(),
                            style(name).bold().cyan(),
                            style(inst_val).yellow(),
                            style("[from instance]").dim(),
                        );
                        ctx.set_compile_param(*name, inst_val);
                        continue;
                    }
                }
                if is_wallet_key {
                    let info = loaded_wallet.as_ref()
                        .map(wallet::wallet_info)
                        .transpose()?;
                    if let Some(info) = info {
                        println!(
                            "  {} {} = {}  {}",
                            style("✓").green(),
                            style(name).bold().cyan(),
                            style(&info.wallet_pubkey).yellow(),
                            style(format!("[wallet key, path: {}]", info.wallet_key_path)).dim(),
                        );
                        ctx.set_compile_param(*name, &info.wallet_pubkey);
                    } else if let Some(ov) = overrides.get(name) {
                        println!(
                            "  {} {} = {}  {}",
                            style("✓").green(),
                            style(name).bold().cyan(),
                            style(ov).yellow(),
                            style("[from --params]").dim(),
                        );
                        ctx.set_compile_param(*name, ov);
                    } else {
                        let default = def.default.as_deref();
                        let value = prompt::prompt_param(name, &def.type_, def.description.as_deref(), default)?;
                        ctx.set_compile_param(*name, value);
                    }
                } else if let Some(ov) = overrides.get(name) {
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(ov).yellow(),
                        style("[from --params]").dim(),
                    );
                    ctx.set_compile_param(*name, ov);
                } else {
                    let default = def.default.as_deref();
                    let value = prompt::prompt_param(name, &def.type_, def.description.as_deref(), default)?;
                    ctx.set_compile_param(*name, value);
                }
            }
        }

        // Load derived params: instance file first (authoritative), then --params overrides.
        let mut loaded_inst = 0usize;
        let mut loaded_ovr = 0usize;
        for (name, _) in &derived {
            if let Some(inst_val) = instance.and_then(|i| i.get_field(name)) {
                ctx.set_compile_param(*name, inst_val);
                loaded_inst += 1;
            } else if let Some(ovr_val) = overrides.get(name) {
                // Derived params with no instance file (e.g. carry-over from a previous action)
                // can be supplied via --params.
                ctx.set_compile_param(*name, ovr_val);
                println!(
                    "  {} {} = {}  {}",
                    style("✓").green(),
                    style(name).bold().cyan(),
                    style(ovr_val).yellow(),
                    style("[from --params]").dim(),
                );
                loaded_ovr += 1;
            }
        }
        if loaded_inst > 0 {
            println!(
                "  {} {} derived param(s) loaded from instance file.",
                style("✓").green(), loaded_inst
            );
        }
        if loaded_ovr > 0 {
            println!(
                "  {} {} derived param(s) loaded from --params.",
                style("✓").green(), loaded_ovr
            );
        }

        // Evaluate expr-based derived params (arithmetic). Tapleaf params run after Step 3.
        for (name, def) in &derived {
            if ctx.get_compile_param(name).is_some() {
                continue; // already set from instance, --params, or a prior compute
            }
            let Some(crate::manifest::ParamCompute::Expr { expr }) = &def.compute else { continue };
            match eval::eval_param_compute_expr(expr, &ctx) {
                Ok(v) => {
                    let vs = v.to_string();
                    ctx.set_compile_param(*name, &vs);
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(*name).bold().cyan(),
                        style(&vs).yellow(),
                        style("[compute: expr]").dim(),
                    );
                }
                Err(e) => {
                    println!(
                        "  {} Derived param '{}' compute failed: {e}",
                        style("[warn]").yellow(),
                        name
                    );
                }
            }
        }
    }

    // For class methods: load all class field values from the instance file as compile params.
    // compile_param_sets() only iterates top-level params/compile_params, not class fields.
    if let Some((_, class_def, _)) = manifest.find_class_and_method(action_name) {
        let mut loaded_class = 0usize;
        for (field_name, field_def) in &class_def.fields {
            if ctx.get_compile_param(field_name).is_some() {
                continue;
            }
            if let Some(v) = instance
                .and_then(|i| i.get_field(field_name))
                .or_else(|| overrides.get(field_name))
            {
                ctx.set_compile_param(field_name, v);
                loaded_class += 1;
            } else if !action.is_constructor {
                // Not in instance or overrides — prompt, pre-filling with default if set.
                // Skipped for constructors: every field is an output computed by create_instance.
                let value = prompt::prompt_param(
                    field_name,
                    &field_def.type_,
                    field_def.description.as_deref(),
                    field_def.default.as_deref(),
                )?;
                ctx.set_compile_param(field_name, value);
            }
        }
        if loaded_class > 0 {
            println!(
                "  {} {} class field(s) loaded from instance.",
                style("✓").green(), loaded_class
            );
        }
    }

    // Type hints from manifest spec — needed for tapleaf computes (and later for covenant address).
    let mut compile_param_type_hints: std::collections::HashMap<String, String> = {
        let (user, derived) = manifest.compile_param_sets();
        user.into_iter().chain(derived)
            .map(|(name, def)| (name.to_string(), def.type_.clone()))
            .collect()
    };

    // Extend type hints with class field types for class methods.
    if let Some((_, class_def, _)) = manifest.find_class_and_method(action_name) {
        for (field_name, field_def) in &class_def.fields {
            compile_param_type_hints
                .entry(field_name.clone())
                .or_insert_with(|| field_def.type_.clone());
        }
    }

    if let Some(params) = &action.params {
        if !params.is_empty() {
            println!();
            println!("  {}", style("Action params:").bold());
            for (name, def) in params {
                if let Some(formula) = &def.formula {
                    println!(
                        "  {} {} formula: {}",
                        style(name).bold().cyan(),
                        style(format!("({})", def.type_)).dim(),
                        style(formula).yellow()
                    );
                }
                // SimfFn params are computed after inputs resolve (Step 3a). Skip here unless
                // an explicit override is provided via --params.
                if matches!(&def.compute, Some(crate::manifest::ParamCompute::SimfFn { .. }))
                    && overrides.get(name.as_str()).is_none()
                {
                    println!(
                        "  {} {}  {}",
                        style("○").dim(),
                        style(name.as_str()).cyan(),
                        style("[will be computed from simf after inputs resolve]").dim(),
                    );
                    continue;
                }

                // Priority: wallet_key source > --params override > formula auto-eval > interactive prompt.
                let value = if def.source.as_ref().map(|s| s.type_ == "wallet_key").unwrap_or(false) {
                    let info = loaded_wallet.as_ref()
                        .map(wallet::wallet_info)
                        .transpose()?
                        .ok_or_else(|| anyhow::anyhow!("Param '{name}' requires wallet_key source but no wallet is loaded"))?;
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(&info.wallet_pubkey).yellow(),
                        style(format!("[wallet key, path: {}]", info.wallet_key_path)).dim(),
                    );
                    info.wallet_pubkey.clone()
                } else if let Some(ov) = overrides.get(name) {
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(ov).yellow(),
                        style("[from --params]").dim(),
                    );
                    ov.to_string()
                } else if let Some(formula) = &def.formula {
                    let computed = eval::eval_expr_str(formula, &ctx)?;
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(&computed).yellow(),
                        style(format!("[auto: {formula}]")).dim(),
                    );
                    computed
                } else {
                    let default = def.default.as_deref();
                    prompt::prompt_param(name, &def.type_, def.description.as_deref(), default)?
                };
                ctx.set_param(name, value.clone());
                // Also write into compile_params so that covenant hash computations
                // (step 3b tapleaf derives) see the fresh value, not a stale one
                // that may have been loaded from a previous instance file.
                ctx.set_compile_param(name, value);
            }
        }
    }

    if let Some(args) = &action.args {
        if !args.is_empty() {
            println!();
            println!("  {}", style("Action args:").bold());
            for (name, def) in args {
                let value = if let Some(ov) = overrides.get(name) {
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(ov).yellow(),
                        style("[from --params]").dim(),
                    );
                    ov.to_string()
                } else {
                    let default = def.default.as_deref();
                    prompt::prompt_param(name, &def.type_, def.description.as_deref(), default)?
                };
                ctx.set_arg(name, value);
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 2 — Input Selection
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 2: Input Selection"));

    let mut claimed: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(inputs) = &action.inputs {
        for input in inputs {
            // Resolution priority: instance.provided_inputs → state file (by utxo_type) → auto-select / prompt
            let resolved = if let Some(provided) = instance
                .and_then(|inst| inst.provided_inputs.get(&input.id))
            {
                println!(
                    "  {} {}  txid={}…  vout={}  {} sat  asset={}  {}",
                    style("✓").green(),
                    style(&input.id).bold(),
                    &provided.txid[..8.min(provided.txid.len())],
                    provided.vout,
                    style(provided.amount_sat).yellow(),
                    style(&provided.asset).dim(),
                    style("[provided]").cyan(),
                );
                provided.clone()
            } else if let Some(type_name) = input.utxo_type_name() {
                // Try to resolve from the state file based on utxo_type + optional asset filter.
                let state_match = contract_state.as_ref().and_then(|s| {
                    let candidates = s.utxos_for_type(&type_name);
                    // If the input specifies an asset, filter by it; otherwise take the first.
                    let asset_filter = input.asset.as_ref().and_then(|v| v.as_str()).map(|a| {
                        if let Some(k) = a
                            .strip_prefix("instance.")
                            .or_else(|| a.strip_prefix("compile_params."))
                        {
                            ctx.get_compile_param(k).unwrap_or(a).to_string()
                        } else {
                            a.to_string()
                        }
                    });
                    candidates.into_iter().find(|u| {
                        asset_filter.as_ref().is_none_or(|a| &u.asset == a)
                    }).cloned()
                });
                if let Some(utxo) = state_match {
                    println!(
                        "  {} {}  txid={}…  vout={}  {} sat  asset={}  {}",
                        style("✓").green(),
                        style(&input.id).bold(),
                        &utxo.txid[..8.min(utxo.txid.len())],
                        utxo.vout,
                        style(utxo.amount_sat).yellow(),
                        style(&utxo.asset).dim(),
                        style("[state]").cyan(),
                    );
                    ResolvedInput {
                        id: input.id.clone(),
                        txid: utxo.txid.clone(),
                        vout: utxo.vout,
                        amount_sat: utxo.amount_sat,
                        asset: utxo.asset.clone(),
                        issuance_entropy: None,
                    }
                } else {
                    select_input(
                        input,
                        &available_utxos,
                        &available_explicit,
                        &mut claimed,
                        manual_inputs,
                        loaded_wallet.as_ref().map(|w| {
                            if w.is_mainnet() { ElementsNetwork::Liquid }
                            else { ElementsNetwork::LiquidTestnet }
                        }),
                        &ctx,
                    )?
                }
            } else {
                select_input(
                    input,
                    &available_utxos,
                    &available_explicit,
                    &mut claimed,
                    manual_inputs,
                    loaded_wallet.as_ref().map(|w| {
                        if w.is_mainnet() { ElementsNetwork::Liquid }
                        else { ElementsNetwork::LiquidTestnet }
                    }),
                    &ctx,
                )?
            };
            ctx.set_input(resolved);
        }
    } else {
        println!("  (no inputs defined for this action)");
    }

    // ------------------------------------------------------------------
    // Step 3 — Resolving Derived Parameters (on_input_resolved hooks)
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 3: Resolving Derived Parameters"));

    let has_hooks = action
        .hooks
        .as_ref()
        .and_then(|h| h.on_input_resolved.as_ref())
        .map(|m| !m.is_empty())
        .unwrap_or(false);

    if has_hooks {
        let hooks = action.hooks.as_ref().unwrap().on_input_resolved.as_ref().unwrap();
        println!(
            "  {}",
            style("Note: hook execution order follows BTreeMap key order (alphabetical). \
                 A production wallet should use IndexMap to preserve declaration order.")
            .yellow()
        );
        for (input_id, hook) in hooks {
            for (param_path, expr) in &hook.set {
                match eval::eval_simplicityhl_hook(expr, input_id, &ctx) {
                    Ok(value) => {
                        // Store the result under the appropriate context namespace
                        if let Some(name) = param_path
                            .strip_prefix("instance.")
                            .or_else(|| param_path.strip_prefix("compile_params."))
                        {
                            ctx.set_compile_param(name, &value);
                        } else if let Some(name) = param_path.strip_prefix("params.") {
                            ctx.set_param(name, &value);
                        } else if let Some(name) = param_path.strip_prefix("args.") {
                            ctx.set_arg(name, &value);
                        }
                        let short = &value[..value.len().min(16)];
                        println!(
                            "  {} {} = {}…",
                            style("✓").green(),
                            style(param_path).bold(),
                            style(short).yellow(),
                        );
                    }
                    Err(e) => {
                        println!(
                            "  {} {} (SimplicityHL: {})",
                            style("[hook — not evaluated]").yellow(),
                            style(param_path).bold(),
                            style(e).dim(),
                        );
                    }
                }
            }
        }
    } else {
        println!("  (no on_input_resolved hooks for this action)");
    }

    {
        let (_, derived) = manifest.compile_param_sets();
        if !derived.is_empty() {
            println!();
            println!("  {}", style("Derived params (set by hooks):").bold());
            for (name, def) in derived {
                println!(
                    "  {} {} — {}",
                    style(name).cyan(),
                    style(format!("({})", def.type_)).dim(),
                    def.description.as_deref().unwrap_or("")
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 3a — Issuance asset IDs + on_resolved compile-param hooks
    // Must run before Step 3b so issuance-derived params (e.g. LENDER_NFT_ASSET_ID)
    // are in ctx when tapleaf hashes are computed.
    // ------------------------------------------------------------------
    for inp in action.inputs.as_deref().unwrap_or_default() {
        match issuance_kind(inp) {
            Some("new") => {
                if let Some(resolved) = ctx.get_input(&inp.id) {
                    if let Ok((asset_id, token_id)) = pset_builder::compute_asset_ids_from_outpoint(
                        &resolved.txid, resolved.vout,
                    ) {
                        ctx.set_input_attr(&inp.id, "asset", asset_id.to_string());
                        ctx.set_input_attr(&inp.id, "reissuance_token", token_id.to_string());
                    }
                }
            }
            Some("reissue") => {
                let (rt_asset, entropy_hex_opt) = match ctx.get_input(&inp.id) {
                    Some(r) => (r.asset.clone(), r.issuance_entropy.clone()),
                    None => continue,
                };
                ctx.set_input_attr(&inp.id, "reissuance_token", &rt_asset);
                if let Some(entropy_hex) = entropy_hex_opt {
                    if let Ok(entropy) = pset_builder::decode_entropy_hex(&entropy_hex) {
                        if let Ok(asset_id) = pset_builder::compute_asset_from_entropy(&entropy) {
                            ctx.set_input_attr(&inp.id, "asset", asset_id.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for inp in action.inputs.as_deref().unwrap_or_default() {
        let Some(hook) = &inp.on_resolved else { continue };
        for (target, formula) in &hook.set {
            let value: Option<String> = match formula.trim() {
                "asset" => ctx
                    .get_input_attr(&inp.id, "asset")
                    .map(str::to_string)
                    .or_else(|| ctx.get_input(&inp.id).map(|r| r.asset.clone())),
                "reissuance_token" => ctx
                    .get_input_attr(&inp.id, "reissuance_token")
                    .map(str::to_string),
                other => eval::eval_expr_str(other, &ctx).ok(),
            };
            match value {
                None => println!(
                    "  {} on_resolved set '{}' = '{}' — could not resolve.",
                    style("[warn]").yellow(), target, formula
                ),
                Some(v) => {
                    if let Some(name) = target
                        .strip_prefix("instance.")
                        .or_else(|| target.strip_prefix("compile_params."))
                    {
                        ctx.set_compile_param(name, &v);
                    } else if let Some(name) = target.strip_prefix("params.") {
                        ctx.set_param(name, &v);
                    } else if let Some(name) = target.strip_prefix("args.") {
                        ctx.set_arg(name, &v);
                    }
                    let short = &v[..v.len().min(16)];
                    println!(
                        "  {} {} = {}…  {}",
                        style("✓").green(),
                        style(target).bold().cyan(),
                        style(short).yellow(),
                        style(format!("[on_resolved: {}]", inp.id)).dim(),
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 3a-ii — Method-level on_pre_broadcast hook
    // Runs after input resolution + issuance attrs, before PSET construction.
    // ------------------------------------------------------------------
    if let Some(hook) = &action.on_pre_broadcast {
        run_hook_block(hook, &mut ctx, "[on_pre_broadcast]");
    }

    // ------------------------------------------------------------------
    // Step 3b — Tapleaf-derived params (computed after hooks set asset IDs)
    // ------------------------------------------------------------------
    let net_for_hash = loaded_wallet.as_ref()
        .map(wallet::elements_network)
        .unwrap_or(ElementsNetwork::LiquidTestnet);
    {
        let (_, derived_defs) = manifest.compile_param_sets();
        let mut failed: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut any_new = true;
        while any_new {
            any_new = false;
            for (name, def) in &derived_defs {
                if ctx.get_compile_param(name).is_some() || failed.contains(*name) { continue; }
                let Some(crate::manifest::ParamCompute::Tapleaf { simf, params, depends_on }) = &def.compute else { continue };

                // Resolve the params map for this simf compilation.
                // When no explicit params override is given, auto-populate:
                //   • if `depends_on` is set, wait only for those params (and pass only them)
                //   • otherwise wait for ALL compile params (legacy behaviour)
                let simf_params: std::collections::HashMap<String, String> = if params.is_empty() {
                    let mut resolved = std::collections::HashMap::new();
                    let mut all_ready = true;
                    let gate: Box<dyn Iterator<Item = &str>> = match depends_on {
                        Some(deps) => Box::new(deps.iter().map(String::as_str)),
                        None => Box::new(manifest.all_compile_param_names().into_iter()),
                    };
                    for cp_name in gate {
                        match ctx.get_compile_param(cp_name) {
                            Some(v) => { resolved.insert(cp_name.to_string(), v.to_string()); }
                            None => { all_ready = false; break; }
                        }
                    }
                    if !all_ready { continue; }
                    resolved
                } else {
                    let mut resolved = std::collections::HashMap::new();
                    let mut all_ready = true;
                    for (k, p) in params {
                        let v = p.value.as_str();
                        // v is either a compile-param reference or a string/bool literal
                        let is_param_ref = ctx.get_compile_param(v).is_some();
                        let is_literal = v.parse::<u64>().is_ok() || v == "true" || v == "false";
                        if !is_param_ref && !is_literal {
                            all_ready = false; // dependency not computed yet
                            break;
                        }
                        let value = ctx.get_compile_param(v)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| p.value.clone());
                        resolved.insert(k.clone(), value);
                    }
                    if !all_ready { continue; }
                    resolved
                };

                // Build type hints: inherit from compile param types (same-name mapping),
                // then override with any explicit inline types from the params map.
                let simf_type_hints: std::collections::HashMap<String, String> = {
                    let mut hints: std::collections::HashMap<String, String> = simf_params.keys()
                        .filter_map(|k| compile_param_type_hints.get(k).map(|t| (k.clone(), t.clone())))
                        .collect();
                    if !params.is_empty() {
                        // For explicit params, inherit type from the *referenced* compile param name.
                        for (k, p) in params {
                            if let Some(ty) = compile_param_type_hints.get(p.value.as_str()) {
                                hints.insert(k.clone(), ty.clone());
                            }
                        }
                        // Then apply inline type overrides.
                        for (k, p) in params {
                            if let Some(ty) = &p.type_ {
                                hints.insert(k.clone(), ty.clone());
                            }
                        }
                    }
                    hints
                };

                let simf_path = manifest_file.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join(simf);

                match covenant::compute_covenant_script_hash(&simf_path, &simf_params, &simf_type_hints, net_for_hash) {
                    Ok(hash_bytes) => {
                        let hex: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();
                        ctx.set_compile_param(*name, &hex);
                        println!(
                            "  {} {} = {}  {}",
                            style("✓").green(),
                            style(*name).bold().cyan(),
                            style(&hex[..16]).yellow(),
                            style("[compute: script_hash]").dim(),
                        );
                        any_new = true;
                    }
                    Err(e) => {
                        println!(
                            "  {} Script hash compute '{}' failed: {e}",
                            style("[error]").red(), name
                        );
                        failed.insert(name.to_string());
                    }
                }
            }
        }
        // ----------------------------------------------------------------
        // Fixed-point pass for circular tapleaf dependencies.
        // Only runs on deploy actions — non-deploy actions read covenant
        // hashes from the instance file rather than recomputing them.
        // ----------------------------------------------------------------
        if action.deploy {
        {
            let stuck_names: Vec<String> = derived_defs
                .iter()
                .filter(|(name, def)| {
                    ctx.get_compile_param(name).is_none()
                        && !failed.contains(*name)
                        && matches!(&def.compute, Some(crate::manifest::ParamCompute::Tapleaf { .. }))
                })
                .map(|(n, _)| n.to_string())
                .collect();

            if !stuck_names.is_empty() {
                let stuck_set: std::collections::HashSet<&str> =
                    stuck_names.iter().map(String::as_str).collect();

                // Separate genuine circular params (only blocked by other stuck tapleaf params)
                // from those with a missing non-tapleaf dependency (real error).
                let mut genuine_circular: Vec<String> = Vec::new();
                for stuck_name in &stuck_names {
                    let Some((_, def)) = derived_defs.iter().find(|(n, _)| *n == stuck_name.as_str()) else { continue };
                    let Some(crate::manifest::ParamCompute::Tapleaf { params, .. }) = &def.compute else { continue };

                    let has_non_stuck_blocker = if params.is_empty() {
                        // auto-populate: blocked by any unresolved compile param NOT in the stuck set
                        manifest.all_compile_param_names().into_iter().any(|cp| {
                            ctx.get_compile_param(cp).is_none() && !stuck_set.contains(cp)
                        })
                    } else {
                        // explicit params: blocked by any unresolved param ref NOT in the stuck set
                        params.values().any(|p| {
                            let v = p.value.as_str();
                            v.parse::<u64>().is_err()
                                && v != "true"
                                && v != "false"
                                && ctx.get_compile_param(v).is_none()
                                && !stuck_set.contains(v)
                        })
                    };

                    if !has_non_stuck_blocker {
                        genuine_circular.push(stuck_name.clone());
                    }
                    // Params with real missing deps stay unresolved; caught by the failed check below.
                }

                if !genuine_circular.is_empty() {
                    println!(
                        "\n  {} Resolving {} circular tapleaf param(s) via fixed-point: {}",
                        style("[fixed-point]").cyan().bold(),
                        genuine_circular.len(),
                        genuine_circular.join(", ")
                    );

                    // Seed all circular params with 32-byte zeros.
                    let zero_seed = "0".repeat(64);
                    for name in &genuine_circular {
                        if ctx.get_compile_param(name).is_none() {
                            ctx.set_compile_param(name, &zero_seed);
                        }
                    }

                    // Iterate until stable (convergence typically happens in 2–3 rounds).
                    let mut converged = false;
                    for iter_num in 0usize..20 {
                        let mut changed = false;

                        for stuck_name in &genuine_circular {
                            if failed.contains(stuck_name.as_str()) { continue; }
                            let Some((_, def)) = derived_defs.iter().find(|(n, _)| *n == stuck_name.as_str()) else { continue };
                            let Some(crate::manifest::ParamCompute::Tapleaf { simf, params, .. }) = &def.compute else { continue };

                            let simf_params_opt: Option<std::collections::HashMap<String, String>> = if params.is_empty() {
                                let mut resolved = std::collections::HashMap::new();
                                let mut ok = true;
                                for cp_name in manifest.all_compile_param_names() {
                                    match ctx.get_compile_param(cp_name) {
                                        Some(v) => { resolved.insert(cp_name.to_string(), v.to_string()); }
                                        None => { ok = false; break; }
                                    }
                                }
                                if ok { Some(resolved) } else { None }
                            } else {
                                let mut resolved = std::collections::HashMap::new();
                                let mut ok = true;
                                for (k, p) in params {
                                    let v = p.value.as_str();
                                    let val = if v.parse::<u64>().is_ok() || v == "true" || v == "false" {
                                        p.value.clone()
                                    } else {
                                        match ctx.get_compile_param(v) {
                                            Some(s) => s.to_string(),
                                            None => { ok = false; break; }
                                        }
                                    };
                                    resolved.insert(k.clone(), val);
                                }
                                if ok { Some(resolved) } else { None }
                            };

                            let Some(simf_params) = simf_params_opt else { continue };

                            let simf_type_hints: std::collections::HashMap<String, String> = {
                                let mut hints: std::collections::HashMap<String, String> = simf_params.keys()
                                    .filter_map(|k| compile_param_type_hints.get(k).map(|t| (k.clone(), t.clone())))
                                    .collect();
                                if !params.is_empty() {
                                    for (k, p) in params {
                                        if let Some(ty) = compile_param_type_hints.get(p.value.as_str()) {
                                            hints.insert(k.clone(), ty.clone());
                                        }
                                    }
                                    for (k, p) in params {
                                        if let Some(ty) = &p.type_ {
                                            hints.insert(k.clone(), ty.clone());
                                        }
                                    }
                                }
                                hints
                            };

                            let simf_path = manifest_file.parent()
                                .unwrap_or(std::path::Path::new("."))
                                .join(simf.as_str());

                            match covenant::compute_covenant_script_hash(&simf_path, &simf_params, &simf_type_hints, net_for_hash) {
                                Ok(hash_bytes) => {
                                    let hex: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();
                                    let old = ctx.get_compile_param(stuck_name).map(str::to_string).unwrap_or_default();
                                    if hex != old {
                                        changed = true;
                                        ctx.set_compile_param(stuck_name, &hex);
                                    }
                                }
                                Err(e) => {
                                    println!(
                                        "  {} Fixed-point compute '{}' failed: {e}",
                                        style("[error]").red(), stuck_name
                                    );
                                    failed.insert(stuck_name.clone());
                                }
                            }
                        }

                        if !changed {
                            converged = true;
                            println!(
                                "  {} Fixed-point converged in {} iteration(s).",
                                style("✓").green(), iter_num + 1
                            );
                            for name in &genuine_circular {
                                if !failed.contains(name.as_str()) {
                                    if let Some(hex) = ctx.get_compile_param(name) {
                                        println!(
                                            "  {} {} = {}…  {}",
                                            style("✓").green(),
                                            style(name.as_str()).bold().cyan(),
                                            style(&hex[..16.min(hex.len())]).yellow(),
                                            style("[compute: tapleaf fixed-point]").dim(),
                                        );
                                    }
                                }
                            }
                            break;
                        }
                    }

                    if !converged {
                        println!(
                            "  {} Fixed-point did not converge in 20 iterations — using last computed values.",
                            style("[warn]").yellow()
                        );
                    }

                    // Re-run the normal tapleaf loop: fixed-point values may unblock
                    // any remaining explicit-params tapleaf entries.
                    let mut any_new2 = true;
                    while any_new2 {
                        any_new2 = false;
                        for (name, def) in &derived_defs {
                            if ctx.get_compile_param(name).is_some() || failed.contains(*name) { continue; }
                            let Some(crate::manifest::ParamCompute::Tapleaf { simf, params, .. }) = &def.compute else { continue };

                            let simf_params_opt: Option<std::collections::HashMap<String, String>> = if params.is_empty() {
                                let mut resolved = std::collections::HashMap::new();
                                let mut ok = true;
                                for cp_name in manifest.all_compile_param_names() {
                                    match ctx.get_compile_param(cp_name) {
                                        Some(v) => { resolved.insert(cp_name.to_string(), v.to_string()); }
                                        None => { ok = false; break; }
                                    }
                                }
                                if ok { Some(resolved) } else { None }
                            } else {
                                let mut resolved = std::collections::HashMap::new();
                                let mut ok = true;
                                for (k, p) in params {
                                    let v = p.value.as_str();
                                    let val = if v.parse::<u64>().is_ok() || v == "true" || v == "false" {
                                        p.value.clone()
                                    } else {
                                        match ctx.get_compile_param(v) {
                                            Some(s) => s.to_string(),
                                            None => { ok = false; break; }
                                        }
                                    };
                                    resolved.insert(k.clone(), val);
                                }
                                if ok { Some(resolved) } else { None }
                            };

                            let Some(simf_params) = simf_params_opt else { continue };

                            let simf_type_hints: std::collections::HashMap<String, String> = {
                                let mut hints: std::collections::HashMap<String, String> = simf_params.keys()
                                    .filter_map(|k| compile_param_type_hints.get(k).map(|t| (k.clone(), t.clone())))
                                    .collect();
                                if !params.is_empty() {
                                    for (k, p) in params {
                                        if let Some(ty) = compile_param_type_hints.get(p.value.as_str()) {
                                            hints.insert(k.clone(), ty.clone());
                                        }
                                    }
                                    for (k, p) in params {
                                        if let Some(ty) = &p.type_ {
                                            hints.insert(k.clone(), ty.clone());
                                        }
                                    }
                                }
                                hints
                            };

                            let simf_path = manifest_file.parent()
                                .unwrap_or(std::path::Path::new("."))
                                .join(simf.as_str());

                            match covenant::compute_covenant_script_hash(&simf_path, &simf_params, &simf_type_hints, net_for_hash) {
                                Ok(hash_bytes) => {
                                    let hex: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();
                                    ctx.set_compile_param(*name, &hex);
                                    println!(
                                        "  {} {} = {}…  {}",
                                        style("✓").green(),
                                        style(*name).bold().cyan(),
                                        style(&hex[..16.min(hex.len())]).yellow(),
                                        style("[compute: script_hash]").dim(),
                                    );
                                    any_new2 = true;
                                }
                                Err(e) => {
                                    println!(
                                        "  {} Script hash compute '{}' failed: {e}",
                                        style("[error]").red(), name
                                    );
                                    failed.insert(name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        } // end if action.deploy

        if !failed.is_empty() {
            let names: Vec<&str> = failed.iter().map(String::as_str).collect();
            anyhow::bail!(
                "Cannot proceed: tapleaf compute failed for: {}",
                names.join(", ")
            );
        }
    }

    // ------------------------------------------------------------------
    // Step 3c — SimfFn computed action params
    // Runs after inputs are fully resolved so that input-derived values
    // (e.g. params.STATE_BYTES already entered, inputs.*.state_bytes) are
    // available to the function.
    // ------------------------------------------------------------------
    if let Some(params) = &action.params {
        let simf_params: Vec<(&str, &crate::manifest::ParamDef)> = params
            .iter()
            .filter(|(_, def)| matches!(&def.compute, Some(crate::manifest::ParamCompute::SimfFn { .. })))
            .map(|(n, d)| (n.as_str(), d))
            .collect();

        if !simf_params.is_empty() {
            println!();
            println!("{}", step_header("Step 3c: SimfFn Computed Params"));
        }

        for (name, def) in simf_params {
            // If an override was supplied in Step 1 the param is already in ctx — skip.
            if ctx.get_param(name).is_some() { continue; }

            let crate::manifest::ParamCompute::SimfFn { simf, fn_name, compile_params: cp_names, input } =
                def.compute.as_ref().unwrap() else { continue };

            // Build the compile-param subset that will become param:: constants.
            let mut cp_map = std::collections::HashMap::new();
            for cp_name in cp_names {
                match ctx.get_compile_param(cp_name) {
                    Some(v) => { cp_map.insert(cp_name.clone(), v.to_string()); }
                    None => {
                        println!(
                            "  {} {} — compile param '{}' not yet in ctx, skipping simf_fn compute",
                            style("[warn]").yellow(), name, cp_name
                        );
                    }
                }
            }

            // Resolve the runtime input value (e.g. "params.STATE_BYTES").
            let _input_hex: Option<String> = input.as_deref().and_then(|path| {
                eval::eval_expr_str(path, &ctx).ok()
            });

            let simf_path = manifest_file
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join(simf.as_str());

            // Ensure input_hex has a "0x" prefix so SimplicityHL can parse it as a byte array.
            let input_hex_owned: String;
            let input_hex: &str = match _input_hex.as_deref() {
                Some(h) if h.starts_with("0x") || h.starts_with("0X") || h.is_empty() => h,
                Some(h) => { input_hex_owned = format!("0x{h}"); &input_hex_owned },
                None => "",
            };
            match covenant::execute_simf_function(
                &simf_path,
                fn_name.as_deref(),
                &cp_map,
                &compile_param_type_hints,
                input_hex,
            ) {
                Ok(result_hex) => {
                    println!(
                        "  {} {} = {}…  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        &result_hex[..result_hex.len().min(16)],
                        style("[simf_fn]").dim(),
                    );
                    ctx.set_param(name, result_hex.clone());
                    ctx.set_compile_param(name, result_hex);
                    continue;
                }
                Err(e) => {
                    println!(
                        "  {} {} — simf_fn failed: {}",
                        style("[error]").red(), name, e
                    );
                    // Fall back to interactive prompt so the user can supply the value manually.
                    let default = def.default.as_deref();
                    let value = prompt::prompt_param(name, &def.type_, def.description.as_deref(), default)?;
                    ctx.set_param(name, value.clone());
                    ctx.set_compile_param(name, value);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 4 — Constructing Outputs
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 4: Constructing Outputs"));

    if let Some(outputs) = &action.outputs {
        for output in outputs {
            let optional_tag = if output.optional.unwrap_or(false) {
                style(" [optional]").dim().to_string()
            } else {
                String::new()
            };
            println!(
                "  {} → {}{}",
                style(&output.id).bold().cyan(),
                output.destination_summary(),
                optional_tag
            );
            if let Some(desc) = &output.description {
                println!("    {}", style(desc).dim());
            }
            if let Some(amount) = &output.amount_sat {
                println!("    amount_sat = {}", style(amount.to_string()).yellow());
            }
        }
    } else {
        println!("  (no outputs defined for this action)");
    }

    // ------------------------------------------------------------------
    // Step 5 — Fee
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 5: Fee"));
    let fee_rate = if let Some(ov) = overrides.get("fee_rate") {
        let r: f64 = ov.parse().map_err(|e| anyhow::anyhow!("fee_rate in --params is not a number: {e}"))?;
        println!("  {} Using fee rate: {} sat/vb  {}", style("✓").green(), r, style("[from --params]").dim());
        r
    } else {
        let r = prompt::prompt_fee_rate()?;
        println!("  {} Using fee rate: {} sat/vb", style("✓").green(), r);
        r
    };

    // ------------------------------------------------------------------
    // Step 6 — Validation
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 6: Validation"));

    if let Some(hooks) = &action.hooks {
        if hooks.on_validate.is_some() {
            println!(
                "  {} on_validate hook present (SimplicityHL) — not executed in this version.",
                style("[TODO]").yellow()
            );
        }
    }

    if let Some(validations) = &action.validations {
        if validations.is_empty() {
            println!("  (no validations defined for this action)");
        }
        for validation in validations {
            run_validation(validation, &manifest, &ctx)?;
        }
    } else {
        println!("  (no validations defined for this action)");
    }

    // ------------------------------------------------------------------
    // Step 7 — PSET
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 7: PSET"));

    // Open a Wollet backed by persisted state — used for PSET building and finalization.
    let wollet_opt: Option<Wollet> = match &loaded_wallet {
        None => {
            println!("  {} No wallet loaded — cannot build PSET.", style("[warn]").yellow());
            None
        }
        Some(w) => {
            let net = wallet::elements_network(w);
            let desc = wallet::descriptor(w)
                .map_err(|e| anyhow::anyhow!("Cannot build descriptor: {e}"))?;
            std::fs::create_dir_all(data_dir)
                .with_context(|| format!("Cannot create data dir: {}", data_dir.display()))?;
            match FsPersister::new(data_dir, net, &desc) {
                Err(e) => {
                    println!("  {} Cannot open wallet state: {e}", style("[warn]").yellow());
                    None
                }
                Ok(persister) => match lwk_wollet::Wollet::new(net, persister, desc) {
                    Err(e) => {
                        println!("  {} Cannot open wallet: {e}", style("[warn]").yellow());
                        None
                    }
                    Ok(w) => Some(w),
                },
            }
        }
    };

    let network_for_asset = loaded_wallet.as_ref().map(wallet::elements_network);
    let mut pset_opt: Option<lwk_wollet::elements::pset::PartiallySignedTransaction> = None;

    // Tracks covenant outputs for state-file updates after broadcast.
    struct CovenantOutputMeta {
        utxo_type: String,
        output_id: String,
        script_pubkey: lwk_wollet::elements::Script,
        amount_sat: u64,
        asset: lwk_wollet::elements::AssetId,
    }
    let mut covenant_output_meta: Vec<CovenantOutputMeta> = Vec::new();

    // Computed here so both Step 7 (PSET building) and Step 9 (dry-run) can use them.
    let simf_path = manifest_file
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(manifest.source.as_deref().unwrap_or("covenant.simf"));

    // For constructor actions: pre-compute create_instance tapleaf fields (e.g.
    // FUNDING_SCRIPT_HASH) so they are present in compile_params_map for Step 7.
    // Without this, missing class fields fall back to the literal param name as a
    // value, which later fails `Value::parse_from_str` with non-hex characters.
    if action.is_constructor {
        if let Some(ci) = &action.create_instance {
            let pre_hints: std::collections::HashMap<String, String> = {
                let mut hints = compile_param_type_hints.clone();
                if let Some(params) = &action.params {
                    for (name, def) in params {
                        hints.entry(name.clone()).or_insert_with(|| def.type_.clone());
                    }
                }
                hints
            };
            let pre_fields = eval_create_instance_fields(
                ci, &ctx, manifest_file, &pre_hints, net_for_hash, false,
            );
            for (name, val) in pre_fields {
                ctx.set_compile_param(&name, val);
            }
        }
    }

    let compile_params_map: std::collections::HashMap<String, String> = {
        let mut m = std::collections::HashMap::new();
        for name in manifest.all_compile_param_names() {
            if let Some(v) = ctx.get_compile_param(name) {
                m.insert(name.to_string(), v.to_string());
            }
        }
        // For class methods: also expose class field values (loaded into ctx in Step 1).
        if let Some((_, class_def, _)) = manifest.find_class_and_method(action_name) {
            for field_name in class_def.fields.keys() {
                if !m.contains_key(field_name.as_str()) {
                    if let Some(v) = ctx.get_compile_param(field_name) {
                        m.insert(field_name.clone(), v.to_string());
                    }
                }
            }
        }
        m
    };

    // Snapshot of action param values, used to resolve witness signing-key
    // references of the form `params.NAME` — needed when a covenant is keyed by
    // a runtime parameter rather than a compile param (see per-site compile_params).
    let action_params_map: std::collections::HashMap<String, String> = {
        let mut m = std::collections::HashMap::new();
        if let Some(defs) = &action.params {
            for k in defs.keys() {
                if let Some(v) = ctx.get_param(k) {
                    m.insert(k.clone(), v.to_string());
                }
            }
        }
        m
    };

    if let (Some(wollet), Some(net)) = (&wollet_opt, network_for_asset) {

        // ---- Populate input attrs for issuance inputs (needed by output asset resolution) ----
        for inp in action.inputs.as_deref().unwrap_or_default() {
            match issuance_kind(inp) {
                Some("new") => {
                    if let Some(resolved) = ctx.get_input(&inp.id) {
                        if let Ok((asset_id, token_id)) = pset_builder::compute_asset_ids_from_outpoint(
                            &resolved.txid, resolved.vout
                        ) {
                            ctx.set_input_attr(&inp.id, "asset", asset_id.to_string());
                            ctx.set_input_attr(&inp.id, "reissuance_token", token_id.to_string());
                        }
                    }
                }
                Some("reissue") => {
                    let (rt_asset, entropy_hex_opt) = match ctx.get_input(&inp.id) {
                        Some(r) => (r.asset.clone(), r.issuance_entropy.clone()),
                        None => continue,
                    };
                    ctx.set_input_attr(&inp.id, "reissuance_token", &rt_asset);
                    if let Some(entropy_hex) = entropy_hex_opt {
                        if let Ok(entropy) = pset_builder::decode_entropy_hex(&entropy_hex) {
                            if let Ok(asset_id) = pset_builder::compute_asset_from_entropy(&entropy) {
                                ctx.set_input_attr(&inp.id, "asset", asset_id.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // ---- Evaluate on_resolved inline hooks ----
        for inp in action.inputs.as_deref().unwrap_or_default() {
            let Some(hook) = &inp.on_resolved else { continue };
            for (target, formula) in &hook.set {
                // Within an input's own on_resolved, "asset" and "reissuance_token"
                // are self-referential: they resolve to the computed input attrs first
                // (the issuance asset / token), falling back to the UTXO's own fields.
                let value: Option<String> = match formula.trim() {
                    "asset" => ctx
                        .get_input_attr(&inp.id, "asset")
                        .map(str::to_string)
                        .or_else(|| ctx.get_input(&inp.id).map(|r| r.asset.clone())),
                    "reissuance_token" => ctx
                        .get_input_attr(&inp.id, "reissuance_token")
                        .map(str::to_string),
                    other => eval::eval_expr_str(other, &ctx).ok(),
                };
                match value {
                    None => println!(
                        "  {} on_resolved set '{}' = '{}' — could not resolve formula.",
                        style("[warn]").yellow(), target, formula
                    ),
                    Some(v) => {
                        if let Some(name) = target
                            .strip_prefix("instance.")
                            .or_else(|| target.strip_prefix("compile_params."))
                        {
                            ctx.set_compile_param(name, &v);
                        } else if let Some(name) = target.strip_prefix("params.") {
                            ctx.set_param(name, &v);
                        } else if let Some(name) = target.strip_prefix("args.") {
                            ctx.set_arg(name, &v);
                        } else {
                            println!(
                                "  {} on_resolved set '{}' — unknown namespace (expected instance./params./args.).",
                                style("[warn]").yellow(), target
                            );
                            continue;
                        }
                        let short = &v[..v.len().min(16)];
                        println!(
                            "  {} {} = {}…  {}",
                            style("✓").green(),
                            style(target).bold().cyan(),
                            style(short).yellow(),
                            style(format!("[on_resolved: {}]", inp.id)).dim(),
                        );
                    }
                }
            }
        }

        // ---- Collect PSET inputs ----
        let mut pset_inputs: Vec<pset_builder::PsetInput> = Vec::new();
        let mut collect_inputs_ok = true;

        for inp in action.inputs.as_deref().unwrap_or_default() {
            let kind = issuance_kind(inp);

            let iso_spec = match kind {
                Some("new") => {
                    let v = inp.issuance.as_ref().unwrap();
                    let asset_amount = v.get("asset_amount_sat")
                        .map(|a| eval::eval_amount(a, &ctx).unwrap_or(0)).unwrap_or(0);
                    let inflation_amount = v.get("inflation_amount_sat")
                        .map(|a| eval::eval_amount(a, &ctx).unwrap_or(0)).unwrap_or(0);
                    Some(pset_builder::IssuanceKind::New { asset_amount, inflation_amount })
                }
                Some("reissue") => {
                    let v = inp.issuance.as_ref().unwrap();
                    let asset_amount = match v.get("asset_amount_sat")
                        .map(|a| eval::eval_amount(a, &ctx))
                    {
                        Some(Ok(n)) => n,
                        Some(Err(e)) => {
                            println!("  {} Input '{}' reissue amount eval failed: {e}", style("[error]").red(), inp.id);
                            collect_inputs_ok = false;
                            break;
                        }
                        None => 0,
                    };
                    let entropy = if let Some(resolved) = ctx.get_input(&inp.id) {
                        if let Some(hex) = &resolved.issuance_entropy.clone() {
                            match pset_builder::decode_entropy_hex(hex) {
                                Ok(e) => e,
                                Err(err) => {
                                    println!("  {} Input '{}' entropy decode failed: {err}", style("[error]").red(), inp.id);
                                    collect_inputs_ok = false;
                                    break;
                                }
                            }
                        } else {
                            println!("  {} Input '{}' is a reissuance but has no issuance_entropy — add it to the instance file.", style("[error]").red(), inp.id);
                            collect_inputs_ok = false;
                            break;
                        }
                    } else {
                        println!("  {} Input '{}' not resolved", style("[error]").red(), inp.id);
                        collect_inputs_ok = false;
                        break;
                    };
                    Some(pset_builder::IssuanceKind::Reissue { asset_amount, entropy })
                }
                _ => None,
            };

            // Resolve the per-input nSequence (BIP68 relative timelock), if any.
            let input_sequence = match resolve_input_sequence(inp, &ctx) {
                Ok(s) => s,
                Err(e) => {
                    println!("  {} Input '{}' sequence: {e}", style("[error]").red(), inp.id);
                    collect_inputs_ok = false;
                    break;
                }
            };

            if inp.is_wallet_source() {
                let resolved_result: Result<(lwk_wollet::elements::Txid, u32)> = (|| {
                    let resolved = ctx.get_input(&inp.id)
                        .ok_or_else(|| anyhow::anyhow!("Input '{}' not resolved", inp.id))?;
                    let txid = lwk_wollet::elements::Txid::from_str(&resolved.txid)
                        .with_context(|| format!("Cannot parse txid '{}'", resolved.txid))?;
                    Ok((txid, resolved.vout))
                })();
                match resolved_result {
                    Err(e) => {
                        println!("  {} {e}", style("[error]").red());
                        collect_inputs_ok = false;
                        break;
                    }
                    Ok((txid, vout)) => {
                        // First try confidential (CT) wallet UTXOs.
                        if let Some(utxo) = available_utxos.iter().find(|u| u.outpoint.txid == txid && u.outpoint.vout == vout).cloned() {
                            pset_inputs.push(pset_builder::PsetInput::Wallet {
                                input_id: inp.id.clone(),
                                utxo,
                                issuance: iso_spec,
                                sequence: input_sequence,
                            });
                        } else if let Some(ext) = available_explicit.iter().find(|u| u.outpoint.txid == txid && u.outpoint.vout == vout).cloned() {
                            // Explicit (non-confidential) wallet UTXO — treat like a covenant input.
                            pset_inputs.push(pset_builder::PsetInput::Covenant {
                                input_id: inp.id.clone(),
                                outpoint: ext.outpoint,
                                script_pubkey: ext.txout.script_pubkey.clone(),
                                asset: ext.unblinded.asset,
                                amount: ext.unblinded.value,
                                issuance: iso_spec,
                                sequence: input_sequence,
                            });
                        } else {
                            println!(
                                "  {} UTXO {}:{} not found in wallet state — run `sync` first",
                                style("[error]").red(), txid, vout
                            );
                            collect_inputs_ok = false;
                            break;
                        }
                    }
                }
            } else if let Some(type_name) = inp.utxo_type_name() {
                let inp_ut = match manifest.utxo_type(&type_name) {
                    Ok(ut) => ut,
                    Err(e) => {
                        println!("  {} {e}", style("[error]").red());
                        collect_inputs_ok = false;
                        break;
                    }
                };
                let leaf_payloads = match inp_ut.resolve_extra_leaf_payloads() {
                    Ok(p) => p,
                    Err(e) => {
                        println!("  {} {e}", style("[error]").red());
                        collect_inputs_ok = false;
                        break;
                    }
                };
                let inp_simf_path = inp_ut.script.as_ref()
                    .and_then(|s| s.source.as_deref())
                    .map(|src| manifest_file.parent().unwrap_or(std::path::Path::new(".")).join(src))
                    .unwrap_or_else(|| simf_path.clone());
                let (inp_params, inp_hints) = apply_utxo_compile_params(&compile_params_map, &compile_param_type_hints, inp_ut);
                // Per-input `utxo_source.compile_params` overrides (resolved against action
                // params/args), mirroring the output `destination.compile_params` form.
                let (inp_params, inp_hints) = apply_site_compile_param_overrides(
                    inp_params, inp_hints, inp.utxo_source.get("compile_params"),
                    action, &compile_param_type_hints, &ctx,
                );
                let script_pubkey = match pset_builder::covenant_script_pubkey(&inp_simf_path, &inp_params, &inp_hints, &leaf_payloads, net) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  {} Covenant address failed (input '{}'):", style("[error]").red(), inp.id);
                        for (i, cause) in e.chain().enumerate() {
                            println!("    {i}: {cause}");
                        }
                        collect_inputs_ok = false;
                        break;
                    }
                };
                let resolved = match ctx.get_input(&inp.id) {
                    Some(r) => r.clone(),
                    None => {
                        println!("  {} Input '{}' not resolved", style("[error]").red(), inp.id);
                        collect_inputs_ok = false;
                        break;
                    }
                };
                let asset_id = match lwk_wollet::elements::AssetId::from_str(&resolved.asset) {
                    Ok(a) => a,
                    Err(e) => {
                        println!("  {} Input '{}' asset parse failed: {e}", style("[error]").red(), inp.id);
                        collect_inputs_ok = false;
                        break;
                    }
                };
                let txid = match lwk_wollet::elements::Txid::from_str(&resolved.txid) {
                    Ok(t) => t,
                    Err(e) => {
                        println!("  {} Input '{}' txid parse failed: {e}", style("[error]").red(), inp.id);
                        collect_inputs_ok = false;
                        break;
                    }
                };
                let outpoint = lwk_wollet::elements::OutPoint::new(txid, resolved.vout);
                pset_inputs.push(pset_builder::PsetInput::Covenant {
                    input_id: inp.id.clone(),
                    outpoint,
                    script_pubkey,
                    asset: asset_id,
                    amount: resolved.amount_sat,
                    issuance: iso_spec,
                    sequence: input_sequence,
                });
            }
        }

        // ---- Collect PSET outputs ----
        let mut pset_outputs: Vec<pset_builder::PsetOutputSpec> = Vec::new();
        // (output id, amount formula) for each pushed output, aligned with pset_outputs
        // by index, so amounts referencing the `fee` keyword can be re-evaluated once
        // the fee is estimated below (and the covenant state metadata kept in sync).
        let mut out_amount_formulas: Vec<(String, Option<serde_json::Value>)> = Vec::new();
        let mut collect_outputs_ok = true;
        // Tracks the next wallet receive-address index so each wallet output gets a unique address.
        // None on first use → wollet.address(None) picks the next confirmed-unused index, then we
        // increment for subsequent outputs.
        let mut next_wallet_addr_idx: Option<u32> = None;

        if collect_inputs_ok {
            for output in action.outputs.as_deref().unwrap_or_default() {
                let push_start = pset_outputs.len();
                let is_change = output.destination.as_str() == Some("change");
                let dest_type = output.destination.get("type").and_then(|v| v.as_str());
                let is_op_return = matches!(dest_type, Some("op_return") | Some("burn"));
                let amount = match &output.amount_sat {
                    None => {
                        if output.optional.unwrap_or(false) || is_change { continue; }
                        if is_op_return { 0u64 } else {
                            anyhow::bail!("Output '{}' has no amount_sat and is not optional.", output.id);
                        }
                    }
                    Some(v) => match eval::eval_amount(v, &ctx) {
                        Ok(a) => a,
                        Err(e) => {
                            if output.optional.unwrap_or(false) {
                                println!("  {} Output '{}' amount_sat eval failed (optional — skipping): {e}", style("·").dim(), output.id);
                                continue;
                            }
                            println!("  {} Output '{}' amount_sat eval failed: {e}", style("[error]").red(), output.id);
                            collect_outputs_ok = false;
                            break;
                        }
                    },
                };

                if output.optional.unwrap_or(false) && amount == 0 {
                    println!("  {} Output '{}' amount=0, optional — skipping.", style("·").dim(), output.id);
                    continue;
                }

                let asset_label = match output.asset.as_ref() {
                    None => "lbtc".to_string(),
                    Some(v) => match eval::eval_asset_label(v, &ctx) {
                        Ok(a) => a,
                        Err(e) => {
                            if output.optional.unwrap_or(false) {
                                println!("  {} Output '{}' asset eval failed (optional — skipping): {e}", style("·").dim(), output.id);
                                continue;
                            }
                            println!("  {} Output '{}' asset eval failed: {e}", style("[error]").red(), output.id);
                            collect_outputs_ok = false;
                            break;
                        }
                    },
                };

                let asset_id = match resolve_asset_id(&asset_label, net) {
                    Ok(id) => id,
                    Err(e) => {
                        if output.optional.unwrap_or(false) {
                            println!("  {} Output '{}' asset ID failed (optional — skipping): {e}", style("·").dim(), output.id);
                            continue;
                        }
                        println!("  {} Output '{}' asset ID failed: {e}", style("[error]").red(), output.id);
                        collect_outputs_ok = false;
                        break;
                    }
                };

                match &output.destination {
                    serde_json::Value::String(dest) if dest == "change" => {
                        println!("  {} Output '{}' → change (auto).", style("·").dim(), output.id);
                        continue;
                    }
                    serde_json::Value::Object(m)
                        if m.get("type").and_then(|v| v.as_str()) == Some("fee") => { continue; }
                    serde_json::Value::Object(m)
                        if matches!(m.get("type").and_then(|v| v.as_str()), Some("op_return") | Some("burn")) =>
                    {
                        let script_pubkey = lwk_wollet::elements::Script::from(vec![0x6au8]); // OP_RETURN
                        println!(
                            "  {} Output '{}': {} sat {} → OP_RETURN",
                            style("+").green(), output.id, style(amount).yellow(), asset_label
                        );
                        pset_outputs.push(pset_builder::PsetOutputSpec {
                            script_pubkey, amount, asset: asset_id, blinding_key: None,
                        });
                    }
                    serde_json::Value::Object(m) if m.contains_key("utxo_type") => {
                        let type_name = match m["utxo_type"].as_str() {
                            Some(s) => s,
                            None => {
                                println!("  {} Output '{}' utxo_type is not a string — skipping.", style("[TODO]").yellow(), output.id);
                                continue;
                            }
                        };
                        let ut = match manifest.utxo_type(type_name) {
                            Ok(ut) => ut,
                            Err(e) => {
                                println!("  {} Output '{}' utxo_type error: {e}", style("[error]").red(), output.id);
                                collect_outputs_ok = false;
                                break;
                            }
                        };
                        let confidential = ut.confidential;
                        let leaf_payloads = match ut.resolve_extra_leaf_payloads() {
                            Ok(p) => p,
                            Err(e) => {
                                println!("  {} Output '{}' extra leaves error: {e}", style("[warn]").yellow(), output.id);
                                collect_outputs_ok = false;
                                break;
                            }
                        };
                        let out_simf_path = ut.script.as_ref()
                            .and_then(|s| s.source.as_deref())
                            .map(|src| manifest_file.parent().unwrap_or(std::path::Path::new(".")).join(src))
                            .unwrap_or_else(|| simf_path.clone());
                        let (out_params, out_hints) = apply_utxo_compile_params(&compile_params_map, &compile_param_type_hints, ut);
                        // Per-output `destination.compile_params` overrides (resolved against
                        // action params/args), so a covenant can be keyed by a runtime value.
                        let (out_params, out_hints) = apply_site_compile_param_overrides(
                            out_params, out_hints, m.get("compile_params"),
                            action, &compile_param_type_hints, &ctx,
                        );
                        let script_pubkey = match pset_builder::covenant_script_pubkey(&out_simf_path, &out_params, &out_hints, &leaf_payloads, net) {
                            Ok(s) => s,
                            Err(e) => {
                                println!("  {} Covenant address failed (output '{}'):", style("[error]").red(), output.id);
                                for (i, cause) in e.chain().enumerate() {
                                    println!("    {i}: {cause}");
                                }
                                collect_outputs_ok = false;
                                break;
                            }
                        };
                        let blinding_key = if confidential {
                            // Derive a blinding key from the covenant script pubkey bytes so the
                            // output is confidential but deterministically re-derivable by the spender.
                            println!("  {} Output '{}' utxo_type '{}' has confidential=true but confidential covenant outputs are not yet supported — using explicit.", style("[warn]").yellow(), output.id, type_name);
                            None
                        } else {
                            None
                        };
                        let conf_label = if confidential { "confidential" } else { "explicit" };
                        println!(
                            "  {} Output '{}': {} sat {} → covenant ({}, {})",
                            style("+").green(), output.id, style(amount).yellow(), asset_label, type_name, conf_label
                        );
                        covenant_output_meta.push(CovenantOutputMeta {
                            utxo_type: type_name.to_string(),
                            output_id: output.id.clone(),
                            script_pubkey: script_pubkey.clone(),
                            amount_sat: amount,
                            asset: asset_id,
                        });
                        pset_outputs.push(pset_builder::PsetOutputSpec {
                            script_pubkey, amount, asset: asset_id, blinding_key,
                        });
                    }
                    serde_json::Value::String(dest) if dest == "wallet" => {
                        let addr_result = match wollet.address(next_wallet_addr_idx) {
                            Ok(a) => a,
                            Err(e) => {
                                println!("  {} Output '{}' wallet address failed: {e}", style("[warn]").yellow(), output.id);
                                continue;
                            }
                        };
                        next_wallet_addr_idx = Some(addr_result.index() + 1);
                        let addr = addr_result.address().clone();
                        // Resolution order: per-output → file-level default → chain default.
                        // Bitcoin does not support confidential outputs; Liquid defaults to confidential.
                        let chain_default = matches!(net, ElementsNetwork::Liquid | ElementsNetwork::LiquidTestnet);
                        let is_confidential = output.confidential
                            .or(manifest.confidential_outputs)
                            .unwrap_or(chain_default);
                        let bpk = if is_confidential {
                            addr.blinding_pubkey.map(|pk| lwk_wollet::elements::bitcoin::PublicKey { inner: pk, compressed: true })
                        } else {
                            None
                        };
                        let addr_str = addr.to_string();
                        println!(
                            "  {} Output '{}': {} sat {} → wallet ({}…)",
                            style("+").green(), output.id, style(amount).yellow(), asset_label,
                            &addr_str[..addr_str.len().min(24)]
                        );
                        pset_outputs.push(pset_builder::PsetOutputSpec {
                            script_pubkey: addr.script_pubkey(), amount, asset: asset_id, blinding_key: bpk,
                        });
                    }
                    serde_json::Value::String(dest) => {
                        let addr_str = eval::eval_destination_str(dest, &ctx)
                            .unwrap_or_else(|| dest.clone());
                        let addr = match addr_str.trim().parse::<lwk_wollet::elements::Address>() {
                            Ok(a) => a,
                            Err(e) => {
                                println!("  {} Output '{}' address parse failed ('{}': {e})", style("[warn]").yellow(), output.id, addr_str);
                                continue;
                            }
                        };
                        let bpk = addr.blinding_pubkey.map(|pk| lwk_wollet::elements::bitcoin::PublicKey { inner: pk, compressed: true });
                        println!(
                            "  {} Output '{}': {} sat {} → {}…",
                            style("+").green(), output.id, style(amount).yellow(), asset_label,
                            &addr_str[..addr_str.len().min(24)]
                        );
                        pset_outputs.push(pset_builder::PsetOutputSpec {
                            script_pubkey: addr.script_pubkey(), amount, asset: asset_id, blinding_key: bpk,
                        });
                    }
                    serde_json::Value::Object(m) if m.contains_key("script_hash") => {
                        let hash_ref = m["script_hash"].as_str().unwrap_or("");
                        let resolved = eval::eval_destination_str(hash_ref, &ctx)
                            .unwrap_or_else(|| hash_ref.to_string());
                        let clean = resolved.trim().trim_start_matches("0x");
                        if clean.len() != 64 {
                            println!("  {} Output '{}' script_hash must be 32 bytes hex (got {} chars)", style("[error]").red(), output.id, clean.len());
                            collect_outputs_ok = false;
                            break;
                        }
                        let mut bytes = [0u8; 32];
                        for i in 0..32 {
                            bytes[i] = match u8::from_str_radix(&clean[i*2..i*2+2], 16) {
                                Ok(b) => b,
                                Err(_) => {
                                    println!("  {} Output '{}' script_hash invalid hex", style("[error]").red(), output.id);
                                    collect_outputs_ok = false;
                                    break;
                                }
                            };
                        }
                        if !collect_outputs_ok { break; }
                        // P2TR: OP_1 OP_PUSHBYTES_32 <tweaked-x-only-key>
                        let mut script_bytes = Vec::with_capacity(34);
                        script_bytes.push(0x51u8); // OP_1
                        script_bytes.push(0x20u8); // OP_PUSHBYTES_32
                        script_bytes.extend_from_slice(&bytes);
                        let script_pubkey = lwk_wollet::elements::Script::from(script_bytes);
                        println!(
                            "  {} Output '{}': {} sat {} → P2TR ({}…)",
                            style("+").green(), output.id, style(amount).yellow(), asset_label,
                            &clean[..16]
                        );
                        pset_outputs.push(pset_builder::PsetOutputSpec {
                            script_pubkey, amount, asset: asset_id, blinding_key: None,
                        });
                    }
                    other => {
                        println!("  {} Output '{}' unsupported destination: {}", style("[TODO]").yellow(), output.id, other);
                        continue;
                    }
                }
                // Record this output's amount formula so it can be re-evaluated once
                // the `fee` keyword is resolved (each iteration pushes at most one output).
                if pset_outputs.len() > push_start {
                    out_amount_formulas.push((output.id.clone(), output.amount_sat.clone()));
                }
            }
        }

        // ---- Build PSET ----
        if collect_inputs_ok && collect_outputs_ok {
            // Only build a change output if the action declared one. Otherwise the
            // fee absorbs the surplus and the output count stays exact (recursive covenants).
            let build_change = action.outputs.as_deref().unwrap_or_default().iter()
                .any(|o| o.destination.as_str() == Some("change"));
            let mut req = pset_builder::BuildPsetRequest {
                inputs: pset_inputs,
                outputs: pset_outputs,
                fee_rate: fee_rate as f32,
                policy_asset: net.policy_asset(),
                build_change,
            };

            // Resolve the `fee` keyword: estimate the fee from the current (fee=0)
            // draft, then re-evaluate any output amount that referenced `fee`. The
            // amounts don't affect the tx vsize, so the draft gives the right size.
            if out_amount_formulas.iter().filter_map(|(_, f)| f.as_ref()).any(amount_uses_fee_keyword) {
                match pset_builder::estimate_fee(wollet, net, &req) {
                    Ok(est) => {
                        ctx.set_fee(est);
                        println!("  {} Estimated network fee: {} sat (resolves `fee`)", style("✓").green(), est);
                        for (i, (out_id, formula)) in out_amount_formulas.iter().enumerate() {
                            let Some(f) = formula else { continue };
                            if !amount_uses_fee_keyword(f) { continue; }
                            match eval::eval_amount(f, &ctx) {
                                Ok(a) if i < req.outputs.len() => {
                                    req.outputs[i].amount = a;
                                    // Keep covenant state metadata in sync so the post-broadcast
                                    // matcher finds this output by its (fee-adjusted) amount.
                                    for meta in covenant_output_meta.iter_mut() {
                                        if meta.output_id == *out_id {
                                            meta.amount_sat = a;
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => println!("  {} Re-evaluating output #{i} with fee failed: {e}", style("[error]").red()),
                            }
                        }
                    }
                    Err(e) => println!("  {} Fee estimation failed (`fee` stays 0): {e}", style("[warn]").yellow()),
                }
            }

            println!();
            println!("  {} Building PSET ({} inputs, {} outputs)…",
                style("·").dim(), req.inputs.len(), req.outputs.len());

            match pset_builder::build_pset(wollet, net, &req) {
                Err(e) => {
                    println!("  {} PSET build failed:", style("[error]").red());
                    for (i, cause) in e.chain().enumerate() {
                        println!("    {i}: {cause}");
                    }
                }
                Ok(result) => {
                    for iso in &result.issuances {
                        println!("    Issuance '{}': asset={}, token={}", iso.input_id,
                            style(&iso.asset_id.to_string()[..16]).yellow(),
                            style(&iso.token_id.to_string()[..16]).yellow());
                        ctx.set_input_attr(&iso.input_id, "asset", iso.asset_id.to_string());
                        ctx.set_input_attr(&iso.input_id, "reissuance_token", iso.token_id.to_string());
                        if let Some(entropy_bytes) = &iso.entropy {
                            let hex = entropy_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                            ctx.set_input_entropy(&iso.input_id, hex);
                        }
                    }
                    println!("  {} PSET constructed ({} outputs).", style("✓").green(), result.pset.outputs().len());
                    for (i, out) in result.pset.outputs().iter().enumerate() {
                        if out.script_pubkey.is_empty() {
                            if let Some(amt) = out.amount { println!("    Output #{i}: fee   {} sat", amt); }
                        } else {
                            let blinded = out.amount.is_none() && out.amount_comm.is_some();
                            let label = if blinded { "confidential" } else { "explicit" };
                            let spk_short: String = {
                                let h = hex_bytes(out.script_pubkey.as_bytes());
                                format!("{}…", &h[..h.len().min(16)])
                            };
                            println!("    Output #{i}: {label}  spk={spk_short}");
                        }
                    }
                    pset_opt = Some(result.pset);
                }
            }
        }
    } else {
        println!("  {} No wallet/network — cannot build PSET.", style("[warn]").yellow());
    }

    // ------------------------------------------------------------------
    // Step 8 — Sign
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 8: Sign"));

    if let Some(witnesses) = &action.witnesses {
        if let Some(obj) = witnesses.as_object() {
            for (name, def) in obj {
                let desc = def.get("description").and_then(|v| v.as_str()).unwrap_or("");
                println!("  {} Witness '{}': {}", style("[info]").dim(), style(name).bold(), desc);
            }
        }
    }

    let mut signed_pset: Option<lwk_wollet::elements::pset::PartiallySignedTransaction> = None;

    match (&mut pset_opt, &loaded_wallet) {
        (Some(pset), Some(w)) => {
            let signer = wallet::signer(w)?;
            match signer.sign(pset) {
                Err(e) => {
                    println!("  {} Sign failed: {e}", style("[error]").red());
                }
                Ok(_) => {
                    println!("  {} Transaction signed.", style("✓").green());
                    signed_pset = pset_opt.take();
                }
            }
        }
        (None, _) => {
            println!("  {} No PSET to sign (not built in Step 7).", style("[skip]").yellow());
        }
        (_, None) => {
            println!("  {} No wallet loaded — cannot sign.", style("[warn]").yellow());
        }
    }

    // ------------------------------------------------------------------
    // Step 9 — Dry-run
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 9: Dry-run"));
    {
        let covenant_inputs: Vec<_> = action.inputs.as_deref().unwrap_or_default()
            .iter()
            .filter(|i| i.utxo_type_name().is_some())
            .collect();

        if covenant_inputs.is_empty() {
            println!("  {} No Simplicity covenant inputs — dry-run skipped.", style("·").dim());
        } else {
            println!(
                "  {} {} covenant input(s) to verify.",
                style("·").dim(),
                covenant_inputs.len()
            );
            let mut all_compiled = true;
            for inp in &covenant_inputs {
                let type_name = inp.utxo_type_name().unwrap();
                let check_ut = manifest.utxo_type(&type_name).ok();
                let check_simf_path = check_ut.as_ref()
                    .and_then(|ut| ut.script.as_ref().and_then(|s| s.source.as_deref()).map(|src| {
                        manifest_file.parent().unwrap_or(std::path::Path::new(".")).join(src)
                    }))
                    .unwrap_or_else(|| simf_path.clone());
                let (check_params, check_hints) = check_ut
                    .map(|ut| apply_utxo_compile_params(&compile_params_map, &compile_param_type_hints, ut))
                    .unwrap_or_else(|| (compile_params_map.clone(), compile_param_type_hints.clone()));
                let (check_params, check_hints) = apply_site_compile_param_overrides(
                    check_params, check_hints, inp.utxo_source.get("compile_params"),
                    action, &compile_param_type_hints, &ctx,
                );
                print!(
                    "  {} Input '{}' ({}) — compiling… ",
                    style("·").dim(), inp.id, type_name
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
                match covenant::check_compile(&check_simf_path, &check_params, &check_hints) {
                    Ok(()) => println!("{}", style("OK").green()),
                    Err(e) => {
                        println!("{}", style("FAILED").red());
                        for (i, cause) in e.chain().enumerate() {
                            println!("    {i}: {cause}");
                        }
                        all_compiled = false;
                    }
                }
            }
            if all_compiled {
                // Execution dry-run — requires a signed PSET to have transaction context.
                if let Some(ref pset) = signed_pset {
                    match pset.extract_tx() {
                        Err(e) => {
                            println!("  {} extract_tx failed: {e}", style("[warn]").yellow());
                        }
                        Ok(tx) => {
                            use std::sync::Arc;
                            
                            let tx = Arc::new(tx);

                            let witness_utxos: Vec<Option<lwk_wollet::elements::TxOut>> = pset
                                .inputs()
                                .iter()
                                .map(|inp| inp.witness_utxo.clone())
                                .collect();

                            if witness_utxos.iter().any(|u| u.is_none()) {
                                println!(
                                    "  {} Some PSET inputs have no witness_utxo — execution dry-run skipped.",
                                    style("[warn]").yellow()
                                );
                            } else {
                                let utxos: Vec<lwk_wollet::elements::TxOut> =
                                    witness_utxos.into_iter().flatten().collect();
                                let genesis_hash = network_genesis_hash(net_for_hash);

                                let action_inputs = action.inputs.as_deref().unwrap_or_default();
                                let mut exec_all_ok = true;

                                for (pset_idx, action_inp) in action_inputs.iter().enumerate() {
                                    let Some(type_name) = action_inp.utxo_type_name() else {
                                        continue;
                                    };
                                    let dry_ut = match manifest.utxo_type(&type_name) {
                                        Ok(ut) => ut,
                                        Err(e) => {
                                            println!(
                                                "    {} utxo_type for '{}': {e}",
                                                style("[error]").red(), action_inp.id
                                            );
                                            exec_all_ok = false;
                                            continue;
                                        }
                                    };
                                    let leaf_payloads = match dry_ut.resolve_extra_leaf_payloads() {
                                        Ok(p) => p,
                                        Err(e) => {
                                            println!(
                                                "    {} leaf_payloads for '{}': {e}",
                                                style("[error]").red(), action_inp.id
                                            );
                                            exec_all_ok = false;
                                            continue;
                                        }
                                    };
                                    let dry_simf_path = dry_ut.script.as_ref()
                                        .and_then(|s| s.source.as_deref())
                                        .map(|src| manifest_file.parent().unwrap_or(std::path::Path::new(".")).join(src))
                                        .unwrap_or_else(|| simf_path.clone());
                                    let (dry_params, dry_hints) = apply_utxo_compile_params(&compile_params_map, &compile_param_type_hints, dry_ut);
                                    let (dry_params, dry_hints) = apply_site_compile_param_overrides(
                                        dry_params, dry_hints, action_inp.utxo_source.get("compile_params"),
                                        action, &compile_param_type_hints, &ctx,
                                    );

                                    use std::io::Write;
                                    print!(
                                        "    {} Input '{}' ({}) — executing… ",
                                        style("·").dim(), action_inp.id, type_name
                                    );
                                    let _ = std::io::stdout().flush();

                                    let dry_inp_witnesses = action_inp.witnesses.clone();
                                    let dry_params_snap = compile_params_map.clone();
                                    let dry_action_params_snap = action_params_map.clone();
                                    let dry_wallet_snap = loaded_wallet.clone();
                                    let dry_signer_fn = move |name: &str, _sig_type: &str, hash: &[u8; 32]| -> anyhow::Result<[u8; 64]> {
                                        let w = dry_wallet_snap.as_ref()
                                            .ok_or_else(|| anyhow::anyhow!("No wallet loaded — cannot sign witness '{name}'"))?;
                                        let key_ref = dry_inp_witnesses.as_ref()
                                            .and_then(|wits| wits.get(name))
                                            .and_then(|spec| spec.get("source"))
                                            .and_then(|src| src.get("key"))
                                            .and_then(|k| k.as_str())
                                            .ok_or_else(|| anyhow::anyhow!("No signing key specified for witness '{name}'"))?;
                                        let resolved = resolve_witness_signing_key(
                                            key_ref, &dry_action_params_snap, &dry_params_snap,
                                        );
                                        wallet::sign_schnorr_for_pubkey(w, resolved, hash)
                                    };
                                    match covenant::dry_run_covenant(
                                        &dry_simf_path,
                                        &dry_params,
                                        &dry_hints,
                                        &leaf_payloads,
                                        action_inp.witnesses.as_ref(),
                                        Some(&dry_signer_fn),
                                        Arc::clone(&tx),
                                        &utxos,
                                        pset_idx as u32,
                                        genesis_hash,
                                        debug_jets,
                                    ) {
                                        Ok(()) => println!("{}", style("OK").green()),
                                        Err(e) => {
                                            println!("{}", style("FAILED").red());
                                            for (i, cause) in e.chain().enumerate() {
                                                println!("      {i}: {cause}");
                                            }
                                            exec_all_ok = false;
                                        }
                                    }
                                }

                                if exec_all_ok {
                                    println!(
                                        "  {} Compilation and execution dry-run passed.",
                                        style("✓").green()
                                    );
                                } else {
                                    println!(
                                        "  {} One or more execution dry-runs failed.",
                                        style("[error]").red()
                                    );
                                }
                            }
                        }
                    }
                } else {
                    println!(
                        "  {} Compilation OK. (No signed PSET — execution dry-run skipped.)",
                        style("✓").green()
                    );
                }
            } else {
                println!(
                    "  {} One or more covenant programs failed to compile — check compile_params.",
                    style("[error]").red()
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 9c — Finalize Simplicity covenant inputs
    // ------------------------------------------------------------------
    // Set final_script_witness on every covenant PSET input so that wollet.finalize()
    // only needs to handle wallet inputs.  Must run after a successful dry-run (Step 9).
    {
        let covenant_input_count = action.inputs.as_deref().unwrap_or_default()
            .iter()
            .filter(|i| i.utxo_type_name().is_some())
            .count();

        if covenant_input_count > 0 {
            println!();
            println!("{}", step_header("Step 9c: Covenant Finalization"));

            if let Some(ref mut pset) = signed_pset {
                let witness_utxos: Vec<Option<lwk_wollet::elements::TxOut>> = pset.inputs().iter()
                    .map(|inp| inp.witness_utxo.clone())
                    .collect();

                if witness_utxos.iter().any(|u| u.is_none()) {
                    println!(
                        "  {} Some inputs missing witness_utxo — finalization skipped.",
                        style("[warn]").yellow()
                    );
                } else {
                    let utxos: Vec<lwk_wollet::elements::TxOut> =
                        witness_utxos.into_iter().flatten().collect();

                    match pset.extract_tx() {
                        Err(e) => println!(
                            "  {} extract_tx for finalization failed: {e}",
                            style("[warn]").yellow()
                        ),
                        Ok(tx) => {
                            use std::sync::Arc;
                            
                            let tx = Arc::new(tx);
                            let genesis_hash = network_genesis_hash(net_for_hash);
                            let action_inputs = action.inputs.as_deref().unwrap_or_default();
                            let mut all_finalized = true;

                            for (pset_idx, action_inp) in action_inputs.iter().enumerate() {
                                let Some(type_name) = action_inp.utxo_type_name() else { continue };

                                let fin_ut = match manifest.utxo_type(&type_name) {
                                    Ok(ut) => ut,
                                    Err(e) => {
                                        println!(
                                            "  {} utxo_type '{}': {e}",
                                            style("[error]").red(), type_name
                                        );
                                        all_finalized = false;
                                        continue;
                                    }
                                };
                                let leaf_payloads = match fin_ut.resolve_extra_leaf_payloads() {
                                    Ok(p) => p,
                                    Err(e) => {
                                        println!(
                                            "  {} leaf_payloads for '{}': {e}",
                                            style("[error]").red(), action_inp.id
                                        );
                                        all_finalized = false;
                                        continue;
                                    }
                                };
                                let fin_simf_path = fin_ut.script.as_ref()
                                    .and_then(|s| s.source.as_deref())
                                    .map(|src| {
                                        manifest_file.parent()
                                            .unwrap_or(std::path::Path::new("."))
                                            .join(src)
                                    })
                                    .unwrap_or_else(|| simf_path.clone());
                                let (fin_params, fin_hints) = apply_utxo_compile_params(
                                    &compile_params_map, &compile_param_type_hints, fin_ut,
                                );
                                let (fin_params, fin_hints) = apply_site_compile_param_overrides(
                                    fin_params, fin_hints, action_inp.utxo_source.get("compile_params"),
                                    action, &compile_param_type_hints, &ctx,
                                );

                                print!(
                                    "  {} Input '{}' ({}) — finalizing… ",
                                    style("·").dim(), action_inp.id, type_name
                                );
                                use std::io::Write as _;
                                let _ = std::io::stdout().flush();

                                // Build a signer closure for any "type": "Signature" witnesses.
                                // Resolves the key reference from compile_params, then signs
                                // the hash with the wallet key.
                                let inp_witnesses = action_inp.witnesses.clone();
                                let params_snap = compile_params_map.clone();
                                let action_params_snap = action_params_map.clone();
                                let wallet_snap = loaded_wallet.clone();
                                let signer_fn = move |name: &str, _sig_type: &str, hash: &[u8; 32]| -> anyhow::Result<[u8; 64]> {
                                    let w = wallet_snap.as_ref()
                                        .ok_or_else(|| anyhow::anyhow!("No wallet loaded — cannot sign witness '{name}'"))?;
                                    let key_ref = inp_witnesses.as_ref()
                                        .and_then(|wits| wits.get(name))
                                        .and_then(|spec| spec.get("source"))
                                        .and_then(|src| src.get("key"))
                                        .and_then(|k| k.as_str())
                                        .ok_or_else(|| anyhow::anyhow!("No signing key specified for witness '{name}'"))?;
                                    let resolved = resolve_witness_signing_key(
                                        key_ref, &action_params_snap, &params_snap,
                                    );
                                    wallet::sign_schnorr_for_pubkey(w, resolved, hash)
                                };

                                match covenant::finalize_covenant_input(
                                    &fin_simf_path,
                                    &fin_params,
                                    &fin_hints,
                                    &leaf_payloads,
                                    action_inp.witnesses.as_ref(),
                                    Some(&signer_fn),
                                    Arc::clone(&tx),
                                    &utxos,
                                    pset_idx as u32,
                                    genesis_hash,
                                    &mut pset.inputs_mut()[pset_idx],
                                ) {
                                    Ok(()) => println!("{}", style("OK").green()),
                                    Err(e) => {
                                        println!("{}", style("FAILED").red());
                                        for (i, cause) in e.chain().enumerate() {
                                            println!("      {i}: {cause}");
                                        }
                                        all_finalized = false;
                                    }
                                }
                            }

                            if all_finalized {
                                println!(
                                    "  {} All covenant inputs finalized.",
                                    style("✓").green()
                                );
                            } else {
                                println!(
                                    "  {} One or more covenant inputs failed to finalize.",
                                    style("[error]").red()
                                );
                            }
                        }
                    }
                }
            } else {
                println!(
                    "  {} No signed PSET — finalization skipped.",
                    style("[skip]").yellow()
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 9b — Create instance file (before broadcast)
    // ------------------------------------------------------------------
    // Build combined type hints: compile params + action params, so tapleaf
    // computes inside create_instance can infer types for things like
    // BORROWER_PUB_KEY (pubkey), PRINCIPAL_INTEREST_RATE (u16), etc.
    let create_instance_hints: std::collections::HashMap<String, String> = {
        let mut hints = compile_param_type_hints.clone();
        if let Some(params) = &action.params {
            for (name, def) in params {
                hints.entry(name.clone()).or_insert_with(|| def.type_.clone());
            }
        }
        hints
    };

    if action.deploy || action.is_constructor {
        println!();
        println!("{}", step_header("Step 9b: Creating Instance"));
        if let Some(ci) = &action.create_instance {
            let fields = eval_create_instance_fields(
                ci, &ctx, manifest_file, &create_instance_hints, net_for_hash, true,
            );
            let inst = crate::instance::InstanceFile {
                instance: Some(crate::instance::InstanceData {
                    class: ci.class.clone(),
                    fields: fields.into_iter().collect(),
                }),
                instance_params: std::collections::HashMap::new(),
                provided_inputs: std::collections::HashMap::new(),
            };
            match inst.write(effective_instance_out) {
                Ok(()) => println!(
                    "  {} Instance written: {}",
                    style("✓").green(),
                    effective_instance_out.display()
                ),
                Err(e) => println!(
                    "  {} Could not write instance file: {e}",
                    style("[warn]").yellow()
                ),
            }
        } else {
            // Legacy: write flat instance_params
            let inst = InstanceFile {
                instance: None,
                instance_params: ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                provided_inputs: std::collections::HashMap::new(),
            };
            match inst.write(effective_instance_out) {
                Ok(()) => println!(
                    "  {} Instance written: {}",
                    style("✓").green(),
                    effective_instance_out.display()
                ),
                Err(e) => println!(
                    "  {} Could not write instance file: {e}",
                    style("[warn]").yellow()
                ),
            }
        }
    }

    // ------------------------------------------------------------------
    // Ready to broadcast (or export)
    // ------------------------------------------------------------------
    println!();

    if signed_pset.is_none() {
        println!(
            "  {} No signed PSET available — cannot broadcast.",
            style("[warn]").yellow()
        );
        println!("    Complete Steps 7 and 8 first (requires an action with concrete address outputs).");
        println!();
        return Ok(());
    }

    // --export-pset: write PSET (base64) + tx (hex) to separate files, skip broadcast.
    if let (Some(export_path), Some(mut pset), Some(wollet)) = (export_pset_path, signed_pset.clone(), &wollet_opt) {
        println!("{}", style("=== Exporting PSET (no broadcast) ===").bold().cyan());

        // Derive tx path: replace/add .tx.hex extension alongside the pset file.
        let tx_path = {
            let stem = export_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("export");
            let parent = export_path.parent().unwrap_or(std::path::Path::new("."));
            parent.join(format!("{stem}.tx.hex"))
        };

        let pset_bytes = lwk_wollet::elements::encode::serialize(&pset);
        use base64::Engine as _;
        let pset_b64 = base64::engine::general_purpose::STANDARD.encode(&pset_bytes);
        match std::fs::write(export_path, &pset_b64) {
            Ok(()) => println!("  {} PSET (base64): {}", style("✓").green(), export_path.display()),
            Err(e) => println!("  {} PSET write failed: {e}", style("[error]").red()),
        }

        match wollet.finalize(&mut pset) {
            Ok(tx) => {
                let tx_hex = hex_bytes(&lwk_wollet::elements::encode::serialize(&tx));
                match std::fs::write(&tx_path, &tx_hex) {
                    Ok(()) => println!("  {} TX  (hex):    {}", style("✓").green(), tx_path.display()),
                    Err(e) => println!("  {} TX write failed: {e}", style("[error]").red()),
                }
            }
            Err(e) => println!("  {} Finalize failed: {e}", style("[warn]").yellow()),
        }
        println!("  Decode PSET with: elements-cli decodepsbt <base64>");
        println!();

        // Fall through to write run output JSON then return.
        let run_output = RunOutput {
            protocol: &manifest.protocol,
            action: action_name,
            compile_params: ctx.all_compile_params(),
            params: ctx.all_params(),
            args: ctx.all_args(),
            inputs: ctx.all_inputs().map(|i| RunOutputInput {
                id: i.id.clone(),
                txid: i.txid.clone(),
                vout: i.vout,
                amount_sat: i.amount_sat,
                asset: i.asset.clone(),
                issuance_entropy: i.issuance_entropy.clone(),
            }).collect(),
            fee_rate_sat_per_vb: fee_rate,
            txid: None,
        };
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let safe_action = action_name.replace(['/', '\\', ' '], "_");
        let run_file = data_dir.join(format!("run_{safe_action}_{epoch}.json"));
        if let Ok(json) = serde_json::to_string_pretty(&run_output) {
            match std::fs::write(&run_file, json) {
                Ok(()) => println!("  {} Run output: {}", style("✓").green(), run_file.display()),
                Err(e) => println!("  {} Could not write run output: {e}", style("[warn]").yellow()),
            }
        }
        return Ok(());
    }

    println!("{}", style("=== Ready to broadcast ===").bold().cyan());

    let confirmed = prompt::confirm_broadcast()?;

    if confirmed {
        if let (Some(mut pset), Some(_w), Some(_wollet)) = (signed_pset, &loaded_wallet, &wollet_opt) {
            // Save signed PSET (hex) before finalization for external inspection.
            let safe_action_name = action_name.replace(['/', '\\', ' '], "_");
            std::fs::create_dir_all(data_dir).ok();
            let pset_bytes = lwk_wollet::elements::encode::serialize(&pset);
            let pset_file = data_dir.join(format!("pset_{safe_action_name}.hex"));
            match std::fs::write(&pset_file, hex_bytes(&pset_bytes)) {
                Ok(()) => println!("  {} PSET saved: {}", style("·").dim(), pset_file.display()),
                Err(e) => println!("  {} Could not save PSET: {e}", style("[warn]").yellow()),
            }

            // Finalize wallet inputs only — covenant inputs are already finalized (Step 9c set
            // final_script_witness on them). elements_miniscript::psbt::finalize() iterates every
            // input and does NOT skip pre-finalized ones, so calling wollet.finalize() on the full
            // PSET fails with "Cannot satisfy Tr descriptor" for Simplicity covenant P2TR inputs.
            //
            // The wallet descriptor is P2WPKH, so wallet inputs carry ECDSA partial_sigs after
            // signing. Manually build final_script_witness = [sig, pubkey] for those inputs.
            let finalized_tx = {
                let mut wallet_finalize_ok = true;
                for i in 0..pset.inputs().len() {
                    if pset.inputs()[i].final_script_witness.is_some() {
                        continue; // already finalized (Simplicity covenant)
                    }
                    // P2WPKH wallet input: partial_sigs has exactly one entry after signing.
                    let partial: Vec<_> = pset.inputs()[i].partial_sigs.iter()
                        .map(|(pk, sig)| (pk.to_bytes(), sig.clone()))
                        .collect();
                    if partial.is_empty() {
                        println!(
                            "  {} Wallet input {i} has no signature — was signing skipped?",
                            style("[error]").red()
                        );
                        wallet_finalize_ok = false;
                        continue;
                    }
                    let (pubkey_bytes, sig_bytes) = &partial[0];
                    pset.inputs_mut()[i].final_script_witness =
                        Some(vec![sig_bytes.clone(), pubkey_bytes.clone()]);
                }
                if wallet_finalize_ok {
                    match pset.extract_tx() {
                        Ok(tx) => Some(tx),
                        Err(e) => {
                            println!("  {} extract_tx failed: {e}", style("[error]").red());
                            None
                        }
                    }
                } else {
                    None
                }
            };
            match finalized_tx {
                None => {}
                Some(tx) => {
                    let tx_bytes = lwk_wollet::elements::encode::serialize(&tx);
                    let tx_hex = hex_bytes(&tx_bytes);
                    // Save finalized TX hex for external inspection / manual broadcast.
                    let tx_file = data_dir.join(format!("tx_{safe_action_name}.hex"));
                    match std::fs::write(&tx_file, &tx_hex) {
                        Ok(()) => println!("  {} TX saved:   {}", style("·").dim(), tx_file.display()),
                        Err(e) => println!("  {} Could not save TX: {e}", style("[warn]").yellow()),
                    }
                    println!(
                        "  {} Finalized tx: {} input(s), {} output(s), {} bytes",
                        style("·").dim(),
                        tx.input.len(),
                        tx.output.len(),
                        tx_bytes.len(),
                    );
                    for (i, inp) in tx.input.iter().enumerate() {
                        println!(
                            "    input  #{i}: {}:{}",
                            inp.previous_output.txid, inp.previous_output.vout
                        );
                    }
                    for (i, out) in tx.output.iter().enumerate() {
                        let val_desc = match &out.value {
                            lwk_wollet::elements::confidential::Value::Explicit(v) => format!("{v} sat explicit"),
                            lwk_wollet::elements::confidential::Value::Confidential(_) => "confidential".to_string(),
                            lwk_wollet::elements::confidential::Value::Null => "null".to_string(),
                        };
                        println!("    output #{i}: {val_desc}  spk_len={}", out.script_pubkey.len());
                    }
                    if tx_hex.len() <= 512 {
                        println!("  {} TX hex: {}", style("·").dim(), tx_hex);
                    } else {
                        println!(
                            "  {} TX hex ({} chars total): {}…",
                            style("·").dim(),
                            tx_hex.len(),
                            &tx_hex[..128]
                        );
                    }
                    let cfg = config::load();
                    match broadcast_finalized_tx(&cfg, &tx, &tx_hex, net_for_hash) {
                        Ok(txid) => {
                                broadcast_txid = Some(txid.clone());
                                println!(
                                    "  {} txid: {}",
                                    style("Broadcast").green().bold(),
                                    style(&txid).yellow()
                                );
                                println!("  Run `sync` after confirmation to update wallet state.");

                                // --- Method-level on_post_broadcast hook ---
                                if let Some(hook) = &action.on_post_broadcast {
                                    ctx.set_param("broadcast_txid", &txid);
                                    run_hook_block(hook, &mut ctx, "[on_post_broadcast]");
                                }

                                // --- Update and write state file ---
                                let mut new_state = contract_state.take()
                                    .unwrap_or_else(|| ContractState::new(action_name));
                                new_state.last_action = action_name.to_string();
                                // Record which instance file this contract belongs to: the
                                // just-written output for constructors, else the loaded input.
                                let recorded_instance = if action.is_constructor || action.deploy {
                                    Some(effective_instance_out)
                                } else {
                                    instance_in_path
                                };
                                new_state.instance =
                                    recorded_instance.map(|p| p.display().to_string());
                                // Remove spent covenant inputs.
                                for inp in action.inputs.as_deref().unwrap_or_default() {
                                    if inp.utxo_type_name().is_some() {
                                        if let Some(r) = ctx.get_input(&inp.id) {
                                            new_state.remove_spent(&r.txid, r.vout);
                                        }
                                    }
                                }
                                // Add new covenant outputs by matching script_pubkeys in the tx.
                                // First, drop any existing UTXOs of the types being produced —
                                // this action supersedes them.
                                for meta in &covenant_output_meta {
                                    new_state.utxos.retain(|u| u.utxo_type != meta.utxo_type);
                                }
                                // Match each meta entry to the correct output vout.
                                // Multiple outputs can share the same script_pubkey (e.g. four
                                // prelock_script_auth outputs for four different NFTs), so we
                                // also match on asset and amount, and consume each position at
                                // most once to avoid duplicates.
                                let mut used_vouts: std::collections::HashSet<usize> =
                                    std::collections::HashSet::new();
                                for meta in &covenant_output_meta {
                                    let found = tx.output.iter().enumerate().find(|(i, o)| {
                                        if used_vouts.contains(i) {
                                            return false;
                                        }
                                        if o.script_pubkey != meta.script_pubkey {
                                            return false;
                                        }
                                        let asset_ok = matches!(
                                            &o.asset,
                                            lwk_wollet::elements::confidential::Asset::Explicit(a)
                                                if *a == meta.asset
                                        );
                                        let value_ok = matches!(
                                            &o.value,
                                            lwk_wollet::elements::confidential::Value::Explicit(v)
                                                if *v == meta.amount_sat
                                        );
                                        asset_ok && value_ok
                                    });
                                    if let Some((vout, _)) = found {
                                        used_vouts.insert(vout);
                                        new_state.utxos.push(StateUtxo {
                                            utxo_type: meta.utxo_type.clone(),
                                            utxo_id: meta.output_id.clone(),
                                            txid: txid.clone(),
                                            vout: vout as u32,
                                            amount_sat: meta.amount_sat,
                                            asset: meta.asset.to_string(),
                                        });
                                    }
                                }
                                match new_state.write(effective_state_out) {
                                    Ok(()) => {
                                        println!(
                                            "  {} State written:    {}",
                                            style("✓").green(),
                                            effective_state_out.display()
                                        );
                                        let hist_path = history_path(effective_state_out);
                                        let entry = HistoryEntry {
                                            action: action_name.to_string(),
                                            txid: txid.clone(),
                                            utxos: new_state.utxos.clone(),
                                        };
                                        match StateHistory::load(&hist_path)
                                            .and_then(|mut h| h.append(entry, &hist_path))
                                        {
                                            Ok(()) => println!(
                                                "  {} History appended: {}",
                                                style("✓").green(),
                                                hist_path.display()
                                            ),
                                            Err(e) => println!(
                                                "  {} Could not write history file: {e}",
                                                style("[warn]").yellow()
                                            ),
                                        }
                                    }
                                    Err(e) => println!(
                                        "  {} Could not write state file: {e}",
                                        style("[warn]").yellow()
                                    ),
                                }
                        }
                        Err(msg) => {
                            println!("  {} Broadcast failed: {msg}", style("[error]").red());
                        }
                    }
                }
            }
        }
    } else {
        println!("  Broadcast cancelled by user.");
    }

    // ------------------------------------------------------------------
    // Write run output JSON to wallet data dir
    // ------------------------------------------------------------------
    let run_output = RunOutput {
        protocol: &manifest.protocol,
        action: action_name,
        compile_params: ctx.all_compile_params(),
        params: ctx.all_params(),
        args: ctx.all_args(),
        inputs: ctx.all_inputs().map(|i| RunOutputInput {
            id: i.id.clone(),
            txid: i.txid.clone(),
            vout: i.vout,
            amount_sat: i.amount_sat,
            asset: i.asset.clone(),
            issuance_entropy: i.issuance_entropy.clone(),
        }).collect(),
        fee_rate_sat_per_vb: fee_rate,
        txid: broadcast_txid,
    };
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let safe_action = action_name.replace(['/', '\\', ' '], "_");
    std::fs::create_dir_all(data_dir).ok();
    let run_file = data_dir.join(format!("run_{}_{epoch}.json", safe_action));
    match serde_json::to_string_pretty(&run_output) {
        Ok(json) => match std::fs::write(&run_file, json) {
            Ok(()) => println!("  {} Run saved: {}", style("✓").green(), run_file.display()),
            Err(e) => println!("  {} Could not write run file: {e}", style("[warn]").yellow()),
        },
        Err(e) => println!("  {} Could not serialize run output: {e}", style("[warn]").yellow()),
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the genesis block hash for the given Elements network.
/// This is required for correct Simplicity `sig_all_hash` computation — the hash
/// is used as a BIP-340 style tag, so signing and on-chain verification must agree.
fn network_genesis_hash(network: ElementsNetwork) -> lwk_wollet::elements::BlockHash {
    use lwk_wollet::elements::hashes::Hash as _;
    use lwk_wollet::elements::BlockHash;
    use std::str::FromStr;
    match network {
        // Liquid mainnet genesis: 1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003
        ElementsNetwork::Liquid => BlockHash::from_str(
            "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003",
        )
        .expect("hardcoded Liquid genesis hash is valid"),
        // Liquid Testnet genesis: a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1
        ElementsNetwork::LiquidTestnet => BlockHash::from_str(
            "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1",
        )
        .expect("hardcoded Liquid Testnet genesis hash is valid"),
        // Regtest has no fixed genesis hash; fall back to all-zero bytes (used in tests only)
        ElementsNetwork::ElementsRegtest { .. } => BlockHash::all_zeros(),
    }
}

fn resolve_asset_id(
    label: &str,
    network: ElementsNetwork,
) -> Result<lwk_wollet::elements::AssetId> {
    match label {
        "lbtc" | "bitcoin" => Ok(network.policy_asset()),
        other => lwk_wollet::elements::AssetId::from_str(other)
            .with_context(|| format!("Cannot parse asset ID '{other}'")),
    }
}

fn select_input(
    input: &Input,
    available: &[lwk_wollet::WalletTxOut],
    available_explicit: &[lwk_wollet::ExternalUtxo],
    claimed: &mut std::collections::HashSet<String>,
    manual_inputs: bool,
    network: Option<ElementsNetwork>,
    ctx: &ExecutionContext,
) -> Result<ResolvedInput> {
    if !input.is_wallet_source() {
        return prompt::prompt_input_selection(input);
    }

    if manual_inputs {
        return prompt::prompt_input_selection(input);
    }

    let required_asset: Option<lwk_wollet::elements::AssetId> = input
        .asset
        .as_ref()
        .and_then(|v| v.as_str())
        .map(|s| {
            if let Some(k) = s
                .strip_prefix("instance.")
                .or_else(|| s.strip_prefix("compile_params."))
            {
                ctx.get_compile_param(k).unwrap_or(s)
            } else if let Some(k) = s.strip_prefix("params.") {
                ctx.get_param(k).unwrap_or(s)
            } else {
                s
            }
        })
        .and_then(|s| match s {
            "lbtc" | "bitcoin" => network.map(|n| n.policy_asset()),
            other => other.parse().ok(),
        });

    // Parse amount constraint from amount_sat, which may be:
    //   - a plain number / string expr → exact match required
    //   - { "min_amount": <expr> }     → accept any UTXO with value >= min_amount
    // Surplus non-LBTC value is returned as change by the pset_builder.
    let resolve_amount_str = |s: &str| -> Option<u64> {
        let resolved = if let Some(k) = s
            .strip_prefix("instance.")
            .or_else(|| s.strip_prefix("compile_params."))
        {
            ctx.get_compile_param(k).unwrap_or(s)
        } else if let Some(k) = s.strip_prefix("params.") {
            ctx.get_param(k).unwrap_or(s)
        } else {
            s
        };
        resolved.parse::<u64>().ok()
    };

    enum AmountConstraint { Exact(u64), AtLeast(u64) }

    let amount_constraint: Option<AmountConstraint> = input.amount_sat.as_ref().and_then(|v| {
        if let Some(n) = v.as_u64() {
            Some(AmountConstraint::Exact(n))
        } else if let Some(s) = v.as_str() {
            resolve_amount_str(s).map(AmountConstraint::Exact)
        } else if let Some(obj) = v.as_object() {
            if let Some(min_v) = obj.get("min_amount") {
                let min = if let Some(n) = min_v.as_u64() {
                    Some(n)
                } else if let Some(s) = min_v.as_str() {
                    resolve_amount_str(s)
                } else {
                    None
                };
                min.map(AmountConstraint::AtLeast)
            } else {
                None
            }
        } else {
            None
        }
    });

    let utxo_matches = |value: u64| -> bool {
        match &amount_constraint {
            None => true,
            Some(AmountConstraint::Exact(a)) => value == *a,
            Some(AmountConstraint::AtLeast(a)) => value >= *a,
        }
    };

    // Check confidential UTXOs first.
    if let Some(asset_id) = required_asset {
        if let Some(utxo) = available.iter().find(|u| {
            u.unblinded.asset == asset_id
                && !claimed.contains(&outpoint_key(u))
                && utxo_matches(u.unblinded.value)
        }) {
            let key = outpoint_key(utxo);
            claimed.insert(key);
            return Ok(ResolvedInput {
                id: input.id.clone(),
                txid: utxo.outpoint.txid.to_string(),
                vout: utxo.outpoint.vout,
                amount_sat: utxo.unblinded.value,
                asset: utxo.unblinded.asset.to_string(),
                issuance_entropy: None,
            });
        }

        // Fall back to explicit (non-confidential) UTXOs.
        if let Some(utxo) = available_explicit.iter().find(|u| {
            u.unblinded.asset == asset_id
                && !claimed.contains(&outpoint_key_ext(u))
                && utxo_matches(u.unblinded.value)
        }) {
            let key = outpoint_key_ext(utxo);
            claimed.insert(key);
            return Ok(ResolvedInput {
                id: input.id.clone(),
                txid: utxo.outpoint.txid.to_string(),
                vout: utxo.outpoint.vout,
                amount_sat: utxo.unblinded.value,
                asset: utxo.unblinded.asset.to_string(),
                issuance_entropy: None,
            });
        }
    }

    let raw_label = input.asset.as_ref().and_then(|v| v.as_str()).unwrap_or("unknown");
    let asset_label = if let Some(k) = raw_label
        .strip_prefix("instance.")
        .or_else(|| raw_label.strip_prefix("compile_params."))
    {
        ctx.get_compile_param(k).unwrap_or(raw_label)
    } else if let Some(k) = raw_label.strip_prefix("params.") {
        ctx.get_param(k).unwrap_or(raw_label)
    } else {
        raw_label
    };
    // Build a per-asset balance summary for the error message.
    let mut balance: std::collections::BTreeMap<String, (u64, usize)> = std::collections::BTreeMap::new();
    for u in available {
        let e = balance.entry(u.unblinded.asset.to_string()).or_default();
        e.0 += u.unblinded.value;
        e.1 += 1;
    }
    for u in available_explicit {
        let e = balance.entry(u.unblinded.asset.to_string()).or_default();
        e.0 += u.unblinded.value;
        e.1 += 1;
    }
    let balance_lines: Vec<String> = if balance.is_empty() {
        vec!["  (no UTXOs — run `sync` first)".to_string()]
    } else {
        balance.iter().map(|(asset, (sats, count))| {
            format!("  {} sat  ({} UTXO{})  asset: {}", sats, count, if *count == 1 { "" } else { "s" }, asset)
        }).collect()
    };
    let balance_str = balance_lines.join("\n");

    let amount_needed = match &amount_constraint {
        None => "any amount".to_string(),
        Some(AmountConstraint::Exact(a)) => format!("exactly {a} sat"),
        Some(AmountConstraint::AtLeast(a)) => format!("at least {a} sat"),
    };

    let total_available = available.len() + available_explicit.len();
    if total_available == 0 {
        anyhow::bail!(
            "No wallet UTXOs available for input '{}'.\n  Need: {} of asset {}\n  Wallet balance:\n{}",
            input.id, amount_needed, asset_label, balance_str,
        );
    } else {
        anyhow::bail!(
            "No UTXO in your wallet matches input '{}'.\n  Need: {} of asset {}\n  Wallet balance:\n{}\n  Run `sync` to refresh, or `prepare` to create a matching UTXO.",
            input.id, amount_needed, asset_label, balance_str,
        );
    }
}

fn outpoint_key_ext(utxo: &lwk_wollet::ExternalUtxo) -> String {
    format!("{}:{}", utxo.outpoint.txid, utxo.outpoint.vout)
}

fn outpoint_key(utxo: &lwk_wollet::WalletTxOut) -> String {
    format!("{}:{}", utxo.outpoint.txid, utxo.outpoint.vout)
}

fn step_header(title: &str) -> String {
    style(format!("=== {title} ===")).bold().cyan().to_string()
}

fn issuance_kind(input: &crate::manifest::Input) -> Option<&str> {
    input
        .issuance
        .as_ref()
        .and_then(|v| v.get("kind"))
        .and_then(|v| v.as_str())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Augment the global `base` compile-params map and type-hints with any per-utxo-type remappings.
/// Each entry `(simf_key, cp_ref)` in `ut.script.compile_params` adds `simf_key → base[cp_ref]`
/// (and the matching type hint) so that simf-local param names (e.g. `SCRIPT_HASH`) are satisfied
/// even when the manifest-level key is named differently (e.g. `LENDING_COV_HASH`).
fn apply_utxo_compile_params(
    base: &std::collections::HashMap<String, String>,
    base_hints: &std::collections::HashMap<String, String>,
    ut: &crate::manifest::UtxoType,
) -> (std::collections::HashMap<String, String>, std::collections::HashMap<String, String>) {
    let cp_map = match ut.script.as_ref() {
        Some(s) if !s.compile_params.is_empty() => &s.compile_params,
        _ => return (base.clone(), base_hints.clone()),
    };
    let mut params = base.clone();
    let mut hints = base_hints.clone();
    for (simf_key, cp_ref) in cp_map {
        // cp_ref is either a key into base compile_params (e.g. "LENDER_NFT_ASSET_ID")
        // or a literal value (e.g. "1", "true"). Prefer lookup; fall back to literal.
        let resolved = base.get(cp_ref).cloned().unwrap_or_else(|| cp_ref.clone());
        params.insert(simf_key.clone(), resolved);
        if let Some(ty) = base_hints.get(cp_ref.as_str()) {
            hints.insert(simf_key.clone(), ty.clone());
        }
    }
    (params, hints)
}

/// Whether an output `amount_sat` formula references the reserved `fee` keyword
/// (as a whole token, so `fee_rate` or `coffee` don't match).
fn amount_uses_fee_keyword(v: &serde_json::Value) -> bool {
    let s = match v {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(m) => m.get("value").and_then(|x| x.as_str()).unwrap_or(""),
        _ => "",
    };
    s.split(|c: char| !c.is_alphanumeric() && c != '_').any(|tok| tok == "fee")
}

/// Resolve a witness `source.key` reference to a concrete pubkey hex for signing.
///
/// Supports `params.NAME` (an action param — used when a covenant is keyed by a
/// runtime value), plus the `$params.NAME` / `instance.NAME` forms (and the
/// deprecated `compile_params.NAME` alias) that resolve against compile params /
/// class fields. Anything else is returned verbatim and treated as a literal
/// pubkey hex.
fn resolve_witness_signing_key<'a>(
    key_ref: &'a str,
    action_params: &'a std::collections::HashMap<String, String>,
    compile_params: &'a std::collections::HashMap<String, String>,
) -> &'a str {
    if let Some(name) = key_ref.strip_prefix("params.") {
        if let Some(v) = action_params.get(name) {
            return v.as_str();
        }
    }
    if let Some(name) = key_ref
        .strip_prefix("$params.")
        .or_else(|| key_ref.strip_prefix("instance."))
        .or_else(|| key_ref.strip_prefix("compile_params."))
    {
        if let Some(v) = compile_params.get(name) {
            return v.as_str();
        }
    }
    key_ref
}

/// Apply per-site (output `destination` / input `utxo_source`) `compile_params`
/// overrides on top of the values derived from the utxo_type's `script` block.
///
/// Unlike the utxo_type form, each value here is resolved through the full
/// expression context, so a covenant compile param can be driven by an action
/// `param` or `arg` (e.g. `"PUB_KEY": "params.pubkey"`) rather than only by a
/// top-level compile param. The SimplicityHL type hint is carried from the
/// referenced declaration — covenant compilation needs it to type the argument
/// (many simf param names, e.g. `PUB_KEY`, are not inferable by convention).
fn apply_site_compile_param_overrides(
    mut params: std::collections::HashMap<String, String>,
    mut hints: std::collections::HashMap<String, String>,
    overrides: Option<&serde_json::Value>,
    action: &crate::manifest::Action,
    base_hints: &std::collections::HashMap<String, String>,
    ctx: &ExecutionContext,
) -> (std::collections::HashMap<String, String>, std::collections::HashMap<String, String>) {
    let Some(map) = overrides.and_then(|v| v.as_object()) else {
        return (params, hints);
    };
    for (simf_key, raw_val) in map {
        let Some(raw) = raw_val.as_str() else { continue };
        let raw = raw.trim();
        let value = eval::resolve_compile_param_value(raw, ctx);
        params.insert(simf_key.clone(), value);

        // Carry the declared type of whatever the value references so the
        // covenant compiler can type the argument.
        let param_type = |m: &Option<std::collections::BTreeMap<String, crate::manifest::ParamDef>>, k: &str| {
            m.as_ref().and_then(|defs| defs.get(k)).map(|p| p.type_.clone())
        };
        let hint = if let Some(k) = raw.strip_prefix("params.") {
            param_type(&action.params, k)
        } else if let Some(k) = raw.strip_prefix("args.") {
            param_type(&action.args, k)
        } else if let Some(k) = raw
            .strip_prefix("instance.")
            .or_else(|| raw.strip_prefix("compile_params."))
        {
            base_hints.get(k).cloned()
        } else if !raw.contains('.') {
            base_hints
                .get(raw)
                .cloned()
                .or_else(|| param_type(&action.params, raw))
                .or_else(|| param_type(&action.args, raw))
        } else {
            None
        };
        if let Some(h) = hint {
            hints.insert(simf_key.clone(), h);
        }
    }
    (params, hints)
}

fn run_validation(
    validation: &Validation,
    manifest: &Manifest,
    ctx: &ExecutionContext,
) -> Result<()> {
    let desc = validation.description.as_deref().unwrap_or("");

    match validation.rule.type_.as_str() {
        "arithmetic" => {
            let expr = validation.rule.expr.as_deref().unwrap_or("[missing expr]");
            // `!=` comparisons are enforced (e.g. asserting two asset IDs differ).
            // Other operators remain informational — see eval::eval_inequality_validation.
            match eval::eval_inequality_validation(expr, ctx) {
                Some(true) => {
                    println!(
                        "  {} Validation '{}': {} {}",
                        style("✓").green(),
                        style(&validation.id).bold(),
                        expr,
                        style("(ok)").dim(),
                    );
                }
                Some(false) => {
                    let msg = validation_error_message(validation).unwrap_or_else(|| {
                        format!("Validation '{}' failed: {}", validation.id, expr)
                    });
                    anyhow::bail!("{msg}");
                }
                None => {
                    println!(
                        "  {} Validation '{}': {}",
                        style("[TODO]").yellow(),
                        style(&validation.id).bold(),
                        expr
                    );
                    if !desc.is_empty() {
                        println!("    {}", style(desc).dim());
                    }
                }
            }
        }
        "simplicity_hl" | "simplicityhl" => {
            println!(
                "  {} SimplicityHL validation '{}'",
                style("[TODO]").yellow(),
                style(&validation.id).bold()
            );
            if !desc.is_empty() {
                println!("    {}", style(desc).dim());
            }
        }
        "utxo_exists" => {
            let utxo_type = validation.rule.utxo_type.as_deref().unwrap_or("[unknown]");
            println!(
                "  {} utxo_exists '{}': checking for utxo_type '{}'",
                style("[TODO]").yellow(),
                style(&validation.id).bold(),
                style(utxo_type).cyan()
            );
        }
        other => {
            println!(
                "  {} Unknown validation type '{}' for '{}'",
                style("[warn]").yellow(),
                other,
                validation.id
            );
        }
    }

    let _ = manifest;
    Ok(())
}

/// Broadcast a finalized transaction through the configured backend, returning the
/// txid on success. Esplora uses a direct HTTP `POST /tx`; Electrum goes through the
/// `Backend` client. Errors are returned as display strings so the caller can print
/// them without aborting the surrounding run bookkeeping.
fn broadcast_finalized_tx(
    cfg: &crate::config::Config,
    tx: &lwk_wollet::elements::Transaction,
    tx_hex: &str,
    network: lwk_wollet::ElementsNetwork,
) -> std::result::Result<String, String> {
    use crate::backend::{Backend, BackendKind};
    match cfg.backend_kind() {
        BackendKind::Esplora => {
            let url = format!("{}/tx", cfg.esplora_url().trim_end_matches('/'));
            println!("  {} POST {}", style("→").cyan(), style(&url).underlined());
            println!("  {} body: {} chars of hex", style("→").cyan(), tx_hex.len());
            match ureq::post(&url)
                .set("Content-Type", "text/plain")
                .send_string(tx_hex)
            {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.into_string().unwrap_or_default();
                    println!("  {} HTTP {status}", style("←").green());
                    println!("  {} body: {}", style("←").green(), body.trim());
                    if status == 200 {
                        Ok(body.trim().to_string())
                    } else {
                        Err(format!("Esplora rejected (HTTP {status}): {}", body.trim()))
                    }
                }
                Err(ureq::Error::Status(status, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    Err(format!("HTTP {status}: {}", body.trim()))
                }
                Err(e) => Err(format!("Transport error: {e}")),
            }
        }
        BackendKind::Electrum => {
            let url = cfg.electrum_url();
            println!(
                "  {} Electrum broadcast via {}",
                style("→").cyan(),
                style(url).underlined()
            );
            let backend = Backend::connect(BackendKind::Electrum, url, network)
                .map_err(|e| e.to_string())?;
            backend
                .broadcast(tx)
                .map(|txid| txid.to_string())
                .map_err(|e| e.to_string())
        }
    }
}

/// Extract a human-readable message from a validation's `error` field, which may be
/// a bare string or a `{"code": ..., "message": ...}` object.
fn validation_error_message(validation: &Validation) -> Option<String> {
    match validation.error.as_ref()? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(m) => {
            m.get("message").and_then(|v| v.as_str()).map(String::from)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Method-level hook execution
// ---------------------------------------------------------------------------

/// Execute a `HookBlock` (on_pre_broadcast / on_post_broadcast) against the
/// current execution context.  Setter targets use dot-path notation:
///   `"params.FOO"`    → ctx.set_param
///   `"instance.FOO"`  → ctx.set_compile_param (deprecated alias: `"compile_params.FOO"`)
///   `"args.FOO"`      → ctx.set_arg
fn run_hook_block(
    hook: &crate::manifest::HookBlock,
    ctx: &mut ExecutionContext,
    label: &str,
) {
    for (target, formula) in &hook.set {
        let value = match eval::eval_expr_str(formula, ctx) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "  {} hook set '{}' = '{}' — could not evaluate.",
                    style("[warn]").yellow(), target, formula
                );
                continue;
            }
        };
        if let Some(name) = target
            .strip_prefix("instance.")
            .or_else(|| target.strip_prefix("compile_params."))
        {
            ctx.set_compile_param(name, &value);
        } else if let Some(name) = target.strip_prefix("params.") {
            ctx.set_param(name, &value);
        } else if let Some(name) = target.strip_prefix("args.") {
            ctx.set_arg(name, &value);
        } else {
            ctx.set_param(target, &value);
        }
        let short = &value[..value.len().min(24)];
        println!(
            "  {} {} = {}…  {}",
            style("✓").green(),
            style(target).bold().cyan(),
            style(short).yellow(),
            style(label).dim(),
        );
    }
}

// ---------------------------------------------------------------------------
// create_instance field evaluation
// ---------------------------------------------------------------------------

/// Evaluate all `create_instance.fields` entries and return the resulting
/// `HashMap<String, String>` to be written as `instance.fields`.
///
/// Each field value is either:
///   - A string expression (`"$params.FOO"`, `"$instance.X"`, etc.)
///   - A `ParamCompute::Tapleaf` spec (same as used in Step 3b)
///
/// Multi-pass: fields that depend on other fields computed in the same block
/// are retried until stable (topological ordering without explicit sort).
fn eval_create_instance_fields(
    ci: &crate::manifest::InstanceCreate,
    ctx: &ExecutionContext,
    manifest_file: &std::path::Path,
    type_hints: &std::collections::HashMap<String, String>,
    network: lwk_wollet::ElementsNetwork,
    verbose: bool,
) -> std::collections::HashMap<String, String> {
    use crate::manifest::FieldValue;

    let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Track which field names still need evaluation; start with all of them.
    let mut remaining: Vec<&str> = ci.fields.keys().map(String::as_str).collect();
    // Names of all fields being computed in this block — used to avoid falling back to
    // a stale ctx value for a field that hasn't been computed yet in the current run.
    // Without this guard, PRE_LOCK_COV_HASH can pick up an old LENDING_COV_HASH from the
    // previously saved instance.json (which ctx loads at startup), compute the wrong hash,
    // and then refuse to recompute it when LENDING_COV_HASH is correctly evaluated later.
    let computed_field_names: std::collections::HashSet<&str> =
        ci.fields.keys().map(String::as_str).collect();

    loop {
        let prev_count = remaining.len();
        let mut still_pending: Vec<&str> = Vec::new();

        for field_name in &remaining {
            let field_value = &ci.fields[*field_name];

            let value: Option<String> = match field_value {
                FieldValue::Expr(expr) => {
                    // $params.X / $instance.X → direct lookup; other → eval_expr_str
                    expr
                        .strip_prefix("$params.")
                        .or_else(|| expr.strip_prefix("$instance."))
                        .or_else(|| expr.strip_prefix("$compile_params."))
                        .and_then(|name| {
                            ctx.get_param(name)
                                .or_else(|| ctx.get_compile_param(name))
                                .map(str::to_string)
                        })
                        .or_else(|| eval::eval_expr_str(expr, ctx).ok())
                }
                FieldValue::Compute(compute) => {
                    match compute {
                        crate::manifest::ParamCompute::Tapleaf { simf, params, depends_on } => {
                            // Build simf_params: if params is empty use depends_on (or all ctx params)
                            let simf_params: Option<std::collections::HashMap<String, String>> = if params.is_empty() {
                                let gate_names: Vec<String> = match depends_on {
                                    Some(deps) => deps.clone(),
                                    None => fields.keys().cloned()
                                        .chain(ctx.all_compile_params().keys().cloned())
                                        .chain(ctx.all_params().keys().cloned())
                                        .collect(),
                                };
                                let mut resolved = std::collections::HashMap::new();
                                let mut ok = true;
                                for cp_name in &gate_names {
                                    let from_ctx = !computed_field_names.contains(cp_name.as_str());
                                    let v = fields.get(cp_name.as_str())
                                        .map(String::as_str)
                                        .or_else(|| if from_ctx { ctx.get_compile_param(cp_name) } else { None })
                                        .or_else(|| if from_ctx { ctx.get_param(cp_name) } else { None });
                                    match v {
                                        Some(val) => { resolved.insert(cp_name.clone(), val.to_string()); }
                                        None => { ok = false; break; }
                                    }
                                }
                                if ok { Some(resolved) } else { None }
                            } else {
                                let mut resolved = std::collections::HashMap::new();
                                let mut ok = true;
                                for (k, p) in params {
                                    let v = p.value.as_str();
                                    let val = if v.parse::<u64>().is_ok() || v == "true" || v == "false" {
                                        p.value.clone()
                                    } else {
                                        // If `v` names another field in this create_instance block,
                                        // only look in `fields` (the in-progress map) — never in ctx.
                                        // ctx may hold a stale value from the previously saved instance,
                                        // and using it here would compute this field with outdated deps.
                                        let from_ctx = !computed_field_names.contains(v);
                                        match fields.get(v)
                                            .map(String::as_str)
                                            .or_else(|| if from_ctx { ctx.get_compile_param(v) } else { None })
                                            .or_else(|| if from_ctx { ctx.get_param(v) } else { None })
                                        {
                                            Some(s) => s.to_string(),
                                            None => { ok = false; break; }
                                        }
                                    };
                                    resolved.insert(k.clone(), val);
                                }
                                if ok { Some(resolved) } else { None }
                            };

                            match simf_params {
                                None => None, // deps not yet available — retry in a later pass
                                Some(p) => {
                                    let mut hints = p.keys()
                                        .filter_map(|k| type_hints.get(k).map(|t| (k.clone(), t.clone())))
                                        .collect::<std::collections::HashMap<_, _>>();
                                    // For explicit param overrides, inherit type from the referenced name,
                                    // then apply any inline type overrides.
                                    for (k, param) in params {
                                        if !hints.contains_key(k) {
                                            if let Some(ty) = type_hints.get(param.value.as_str()) {
                                                hints.insert(k.clone(), ty.clone());
                                            }
                                        }
                                    }
                                    for (k, param) in params {
                                        if let Some(ty) = &param.type_ {
                                            hints.insert(k.clone(), ty.clone());
                                        }
                                    }

                                    let simf_path = manifest_file.parent()
                                        .unwrap_or(std::path::Path::new("."))
                                        .join(simf.as_str());

                                    match covenant::compute_covenant_script_hash(&simf_path, &p, &hints, network) {
                                        Ok(hash_bytes) => {
                                            Some(hash_bytes.iter().map(|b| format!("{b:02x}")).collect())
                                        }
                                        Err(e) => {
                                            println!(
                                                "  {} create_instance script_hash '{}' failed: {e}",
                                                style("[error]").red(), field_name
                                            );
                                            None
                                        }
                                    }
                                }
                            }
                        }
                        crate::manifest::ParamCompute::Expr { expr } => {
                            eval::eval_expr_str(expr, ctx).ok()
                        }
                        crate::manifest::ParamCompute::SimfFn { .. } => {
                            // SimfFn is only valid on action params, not create_instance fields.
                            None
                        }
                    }
                }
            };

            match value {
                Some(v) => {
                    if verbose {
                        let short = &v[..v.len().min(16)];
                        println!(
                            "  {} {} = {}…  {}",
                            style("✓").green(),
                            style(*field_name).bold().cyan(),
                            style(short).yellow(),
                            style("[create_instance]").dim(),
                        );
                    }
                    fields.insert(field_name.to_string(), v);
                }
                None => {
                    still_pending.push(field_name);
                }
            }
        }

        remaining = still_pending;
        if remaining.is_empty() || remaining.len() == prev_count {
            break;
        }
    }

    // Warn about fields that could not be resolved in any pass.
    if verbose {
        for field_name in &remaining {
            println!(
                "  {} create_instance field '{}' — could not resolve (missing deps or compute error)",
                style("[warn]").yellow(), field_name
            );
        }
    }

    fields
}

// ---------------------------------------------------------------------------
// Headless API

/// One UTXO to pre-populate in the temporary state file for a headless run.
pub struct HeadlessUtxo {
    pub utxo_type: String,
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub asset: String,
}

/// Result of a successful headless lifecycle run.
pub struct HeadlessResult {
    /// Finalized transaction hex, ready to broadcast.
    pub tx_hex: String,
    /// Signed PSET as base64 (pre-finalization snapshot).
    pub pset_b64: String,
}

/// Run a manifest action non-interactively.
///
/// All UTXOs are provided explicitly via the state file mechanism.
/// `extra_params` must include every action param (e.g. `STATE_BYTES`,
/// `NEW_STATE_BYTES`, `NETWORK_FEE`) plus `fee_rate` (sat/vb as a float
/// string) to prevent the interactive fee prompt.
/// The instance file at `instance_path` must supply all compile params.
#[allow(clippy::too_many_arguments)]
pub fn run_headless(
    manifest_path: &Path,
    action_name: &str,
    network: &str,
    instance_path: Option<&Path>,
    wallet_path: &Path,
    data_dir: &Path,
    utxos: &[HeadlessUtxo],
    extra_params: &std::collections::HashMap<String, String>,
) -> Result<HeadlessResult> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("Cannot create data dir: {}", data_dir.display()))?;

    // Use nanosecond sub-second component to make temp filenames unique within
    // a single second (multiple concurrent creature ticks).
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);

    // Write temporary state file so lifecycle::run can auto-select UTXOs.
    let state = ContractState {
        instance: None,
        last_action: "prior".to_string(),
        utxos: utxos.iter().map(|u| StateUtxo {
            utxo_type: u.utxo_type.clone(),
            utxo_id: String::new(),
            txid: u.txid.clone(),
            vout: u.vout,
            amount_sat: u.amount_sat,
            asset: u.asset.clone(),
        }).collect(),
    };
    let state_path = data_dir.join(format!("_hl_state_{ns}.json"));
    state.write(&state_path).context("cannot write headless state file")?;

    // Write temporary params override file.
    let params_json = serde_json::to_string(extra_params)
        .context("cannot serialize headless params")?;
    let params_path = data_dir.join(format!("_hl_params_{ns}.json"));
    std::fs::write(&params_path, &params_json)
        .context("cannot write headless params file")?;

    // lifecycle::run writes PSET base64 to export_path and tx hex to <stem>.tx.hex.
    let export_path = data_dir.join(format!("_hl_export_{ns}.pset"));
    let tx_path = {
        let stem = format!("_hl_export_{ns}");
        data_dir.join(format!("{stem}.tx.hex"))
    };

    // Load the instance file (read-only for Heartbeat / DeathHeartbeat).
    let loaded_instance = instance_path
        .map(InstanceFile::load)
        .transpose()
        .context("cannot load instance file")?;

    // Run lifecycle — fully non-interactive when params + state are pre-filled.
    let run_result = run(
        manifest_path,
        action_name,
        Some(network),
        Some(&params_path),
        loaded_instance.as_ref(),
        instance_path,          // instance_in_path
        instance_path,          // instance_out_path (read-only methods; unused)
        Some(&state_path),      // state_in_path
        Some(&state_path),      // state_out_path
        wallet_path,
        data_dir,
        false,        // manual_inputs
        Some(&export_path),
        false,        // debug_jets
    );

    // Best-effort cleanup of temp files regardless of run_result.
    let _ = std::fs::remove_file(&state_path);
    let _ = std::fs::remove_file(&params_path);

    run_result?;

    let pset_b64 = std::fs::read_to_string(&export_path)
        .with_context(|| format!("Cannot read exported PSET: {}", export_path.display()))?;
    let tx_hex = std::fs::read_to_string(&tx_path)
        .with_context(|| format!("Cannot read exported TX hex: {}", tx_path.display()))?;

    let _ = std::fs::remove_file(&export_path);
    let _ = std::fs::remove_file(&tx_path);

    Ok(HeadlessResult { tx_hex, pset_b64 })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use crate::manifest::{FieldValue, InstanceCreate};

    /// When the action params handler resolves a `wallet_key` param, it must write
    /// the fresh value into BOTH `params` and `compile_params`.  Without the
    /// `compile_params` write, tapleaf hash computations (which read
    /// `ctx.all_compile_params()`) would silently use the stale key loaded from the
    /// previous instance file.
    #[test]
    fn wallet_key_action_param_overwrites_stale_compile_param() {
        let mut ctx = ExecutionContext::new();

        // Simulate class-fields loading from a previous instance file.
        ctx.set_compile_param("BORROWER_PUB_KEY", "1d4c354f5f91613f50ba8f59361bc5fb0d0e01fbb90495b7fbfc744e8f5d2253");

        // Simulate the fixed action-params handler: both writes now happen.
        let fresh_key = "c21eda458165b99ce9309896df32ea7470ee6c03d26f54b49fbd56df2295bdb8";
        ctx.set_param("BORROWER_PUB_KEY", fresh_key);
        ctx.set_compile_param("BORROWER_PUB_KEY", fresh_key);

        // compile_params must reflect the fresh key so tapleaf computations are correct.
        assert_eq!(
            ctx.get_compile_param("BORROWER_PUB_KEY"),
            Some(fresh_key),
            "compile_params must be overwritten with the fresh wallet key",
        );
        assert_eq!(
            ctx.get_param("BORROWER_PUB_KEY"),
            Some(fresh_key),
        );
        // Verify the full map that tapleaf code reads has the fresh value.
        assert_eq!(
            ctx.all_compile_params().get("BORROWER_PUB_KEY").map(String::as_str),
            Some(fresh_key),
        );
    }

    /// `apply_utxo_compile_params` must pass literal values (e.g. `"1"`, `"true"`) through
    /// unchanged when they don't exist as keys in the base compile_params map, and still
    /// resolve values that ARE keys. Without this, params like `ASSET_AMOUNT: "1"` were silently
    /// dropped, causing SimplicityHL to fail with "Parameter ASSET_AMOUNT is missing an argument".
    #[test]
    fn apply_utxo_compile_params_passes_literal_values_through() {
        use crate::manifest::{UtxoScript, UtxoType};
        use std::collections::HashMap;

        let mut base: HashMap<String, String> = HashMap::new();
        base.insert("LENDER_NFT_ASSET_ID".to_string(), "deadbeef".to_string());

        let base_hints: HashMap<String, String> = HashMap::new();

        let mut cp_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        cp_map.insert("ASSET_ID".to_string(), "LENDER_NFT_ASSET_ID".to_string()); // key reference
        cp_map.insert("ASSET_AMOUNT".to_string(), "1".to_string());                // literal
        cp_map.insert("WITH_ASSET_BURN".to_string(), "true".to_string());          // literal

        let ut = UtxoType {
            description: "test".to_string(),
            script: Some(UtxoScript {
                type_: "simplicity".to_string(),
                source: None,
                extra_leaves: None,
                compile_params: cp_map,
            }),
            asset: None,
            state_vars: None,
            confidential: false,
        };

        let (params, _hints) = apply_utxo_compile_params(&base, &base_hints, &ut);

        assert_eq!(params.get("ASSET_ID").map(String::as_str), Some("deadbeef"),
            "key reference should resolve to value from base");
        assert_eq!(params.get("ASSET_AMOUNT").map(String::as_str), Some("1"),
            "literal '1' must pass through even though it is not a key in base");
        assert_eq!(params.get("WITH_ASSET_BURN").map(String::as_str), Some("true"),
            "literal 'true' must pass through even though it is not a key in base");
    }

    /// Per-output `destination.compile_params` (and per-input `utxo_source.compile_params`)
    /// must let a covenant param be driven by an action `param`, resolving the value through
    /// the execution context AND carrying the param's declared type as the SimplicityHL hint.
    /// This is the p2pk case: a `PUB_KEY` covenant param keyed off `params.pubkey`, with no
    /// top-level `compile_params` block at all.
    #[test]
    fn site_compile_param_override_resolves_action_param_and_type() {
        use std::collections::HashMap;

        let action: crate::manifest::Action = serde_json::from_value(serde_json::json!({
            "description": "Pay",
            "params": {
                "pubkey": { "type": "pubkey", "description": "recipient key" }
            }
        })).expect("deserialize action");

        let mut ctx = ExecutionContext::new();
        let key = "c21eda458165b99ce9309896df32ea7470ee6c03d26f54b49fbd56df2295bdb8";
        ctx.set_param("pubkey", key);

        let base_hints: HashMap<String, String> = HashMap::new();
        let overrides = serde_json::json!({ "PUB_KEY": "params.pubkey" });

        let (params, hints) = apply_site_compile_param_overrides(
            HashMap::new(), HashMap::new(), Some(&overrides), &action, &base_hints, &ctx,
        );

        assert_eq!(params.get("PUB_KEY").map(String::as_str), Some(key),
            "PUB_KEY must resolve to the action param's runtime value");
        assert_eq!(hints.get("PUB_KEY").map(String::as_str), Some("pubkey"),
            "type hint must be carried from the referenced action param (PUB_KEY is not name-inferable)");
    }

    /// A witness `source.key` may reference an action `param` (covenant keyed by a runtime
    /// value), the `instance.` form, the legacy `$params.`/`compile_params.` compile-param
    /// forms, or a literal hex.
    #[test]
    fn witness_signing_key_resolves_action_param_and_compile_param() {
        use std::collections::HashMap;

        let mut action_params = HashMap::new();
        action_params.insert("pubkey".to_string(), "aa11".to_string());
        let mut compile_params = HashMap::new();
        compile_params.insert("BORROWER_PUB_KEY".to_string(), "bb22".to_string());

        // action param (the p2pk runtime-key case)
        assert_eq!(resolve_witness_signing_key("params.pubkey", &action_params, &compile_params), "aa11");
        // legacy compile-param forms (as used by the lending example)
        assert_eq!(resolve_witness_signing_key("$params.BORROWER_PUB_KEY", &action_params, &compile_params), "bb22");
        assert_eq!(resolve_witness_signing_key("instance.BORROWER_PUB_KEY", &action_params, &compile_params), "bb22");
        // Deprecated alias still accepted during the transition.
        assert_eq!(resolve_witness_signing_key("compile_params.BORROWER_PUB_KEY", &action_params, &compile_params), "bb22");
        // unknown / literal passes through verbatim
        assert_eq!(resolve_witness_signing_key("cc33ddee", &action_params, &compile_params), "cc33ddee");
    }

    /// A literal value in a per-site override passes through unchanged (no reference match).
    #[test]
    fn site_compile_param_override_passes_literal_through() {
        use std::collections::HashMap;

        let action: crate::manifest::Action =
            serde_json::from_value(serde_json::json!({ "description": "x" })).expect("action");
        let ctx = ExecutionContext::new();
        let overrides = serde_json::json!({ "COUNT": "7" });

        let (params, _hints) = apply_site_compile_param_overrides(
            HashMap::new(), HashMap::new(), Some(&overrides), &action, &HashMap::new(), &ctx,
        );

        assert_eq!(params.get("COUNT").map(String::as_str), Some("7"),
            "an unreferencing literal must pass through verbatim");
    }

    /// `eval_create_instance_fields` with a `"$params.KEY"` expression must prefer
    /// `ctx.params` over `ctx.compile_params`, so the fresh wallet key is used even
    /// if `compile_params` still holds a stale value (extra regression guard for the
    /// `Expr` evaluation path).
    #[test]
    fn eval_create_instance_fields_prefers_params_over_compile_params() {
        let mut ctx = ExecutionContext::new();
        ctx.set_compile_param("MY_KEY", "stale");
        ctx.set_param("MY_KEY", "fresh");

        let mut fields = BTreeMap::new();
        fields.insert(
            "MY_KEY".to_string(),
            FieldValue::Expr("$params.MY_KEY".to_string()),
        );
        let ci = InstanceCreate {
            class: "test".to_string(),
            fields,
        };

        let result = eval_create_instance_fields(
            &ci,
            &ctx,
            std::path::Path::new("/nonexistent"),
            &std::collections::HashMap::new(),
            lwk_wollet::ElementsNetwork::LiquidTestnet,
            false,
        );

        assert_eq!(
            result.get("MY_KEY").map(String::as_str),
            Some("fresh"),
            "$params.KEY expressions must prefer params over compile_params",
        );
    }
}
