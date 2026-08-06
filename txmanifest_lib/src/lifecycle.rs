use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use console::style;
use lwk_common::Signer;
use lwk_wollet::{ElementsNetwork, FsPersister, Wollet};

use crate::manifest::{Manifest, Input};
use crate::context::{ExecutionContext, ResolvedInput};
use crate::instance::InstanceFile;
use crate::state::{history_path, ContractState, HistoryEntry, StateHistory, StateUtxo};
use crate::params::ParamOverrides;
use crate::preview;
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

/// A runtime override that pins a manifest input to a specific on-chain outpoint.
///
/// Supplied via the CLI (`--input <id>=<txid>:<vout>`) or a JSON file, it takes
/// priority over `instance.provided_inputs` and the state file during input
/// resolution. `amount_sat` / `asset` are optional: when omitted they are derived
/// from the manifest input spec (e.g. a covenant input's fixed `amount_sat` and
/// `asset: instance.X`), which is what makes `txid:vout` alone sufficient for
/// covenant UTXOs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OutpointOverride {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub amount_sat: Option<u64>,
    #[serde(default)]
    pub asset: Option<String>,
}

impl OutpointOverride {
    /// Parse the CLI string form `<txid>:<vout>` (amount/asset derived later).
    pub fn parse_outpoint(s: &str) -> Result<Self> {
        let (txid, vout) = s
            .rsplit_once(':')
            .with_context(|| format!("expected <txid>:<vout>, got '{s}'"))?;
        let vout: u32 = vout
            .trim()
            .parse()
            .with_context(|| format!("vout in '{s}' must be a u32"))?;
        let txid = txid.trim();
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("txid in '{s}' must be 64 hex chars");
        }
        Ok(Self { txid: txid.to_string(), vout, amount_sat: None, asset: None })
    }
}

/// Run the interactive wallet lifecycle for the given action in a manifest file.
#[allow(clippy::too_many_arguments)]
pub fn run(
    manifest_file: &Path,
    action_name: &str,
    network: Option<&str>,
    params_file: Option<&Path>,
    instance: Option<&InstanceFile>,
    // Path the instance was loaded from (INPUT). Never auto-discovered; recorded into the
    // state file so template actions know which instance they belong to.
    instance_in_path: Option<&Path>,
    // Path to write the instance file on deploy (OUTPUT). When omitted, a fresh numbered
    // file `<stem>.instance.N.json` is used — never overwriting the input.
    instance_out_path: Option<&Path>,
    // Path to load existing contract state from (INPUT). Never auto-discovered.
    state_in_path: Option<&Path>,
    // Path to write updated contract state to (OUTPUT). When omitted, a fresh numbered file
    // `<stem>.state.N.json` is used — never overwriting `state_in_path`.
    state_out_path: Option<&Path>,
    // Runtime input overrides keyed by manifest input id (INPUT). Highest priority in
    // resolution, above `instance.provided_inputs` and the state file.
    provided_inputs: &std::collections::HashMap<String, OutpointOverride>,
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

    let manifest: Manifest = Manifest::from_json_str(&raw).with_context(|| {
        format!("Failed to parse manifest file: {}", manifest_file.display())
    })?;
    // How every `.simf` in this run compiles: debug symbols (which affect every CMR and
    // address, so interop targets like simplicity-lending can be matched without
    // hardcoding) and any unstable `-Z` features the programs need. Sourced from the
    // manifest's `simplicity_hl` block once, then passed to every compile site.
    let compile_opts = manifest.compile_opts();
    // INPUT paths (instance load, state load) are NEVER auto-discovered: a run only
    // loads an instance/state if one is passed explicitly (`--instance` / `--state`).
    // This keeps a stale on-disk file from silently overriding `--params` and never
    // continues from a state the caller didn't ask for.
    //
    // OUTPUT paths: an explicit `--instance-out` / `--state-out` is used verbatim;
    // otherwise the run writes a FRESH numbered file derived from the manifest stem
    // (`txmanifest.state.1.json`, `.2`, …) rather than overwriting the input file or a
    // bare canonical. Nothing is ever clobbered, and the input state is preserved.
    let manifest_dir = manifest_file.parent().unwrap_or(Path::new("."));
    let manifest_stem = manifest_file
        .file_name().and_then(|n| n.to_str()).unwrap_or("contract")
        .trim_end_matches(".json");
    // Stable, unversioned bases — used to seed numbered outputs and to derive the
    // single append-only history log (which must not itself be versioned).
    let instance_base = manifest_dir.join(format!("{manifest_stem}.instance.json"));
    let state_base    = manifest_dir.join(format!("{manifest_stem}.state.json"));
    let effective_instance_out: std::path::PathBuf = match instance_out_path {
        Some(p) => p.to_path_buf(),
        None => crate::state::next_version_path(&instance_base),
    };
    let effective_state_out: std::path::PathBuf = match state_out_path {
        Some(p) => p.to_path_buf(),
        None => crate::state::next_version_path(&state_base),
    };
    // History log lives next to the explicit output when one is given, else next to
    // the stable state base — a single `<stem>.state.history.json`, not per-version.
    let history_seed: std::path::PathBuf = state_out_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| state_base.clone());

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

    // Dispatch: standalone actions first, then contract-template actions.
    let mut enclosing_template: Option<&str> = None;
    let action = if let Some(a) = manifest.actions.get(action_name) {
        a
    } else if let Some((template_id, _template_def, template_action)) = manifest.find_template_action(action_name) {
        enclosing_template = Some(template_id);
        template_action
    } else {
        let mut available: Vec<String> = manifest.actions.keys().cloned().collect();
        if let Some(contract_templates) = &manifest.contract_templates {
            for cls in contract_templates.values() {
                available.extend(cls.actions.keys().cloned());
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

    // Load all template field values from the instance file as compile params.
    if let Some((_, template_def, _)) = manifest.find_template_action(action_name) {
        let mut loaded_fields = 0usize;
        for (field_name, field_def) in &template_def.fields {
            if ctx.get_compile_param(field_name).is_some() {
                continue;
            }
            if let Some(v) = instance
                .and_then(|i| i.get_field(field_name))
                .or_else(|| overrides.get(field_name))
            {
                ctx.set_compile_param(field_name, v);
                loaded_fields += 1;
            } else if action.create_instance.is_none() {
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
        if loaded_fields > 0 {
            println!(
                "  {} {} template field(s) loaded from instance.",
                style("✓").green(), loaded_fields
            );
        }
    }

    // Type hints from manifest spec — needed for tapleaf computes (and later for covenant address).
    let mut compile_param_type_hints: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Extend type hints with template field types for template actions.
    if let Some((_, template_def, _)) = manifest.find_template_action(action_name) {
        for (field_name, field_def) in &template_def.fields {
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
                if let Some(expr) = def.compute.as_ref().and_then(|c| c.as_expr()) {
                    println!(
                        "  {} {} computed: {}",
                        style(name).bold().cyan(),
                        style(format!("({})", def.type_)).dim(),
                        style(expr).yellow()
                    );
                }
                // Hook params are filled by an on_resolved / on_pre_broadcast block later in
                // the run. Nothing to prompt for and nothing to evaluate yet — but a
                // --params override still wins, so a value can be pinned for a dry run.
                if def.compute.as_ref().is_some_and(|c| c.is_hook())
                    && overrides.get(name.as_str()).is_none()
                {
                    println!(
                        "  {} {}  {}",
                        style("○").dim(),
                        style(name.as_str()).cyan(),
                        style("[will be set by a hook]").dim(),
                    );
                    continue;
                }

                // SimfFn params are computed after inputs resolve (Step 3a). Skip here unless
                // an explicit override is provided via --params.
                if def.compute.as_ref().is_some_and(|c| c.is_simf_fn())
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

                // Priority: wallet_* compute > --params override > expr compute > prompt.
                use crate::manifest::WalletValue as WV;
                let value = if let Some(kind) = def.compute.as_ref().and_then(|c| c.as_wallet()) {
                    let label = match kind {
                        WV::Key => "wallet.key",
                        WV::ScriptHash => "wallet.script_hash",
                        WV::Address => "wallet.address",
                    };
                    let w = loaded_wallet.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Param '{name}' computes from {label} but no wallet is loaded")
                    })?;
                    let (v, detail) = match kind {
                        WV::Key => {
                            let info = wallet::wallet_info(w)?;
                            let d = format!("[wallet key, path: {}]", info.wallet_key_path);
                            (info.wallet_pubkey.clone(), d)
                        }
                        // Committed payout target: sha256(explicit index-0 scriptPubKey) and
                        // the matching explicit address. Mirrors simplicity-lending's
                        // borrower payout — the covenant commits to the hash, the wallet
                        // receives at the address, so the two must agree.
                        WV::ScriptHash | WV::Address => {
                            let (addr, hash) = wallet::committed_output(w)?;
                            let v = if matches!(kind, WV::ScriptHash) { hash } else { addr };
                            (v, format!("[{label}]"))
                        }
                    };
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(&v).yellow(),
                        style(detail).dim(),
                    );
                    v
                } else if let Some(ov) = overrides.get(name) {
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(ov).yellow(),
                        style("[from --params]").dim(),
                    );
                    ov.to_string()
                } else if let Some(expr) = def.compute.as_ref().and_then(|c| c.as_expr()) {
                    let computed = eval::eval_expr_str(expr, &ctx)?;
                    println!(
                        "  {} {} = {}  {}",
                        style("✓").green(),
                        style(name).bold().cyan(),
                        style(&computed).yellow(),
                        style(format!("[auto: {expr}]")).dim(),
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

    // ------------------------------------------------------------------
    // Step 2 — Input Selection
    // ------------------------------------------------------------------
    println!();
    println!("{}", step_header("Step 2: Input Selection"));

    let mut claimed: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(inputs) = &action.inputs {
        for input in inputs {
            print_input_intent(input);
            // Resolution priority: CLI/file override → instance.provided_inputs →
            // state file (by utxo_type) → auto-select / prompt.
            let resolved = if let Some(ov) = provided_inputs.get(&input.id) {
                // Derive amount/asset from the override, then the state file (matching
                // outpoint), then the manifest input spec — so `txid:vout` alone works
                // for covenant inputs whose amount/asset are fixed in the manifest.
                let state_utxo = contract_state.as_ref().and_then(|s| {
                    s.utxos.iter().find(|u| u.txid == ov.txid && u.vout == ov.vout)
                });
                let asset = ov
                    .asset
                    .clone()
                    .or_else(|| state_utxo.map(|u| u.asset.clone()))
                    .or_else(|| input.asset.as_ref().and_then(|v| eval::eval_asset_label(v, &ctx).ok()))
                    .unwrap_or_else(|| "lbtc".to_string());
                let amount_sat = ov
                    .amount_sat
                    .or_else(|| state_utxo.map(|u| u.amount_sat))
                    .or_else(|| input.amount_sat.as_ref().and_then(|v| eval::eval_amount(v, &ctx).ok()))
                    .unwrap_or(0);
                println!(
                    "  {} {}  txid={}…  vout={}  {} sat  asset={}  {}",
                    style("✓").green(),
                    style(&input.id).bold(),
                    &ov.txid[..8.min(ov.txid.len())],
                    ov.vout,
                    style(amount_sat).yellow(),
                    style(&asset).dim(),
                    style("[override]").cyan(),
                );
                ResolvedInput {
                    id: input.id.clone(),
                    txid: ov.txid.clone(),
                    vout: ov.vout,
                    amount_sat,
                    asset,
                    issuance_entropy: None,
                }
            } else if let Some(provided) = instance
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
                        ctx.set_input_attr(&inp.id, "issued_asset", asset_id.to_string());
                        ctx.set_input_attr(&inp.id, "reissuance_token", token_id.to_string());
                    }
                }
            }
            Some("reissue") => {
                let rt_asset = match ctx.get_input(&inp.id) {
                    Some(r) => r.asset.clone(),
                    None => continue,
                };
                ctx.set_input_attr(&inp.id, "reissuance_token", &rt_asset);
                if let Ok(Some(entropy)) = resolve_issuance_entropy(inp, &ctx) {
                    if let Ok(asset_id) = pset_builder::compute_asset_from_entropy(&entropy) {
                        ctx.set_input_attr(&inp.id, "asset", asset_id.to_string());
                        ctx.set_input_attr(&inp.id, "issued_asset", asset_id.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    for inp in action.inputs.as_deref().unwrap_or_default() {
        let Some(hook) = &inp.on_resolved else { continue };
        let label = format!("[on_resolved: {}]", inp.id);
        run_hook_block(hook, &mut ctx, &label, Some(&inp.id));
    }

    // ------------------------------------------------------------------
    // Step 3a-ii — Method-level on_pre_broadcast hook
    // Runs after input resolution + issuance attrs, before PSET construction.
    // ------------------------------------------------------------------
    if let Some(hook) = &action.on_pre_broadcast {
        run_hook_block(hook, &mut ctx, "[on_pre_broadcast]", None);
    }

    // ------------------------------------------------------------------
    // Step 3b — Tapleaf-derived params (computed after hooks set asset IDs)
    // ------------------------------------------------------------------
    let net_for_hash = loaded_wallet.as_ref()
        .map(wallet::elements_network)
        .unwrap_or(ElementsNetwork::LiquidTestnet);

    // ------------------------------------------------------------------
    // Step 3c — SimfFn computed action params
    // Runs after inputs are fully resolved so that input-derived values
    // (e.g. params.STATE_BYTES already entered, inputs.*.state_bytes) are
    // available to the function.
    // ------------------------------------------------------------------
    if let Some(params) = &action.params {
        let simf_params: Vec<(&str, &crate::manifest::ParamDef)> = params
            .iter()
            .filter(|(_, def)| def.compute.as_ref().is_some_and(|c| c.is_simf_fn()))
            .map(|(n, d)| (n.as_str(), d))
            .collect();

        if !simf_params.is_empty() {
            println!();
            println!("{}", step_header("Step 3c: SimfFn Computed Params"));
        }

        for (name, def) in simf_params {
            // If an override was supplied in Step 1 the param is already in ctx — skip.
            if ctx.get_param(name).is_some() { continue; }

            let Some(crate::manifest::ParamCompute::SimfFn { simf, fn_name, compile_params: cp_names, input }) =
                def.compute.as_ref().and_then(|c| c.as_spec()) else { continue };

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
                &compile_opts,
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
        .join("covenant.simf");

    // For constructor actions: pre-compute create_instance tapleaf fields (e.g.
    // FUNDING_SCRIPT_HASH) so they are present in compile_params_map for Step 7.
    // Without this, missing template fields fall back to the literal param name as a
    // value, which later fails `Value::parse_from_str` with non-hex characters.
    {
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
                ci, &ctx, manifest_file, &pre_hints, net_for_hash, false, &compile_opts,
            );
            for (name, val) in pre_fields {
                ctx.set_compile_param(&name, val);
            }
        }
    }

    let compile_params_map: std::collections::HashMap<String, String> = {
        let mut m = std::collections::HashMap::new();
        // For template actions: also expose template field values (loaded into ctx in Step 1).
        if let Some((_, template_def, _)) = manifest.find_template_action(action_name) {
            for field_name in template_def.fields.keys() {
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
                            ctx.set_input_attr(&inp.id, "issued_asset", asset_id.to_string());
                            ctx.set_input_attr(&inp.id, "reissuance_token", token_id.to_string());
                        }
                    }
                }
                Some("reissue") => {
                    let rt_asset = match ctx.get_input(&inp.id) {
                        Some(r) => r.asset.clone(),
                        None => continue,
                    };
                    ctx.set_input_attr(&inp.id, "reissuance_token", &rt_asset);
                    if let Ok(Some(entropy)) = resolve_issuance_entropy(inp, &ctx) {
                        if let Ok(asset_id) = pset_builder::compute_asset_from_entropy(&entropy) {
                            ctx.set_input_attr(&inp.id, "asset", asset_id.to_string());
                            ctx.set_input_attr(&inp.id, "issued_asset", asset_id.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        // ---- Evaluate on_resolved inline hooks ----
        for inp in action.inputs.as_deref().unwrap_or_default() {
            let Some(hook) = &inp.on_resolved else { continue };
            let label = format!("[on_resolved: {}]", inp.id);
            run_hook_block(hook, &mut ctx, &label, Some(&inp.id));
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
                    let entropy = match resolve_issuance_entropy(inp, &ctx) {
                        Ok(Some(e)) => e,
                        Ok(None) => {
                            println!(
                                "  {} Input '{}' is a reissuance but no entropy was found. Give the 
         issuance an \"entropy\" reference (e.g. \"instance.YES_ISSUANCE_ENTROPY\",
         captured by the constructor as \"$inputs.<id>.issuance_entropy\"), or put
         issuance_entropy on this input in the instance file's provided_inputs.",
                                style("[error]").red(), inp.id
                            );
                            collect_inputs_ok = false;
                            break;
                        }
                        Err(e) => {
                            println!("  {} Input '{}': {e}", style("[error]").red(), inp.id);
                            collect_inputs_ok = false;
                            break;
                        }
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
                let leaf_payloads = match inp_ut.resolve_extra_leaf_payloads(&ctx) {
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
                // params), mirroring the output `destination.compile_params` form.
                let (inp_params, inp_hints) = apply_site_compile_param_overrides(
                    inp_params, inp_hints, inp.utxo_source.get("compile_params"),
                    action, &compile_param_type_hints, &ctx,
                );
                let script_pubkey = match pset_builder::covenant_script_pubkey(&inp_simf_path, &inp_params, &inp_hints, &leaf_payloads, net, &compile_opts) {
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
    // Assets the action declares a `"change"` output for. Anything left over in an asset
    // absent from this set is an error, not an output the engine invents.
    let mut change_assets: std::collections::HashSet<lwk_wollet::elements::AssetId> =
        std::collections::HashSet::new();
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
                        change_assets.insert(asset_id);
                        continue;
                    }
                    serde_json::Value::Object(m)
                        if m.get("type").and_then(|v| v.as_str()) == Some("fee") => { continue; }
                    serde_json::Value::Object(m)
                        if matches!(m.get("type").and_then(|v| v.as_str()), Some("op_return") | Some("burn")) =>
                    {
                        // Bare `OP_RETURN` by default (sufficient for NFT burns); if a `data`
                        // expression is present, embed its bytes so indexers can discover the tx.
                        let script_pubkey = match &output.data {
                            None => lwk_wollet::elements::Script::from(vec![0x6au8]),
                            Some(expr) => match eval::eval_op_return_data(expr, &ctx, &compile_param_type_hints) {
                                Ok(bytes) => lwk_wollet::elements::Script::new_op_return(&bytes),
                                Err(e) => {
                                    println!("  {} Output '{}' OP_RETURN data eval failed: {e}", style("[error]").red(), output.id);
                                    collect_outputs_ok = false;
                                    break;
                                }
                            },
                        };
                        let data_note = if output.data.is_some() { format!(" ({} data bytes)", script_pubkey.len().saturating_sub(2)) } else { String::new() };
                        println!(
                            "  {} Output '{}': {} sat {} → OP_RETURN{}",
                            style("+").green(), output.id, style(amount).yellow(), asset_label, data_note
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
                        let leaf_payloads = match ut.resolve_extra_leaf_payloads(&ctx) {
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
                        // action params), so a covenant can be keyed by a runtime value.
                        let (out_params, out_hints) = apply_site_compile_param_overrides(
                            out_params, out_hints, m.get("compile_params"),
                            action, &compile_param_type_hints, &ctx,
                        );
                        let script_pubkey = match pset_builder::covenant_script_pubkey(&out_simf_path, &out_params, &out_hints, &leaf_payloads, net, &compile_opts) {
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
                        // Resolution order: per-output → chain default.
                        // Bitcoin does not support confidential outputs; Liquid defaults to confidential.
                        let chain_default = matches!(net, ElementsNetwork::Liquid | ElementsNetwork::LiquidTestnet);
                        let is_confidential = output.confidential.unwrap_or(chain_default);
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
            // Change is permitted per ASSET: by an explicit `destination: "change"`
            // output (collected while resolving outputs, above), or by the action's
            // `allow_change` setting, which covers surpluses that cannot be predicted —
            // chiefly the L-BTC left after a fee whose size is only known once the
            // transaction is built.
            let mut change_assets = change_assets;
            match action.allow_change {
                crate::manifest::AllowChange::None => {}
                crate::manifest::AllowChange::LbtcOnly => {
                    change_assets.insert(net.policy_asset());
                }
                crate::manifest::AllowChange::Any => {
                    for i in &pset_inputs {
                        if let pset_builder::PsetInput::Wallet { utxo, .. } = i {
                            change_assets.insert(utxo.unblinded.asset);
                        }
                    }
                    change_assets.insert(net.policy_asset());
                }
            }
            let mut req = pset_builder::BuildPsetRequest {
                inputs: pset_inputs,
                outputs: pset_outputs,
                fee_rate: fee_rate as f32,
                policy_asset: net.policy_asset(),
                change_assets: change_assets.clone(),
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
                        // Printed in full, not elided. These ids exist nowhere else yet:
                        // they are derived from this input's outpoint, and unless the action
                        // is a constructor that captures them via `on_resolved`, this line is
                        // the only record the operator will ever get. An elided id is not a
                        // record of anything.
                        println!("    Issuance '{}':", iso.input_id);
                        println!("      asset             = {}", style(iso.asset_id.to_string()).yellow());
                        println!("      reissuance_token  = {}", style(iso.token_id.to_string()).yellow());
                        if let Some(entropy_bytes) = &iso.entropy {
                            // Needed verbatim in the instance file's `provided_inputs` before
                            // any later reissuance of this asset can be built.
                            println!("      issuance_entropy  = {}", style(hex_bytes(entropy_bytes)).yellow());
                        }
                        ctx.set_input_attr(&iso.input_id, "asset", iso.asset_id.to_string());
                        ctx.set_input_attr(&iso.input_id, "issued_asset", iso.asset_id.to_string());
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
                match covenant::check_compile(&check_simf_path, &check_params, &check_hints, &compile_opts) {
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
                                    let leaf_payloads = match dry_ut.resolve_extra_leaf_payloads(&ctx) {
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

                                    let dry_witnesses = action_inp.witnesses.as_ref()
                                        .map(|w| eval::resolve_witness_refs(w, &ctx));
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
                                        dry_witnesses.as_ref(),
                                        Some(&dry_signer_fn),
                                        Arc::clone(&tx),
                                        &utxos,
                                        pset_idx as u32,
                                        genesis_hash,
                                        debug_jets,
                                        &compile_opts,
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
                                let leaf_payloads = match fin_ut.resolve_extra_leaf_payloads(&ctx) {
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
                                let fin_witnesses = action_inp.witnesses.as_ref()
                                    .map(|w| eval::resolve_witness_refs(w, &ctx));
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
                                    fin_witnesses.as_ref(),
                                    Some(&signer_fn),
                                    Arc::clone(&tx),
                                    &utxos,
                                    pset_idx as u32,
                                    genesis_hash,
                                    &mut pset.inputs_mut()[pset_idx],
                                    &compile_opts,
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

    if let Some(ci) = &action.create_instance {
        println!();
        println!("{}", step_header("Step 9b: Creating Instance"));
        let fields = eval_create_instance_fields(
            ci, &ctx, manifest_file, &create_instance_hints, net_for_hash, true, &compile_opts,
        );
        let inst = crate::instance::InstanceFile {
            instance: Some(crate::instance::InstanceData {
                template: enclosing_template
                    .expect("create_instance is only legal inside a contract template")
                    .to_string(),
                fields: fields.into_iter().collect(),
            }),
            instance_params: std::collections::HashMap::new(),
            provided_inputs: std::collections::HashMap::new(),
        };
        match inst.write(&effective_instance_out) {
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

    // Clear-signing preview: action summary + net-effect diff, from the
    // manifest's `ui` metadata. Author-supplied, so gated by the manifest's own
    // trust chain — not a device-verified display. The verified wallet-delta
    // section comes from the built PSET (LWK unblinds the wallet's own outputs),
    // so it reflects the real selected inputs, change, and fee.
    // Fee from the built PSET's explicit fee output — available whenever a PSET was
    // built, so change amounts stay exact even if get_details can't unblind below.
    let preview_fee = signed_pset.as_ref().map(crate::prepare::pset_fee);
    let wallet_delta = match (&signed_pset, &wollet_opt) {
        (Some(pset), Some(wollet)) => match wollet.get_details(pset) {
            Ok(details) => Some(preview::WalletDelta {
                fee_sat: details.balance.fee,
                balances: details
                    .balance
                    .balances
                    .iter()
                    .map(|(asset, units)| (asset.to_string(), *units))
                    .collect(),
            }),
            Err(e) => {
                println!("  {} Could not compute verified wallet delta for preview: {e}", style("[warn]").yellow());
                None
            }
        },
        _ => None,
    };
    preview::render_preview(action, &ctx, preview_fee, wallet_delta.as_ref());

    println!();
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
                                    run_hook_block(hook, &mut ctx, "[on_post_broadcast]", None);
                                }

                                // --- Update and write state file ---
                                let mut new_state = contract_state.take()
                                    .unwrap_or_else(|| ContractState::new(action_name));
                                new_state.last_action = action_name.to_string();
                                // Record which instance file this contract belongs to: the
                                // just-written output for constructors, else the loaded input.
                                let recorded_instance = if action.create_instance.is_some() {
                                    Some(effective_instance_out.as_path())
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
                                match new_state.write(&effective_state_out) {
                                    Ok(()) => {
                                        println!(
                                            "  {} State written:    {}",
                                            style("✓").green(),
                                            effective_state_out.display()
                                        );
                                        let hist_path = history_path(&history_seed);
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

/// Announce what an input *is* — its `ui.label` and `ui.role` — before resolution is attempted.
///
/// The resolution lines that follow identify an input only by its manifest id (`active_offer_in`),
/// which says nothing about the thing being spent. Printed ahead of resolution so the intent is on
/// screen even when resolution then fails. Silent for inputs with no declared label, so manifests
/// that carry no UI hints log exactly as before.
fn print_input_intent(input: &Input) {
    let Some(label) = input.ui_label() else { return };
    // Separator is ':' rather than a dash — labels commonly contain an em-dash of their own,
    // and two dashes on one line read as a single run-on sentence.
    match input.ui_role() {
        Some(role) => println!(
            "  {} {}{} {}",
            style(&input.id).bold(),
            style(format!("[{role}]")).cyan(),
            style(":").dim(),
            style(label).dim(),
        ),
        None => println!(
            "  {}{} {}",
            style(&input.id).bold(),
            style(":").dim(),
            style(label).dim(),
        ),
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
    // Protocol/covenant inputs are never invented. Reaching here means every
    // resolution source came up empty (--input override, instance.provided_inputs,
    // and the state file), so fail loudly with the fix rather than fabricating a UTXO.
    if !input.is_wallet_source() {
        let utxo_type = input.utxo_type_name().unwrap_or_else(|| "[complex]".to_string());
        // Say what the input IS, not just its id — this error is the one place a covenant input's
        // absence surfaces, and "active_offer_in could not be resolved" alone gives the reader
        // nothing to act on. Broken across lines: the label is a sentence, so inlining it into the
        // headline ran the id, the prose and the utxo_type together.
        let what = input
            .ui_label()
            .map(|l| format!("\n  what it is : {l}"))
            .unwrap_or_default();
        anyhow::bail!(
            "Input '{id}' could not be resolved.{what}\n  \
             utxo_type  : {utxo_type}\n\
             It was not found in --input, the instance's provided_inputs, or the state file.\n\
             Provide its outpoint explicitly:\n    \
             --input {id}=<txid>:<vout>\n\
             or pass a state file that contains it:\n    \
             --state <contract>.state.N.json",
            id = input.id,
        );
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

    // Optional address pin: restrict selection to UTXOs at this exact scriptPubKey.
    // Resolves a reference (instance./params.) or a literal address string.
    let from_spk: Option<lwk_wollet::elements::Script> = input.from_address.as_ref().and_then(|s| {
        let resolved = eval::eval_destination_str(s, ctx).unwrap_or_else(|| s.clone());
        match resolved.trim().parse::<lwk_wollet::elements::Address>() {
            Ok(a) => Some(a.script_pubkey()),
            Err(e) => {
                println!("  {} Input '{}' from_address '{}' is not a valid address: {e}", style("[warn]").yellow(), input.id, resolved);
                None
            }
        }
    });
    let spk_matches_wt = |u: &lwk_wollet::WalletTxOut| from_spk.as_ref().map_or(true, |spk| &u.script_pubkey == spk);
    let spk_matches_ext = |u: &lwk_wollet::ExternalUtxo| from_spk.as_ref().map_or(true, |spk| &u.txout.script_pubkey == spk);

    // Check confidential UTXOs first.
    if let Some(asset_id) = required_asset {
        if let Some(utxo) = available.iter().find(|u| {
            u.unblinded.asset == asset_id
                && !claimed.contains(&outpoint_key(u))
                && utxo_matches(u.unblinded.value)
                && spk_matches_wt(u)
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
                && spk_matches_ext(u)
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

/// Resolve the issuance entropy for a reissuance input.
///
/// Two sources, in order:
/// 1. `issuance.entropy` — a reference into the run context, normally an instance field a
///    constructor captured with `$inputs.<id>.issuance_entropy`. This is the good path: the
///    value travels with the contract and nothing has to pin an outpoint to carry it.
/// 2. `provided_inputs.<id>.issuance_entropy` in the instance file — the older path, kept
///    working. It rides along with an outpoint override, which pins that input for *every*
///    action sharing the input id, long after the pin stops being correct.
///
/// Returns `Ok(None)` when neither is present, so the caller can name the offending input.
fn resolve_issuance_entropy(
    inp: &crate::manifest::Input,
    ctx: &ExecutionContext,
) -> anyhow::Result<Option<[u8; 32]>> {
    let spec = inp.issuance.as_ref();
    let entropy_ref = spec.and_then(|v| v.get("entropy")).and_then(|v| v.as_str());

    let hex = match entropy_ref {
        Some(r) => Some(eval::resolve_value_ref(r, ctx).ok_or_else(|| {
            anyhow::anyhow!(
                "issuance.entropy '{r}' does not resolve — a constructor should capture it \
                 with \"$inputs.<id>.issuance_entropy\""
            )
        })?),
        None => ctx.get_input(&inp.id).and_then(|r| r.issuance_entropy.clone()),
    };

    let Some(hex) = hex else { return Ok(None) };
    let entropy = pset_builder::decode_entropy_hex(&hex)
        .with_context(|| format!("issuance entropy '{hex}' is not 32 bytes of hex"))?;

    // Optional cross-check. An entropy is opaque — a byte-reversed one (the order every
    // block explorer prints) is still well-formed, and the transaction it builds still
    // broadcasts; it just reissues a different asset. Re-deriving the asset id turns that
    // into an error here rather than a wrong market later.
    if let Some(expected_ref) = spec
        .and_then(|v| v.get("issued_asset"))
        .and_then(|v| v.as_str())
    {
        if let Some(expected) = eval::resolve_value_ref(expected_ref, ctx) {
            let derived = pset_builder::compute_asset_from_entropy(&entropy)?.to_string();
            anyhow::ensure!(
                derived == expected,
                "issuance entropy does not produce the declared asset:\n      \
                 entropy  {hex}\n      derives  {derived}\n      declared {expected} ({expected_ref})\n      \
                 note: an entropy copied from a block explorer is byte-reversed relative to this one"
            );
        }
    }
    Ok(Some(entropy))
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
/// template fields. Anything else is returned verbatim and treated as a literal
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
        } else {
            None
        };
        if let Some(h) = hint {
            hints.insert(simf_key.clone(), h);
        }
    }
    (params, hints)
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

// ---------------------------------------------------------------------------
// Method-level hook execution
// ---------------------------------------------------------------------------

/// Execute one hook block: evaluate each `set` value and write it to its target.
///
/// Serves every hook position. `input_id` is `Some` for an input's `on_resolved`,
/// which enables the two self-referential keywords `asset` and `reissuance_token`.
///
/// Only the expression forms of [`ComputeSpec`] are evaluated here; `validate`
/// rejects the others in hook position, so reaching one at run time means the
/// manifest was not validated.
fn run_hook_block(
    hook: &crate::manifest::HookBlock,
    ctx: &mut ExecutionContext,
    label: &str,
    input_id: Option<&str>,
) {
    for (target, spec) in &hook.set {
        let Some(expr) = spec.as_expr() else {
            println!(
                "  {} hook set '{}' — only expression values run in a hook; \
                 tapleaf/simf_fn/wallet are rejected by `validate`.",
                style("[warn]").yellow(), target
            );
            continue;
        };

        // Within an input's own on_resolved, `asset` and `reissuance_token` resolve
        // to that input's computed issuance attrs, falling back to its UTXO fields.
        let value: Option<String> = match (input_id, expr.trim()) {
            (Some(id), "asset") => ctx
                .get_input_attr(id, "asset")
                .map(str::to_string)
                .or_else(|| ctx.get_input(id).map(|r| r.asset.clone())),
            (Some(id), "reissuance_token") => {
                ctx.get_input_attr(id, "reissuance_token").map(str::to_string)
            }
            _ => eval::eval_expr_str(expr, ctx).ok(),
        };

        let Some(v) = value else {
            println!(
                "  {} hook set '{}' = '{}' — could not evaluate.",
                style("[warn]").yellow(), target, expr
            );
            continue;
        };

        if let Some(name) = target
            .strip_prefix("instance.")
            .or_else(|| target.strip_prefix("compile_params."))
        {
            ctx.set_compile_param(name, &v);
        } else if let Some(name) = target.strip_prefix("params.") {
            ctx.set_param(name, &v);
        } else {
            println!(
                "  {} hook set '{}' — unknown namespace (expected instance./params.).",
                style("[warn]").yellow(), target
            );
            continue;
        }

        let short = &v[..v.len().min(24)];
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

/// Resolve a `Tapleaf.extra_leaves` spec inside `create_instance` (task 11).
/// Each leaf is the concatenation of its payload items; a typed value item's `value`
/// resolves against the in-progress `fields` first (for sibling computed fields such as
/// `CURRENT_DEBT`), then ctx. Returns `None` if a referenced computed field is not yet
/// available, so the caller defers this field to a later topological pass.
fn resolve_create_instance_leaves(
    specs: &[crate::manifest::TaprootLeafSpec],
    fields: &std::collections::HashMap<String, String>,
    ctx: &ExecutionContext,
    computed_field_names: &std::collections::HashSet<&str>,
) -> Option<Vec<Vec<u8>>> {
    let mut leaves = Vec::with_capacity(specs.len());
    for leaf in specs {
        let mut bytes: Vec<u8> = Vec::new();
        for item in &leaf.payload {
            match item {
                serde_json::Value::String(s) => {
                    match eval::encode_leaf_bytes(&serde_json::json!({ "type": "bytes", "value": s }), s) {
                        Ok(b) => bytes.extend_from_slice(&b),
                        Err(_) => return None,
                    }
                }
                serde_json::Value::Object(m) if m.contains_key("value") => {
                    let vref = m.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    let key = vref
                        .strip_prefix("instance.")
                        .or_else(|| vref.strip_prefix("compile_params."))
                        .or_else(|| vref.strip_prefix("params."))
                        .unwrap_or(vref);
                    // A sibling computed field: only use the in-progress map (never a stale ctx value);
                    // if not ready yet, defer.
                    let resolved: String = if computed_field_names.contains(key) {
                        match fields.get(key) {
                            Some(v) => v.clone(),
                            None => return None,
                        }
                    } else {
                        fields.get(key)
                            .cloned()
                            .or_else(|| ctx.get_compile_param(key).map(str::to_string))
                            .or_else(|| ctx.get_param(key).map(str::to_string))
                            .unwrap_or_else(|| vref.to_string())
                    };
                    match eval::encode_leaf_bytes(item, &resolved) {
                        Ok(b) => bytes.extend_from_slice(&b),
                        Err(_) => return None,
                    }
                }
                _ => return None,
            }
        }
        leaves.push(bytes);
    }
    Some(leaves)
}

fn eval_create_instance_fields(
    ci: &crate::manifest::InstanceCreate,
    ctx: &ExecutionContext,
    manifest_file: &std::path::Path,
    type_hints: &std::collections::HashMap<String, String>,
    network: lwk_wollet::ElementsNetwork,
    verbose: bool,
    opts: impl Into<crate::covenant::CompileOpts>,
) -> std::collections::HashMap<String, String> {
    use crate::manifest::ComputeSpec;

    let opts = opts.into();

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
                ComputeSpec::Expr(expr) => {
                    // `$`-prefixed forms are direct STRING lookups; everything else falls
                    // through to eval_expr_str, which is arithmetic and returns a u64. That
                    // is why a 32-byte id has to arrive by a `$` form: an asset id is not a
                    // number, and the numeric path rejects it.
                    //   $params.X / $instance.X          — a named value in the run context
                    //   $inputs.<input_id>.<field>       — straight off a resolved input
                    expr
                        .strip_prefix("$inputs.")
                        .and_then(|rest| eval::resolve_input_ref(rest, ctx))
                        .or_else(|| {
                            expr.strip_prefix("$params.")
                                .or_else(|| expr.strip_prefix("$instance."))
                                .or_else(|| expr.strip_prefix("$compile_params."))
                                .and_then(|name| {
                                    ctx.get_param(name)
                                        .or_else(|| ctx.get_compile_param(name))
                                        .map(str::to_string)
                                })
                        })
                        .or_else(|| eval::eval_expr_str(expr, ctx).ok())
                }
                ComputeSpec::Compute(compute) => {
                    match compute {
                        crate::manifest::ParamCompute::Tapleaf { simf, params, depends_on, extra_leaves } => {
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

                                    // Resolve optional storage leaves (task 11): each payload item is a
                                    // hex literal or a typed value-ref that resolves against the in-progress
                                    // create_instance `fields` (then ctx). None => storage-less hash.
                                    let leaves_result: Option<Vec<Vec<u8>>> = match extra_leaves {
                                        None => Some(vec![]),
                                        Some(specs) => resolve_create_instance_leaves(specs, &fields, ctx, &computed_field_names),
                                    };
                                    match leaves_result {
                                        None => None, // a leaf ref not yet computed — retry in a later pass
                                        Some(leaves) => {
                                            match covenant::compute_covenant_script_hash_with_leaves(&simf_path, &p, &hints, &leaves, network, &opts) {
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
                            }
                        }
                        crate::manifest::ParamCompute::Expr { expr } => {
                            eval::eval_expr_str(expr, ctx).ok()
                        }
                        crate::manifest::ParamCompute::SimfFn { .. } => {
                            // SimfFn is only valid on action params, not create_instance fields.
                            None
                        }
                        crate::manifest::ParamCompute::Hook {} => {
                            // A hook fills a PARAM, not an instance field. If a hook produced
                            // this value, name the param it wrote: "$params.NAME".
                            println!(
                                "  {} create_instance field '{}' cannot be computed by a hook — reference the param the hook set (e.g. \"$params.NAME\"), or read the input directly (\"$inputs.<id>.issued_asset\").",
                                style("[error]").red(), field_name
                            );
                            None
                        }
                        crate::manifest::ParamCompute::Wallet { .. } => {
                            // Wallet-derived values are resolved for action params in Step 1;
                            // an instance field must be reproducible from the manifest, so a
                            // constructor writes the already-resolved param, not the source.
                            println!(
                                "  {} create_instance field '{}' cannot compute from the wallet —                                  reference the resolved param instead (e.g. \"$params.NAME\").",
                                style("[error]").red(), field_name
                            );
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
        instance_path,          // instance_out_path (read-only actions; unused)
        Some(&state_path),      // state_in_path
        Some(&state_path),      // state_out_path
        &std::collections::HashMap::new(), // provided_inputs (none in headless)
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
    use crate::manifest::{ComputeSpec, InstanceCreate};

    #[test]
    fn outpoint_override_parses_txid_vout() {
        let ov = OutpointOverride::parse_outpoint(
            "fd6c7a7b01c6dee573081c8c69587eefd79df15a833a61e67a6607449418ac90:1",
        )
        .unwrap();
        assert_eq!(ov.txid, "fd6c7a7b01c6dee573081c8c69587eefd79df15a833a61e67a6607449418ac90");
        assert_eq!(ov.vout, 1);
        assert!(ov.amount_sat.is_none() && ov.asset.is_none());
    }

    #[test]
    fn outpoint_override_rejects_bad_forms() {
        // Missing vout.
        assert!(OutpointOverride::parse_outpoint("fd6c7a7b").is_err());
        // Non-numeric vout.
        assert!(OutpointOverride::parse_outpoint(&format!("{}:x", "a".repeat(64))).is_err());
        // Wrong-length / non-hex txid.
        assert!(OutpointOverride::parse_outpoint("zz:0").is_err());
        assert!(OutpointOverride::parse_outpoint(&format!("{}:0", "a".repeat(63))).is_err());
    }

    /// When the action params handler resolves a `wallet_key` param, it must write
    /// the fresh value into BOTH `params` and `compile_params`.  Without the
    /// `compile_params` write, tapleaf hash computations (which read
    /// `ctx.all_compile_params()`) would silently use the stale key loaded from the
    /// previous instance file.
    #[test]
    fn wallet_key_action_param_overwrites_stale_compile_param() {
        let mut ctx = ExecutionContext::new();

        // Simulate template-fields loading from a previous instance file.
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

    /// `$inputs.<id>.<field>` reads an instance field straight off a resolved input, with
    /// no hook in between (examples/deadcat's constructor).
    ///
    /// The assertion that matters is `issued_asset` != `asset`. On an input carrying a new
    /// issuance those are different things — the spent UTXO is L-BTC, the created asset is
    /// not — and confusing them writes L-BTC's id into a field meant to hold the asset the
    /// transaction just created. Nothing downstream would notice: it is a well-formed
    /// 32-byte id, so the covenant addresses simply come out wrong.
    #[test]
    fn create_instance_reads_input_refs_and_distinguishes_issued_asset() {
        const LBTC: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const ISSUED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
        const TOKEN: &str = "3333333333333333333333333333333333333333333333333333333333333333";

        let mut ctx = ExecutionContext::new();
        ctx.set_input(ResolvedInput {
            id: "yes_defining_in".to_string(),
            txid: "aa".repeat(32),
            vout: 0,
            amount_sat: 5_000,
            asset: LBTC.to_string(),
            issuance_entropy: None,
        });
        ctx.set_input_attr("yes_defining_in", "issued_asset", ISSUED);
        ctx.set_input_attr("yes_defining_in", "reissuance_token", TOKEN);

        let mut fields = BTreeMap::new();
        for (name, expr) in [
            ("YES_TOKEN_ASSET", "$inputs.yes_defining_in.issued_asset"),
            ("YES_REISSUANCE_TOKEN", "$inputs.yes_defining_in.reissuance_token"),
            ("SPENT_ASSET", "$inputs.yes_defining_in.asset"),
        ] {
            fields.insert(name.to_string(), ComputeSpec::Expr(expr.to_string()));
        }
        let ci = InstanceCreate { fields };

        let result = eval_create_instance_fields(
            &ci,
            &ctx,
            std::path::Path::new("/nonexistent"),
            &std::collections::HashMap::new(),
            lwk_wollet::ElementsNetwork::LiquidTestnet,
            false,
            false,
        );

        assert_eq!(result.get("YES_TOKEN_ASSET").map(String::as_str), Some(ISSUED));
        assert_eq!(result.get("YES_REISSUANCE_TOKEN").map(String::as_str), Some(TOKEN));
        assert_eq!(
            result.get("SPENT_ASSET").map(String::as_str),
            Some(LBTC),
            "`asset` must stay the SPENT utxo's asset — if this ever aliases to the issued \
             asset, every manifest using `.asset` on a funding input changes meaning",
        );
    }

    /// Build a reissuance input whose `issuance` block carries the given extra keys.
    #[cfg(test)]
    fn reissue_input(extra: serde_json::Value) -> crate::manifest::Input {
        let mut iss = serde_json::json!({ "kind": "reissue", "asset_amount_sat": 10 });
        for (k, v) in extra.as_object().unwrap() {
            iss[k] = v.clone();
        }
        serde_json::from_value(serde_json::json!({
            "id": "yes_reissuance_in",
            "utxo_source": "wallet",
            "issuance": iss
        }))
        .expect("test input should deserialize")
    }

    /// The entropy that mints the real testnet market's YES asset, and the asset id it
    /// must produce. Taken from the live chain (mint tx 14369d64…), so this also pins the
    /// byte order: a block explorer prints this entropy reversed.
    #[cfg(test)]
    const YES_ENTROPY: &str = "f8326827828ee2aab3c4d273fb573a8cf89a401bbc6643637d439ff36c60b6b9";
    #[cfg(test)]
    const YES_ASSET: &str = "3a8b6b466346d9dbfcecd8c8d7b0c1873aee4e00fd5df0d95086a3f7eecd5a39";

    #[test]
    fn issuance_entropy_comes_from_the_reference() {
        let mut ctx = ExecutionContext::new();
        ctx.set_compile_param("YES_ISSUANCE_ENTROPY", YES_ENTROPY);

        let inp = reissue_input(serde_json::json!({ "entropy": "instance.YES_ISSUANCE_ENTROPY" }));
        let entropy = resolve_issuance_entropy(&inp, &ctx)
            .expect("should resolve")
            .expect("should be present");
        assert_eq!(hex_bytes(&entropy), YES_ENTROPY);
    }

    #[test]
    fn issuance_entropy_cross_check_rejects_a_reversed_value() {
        // The failure this check exists for. A byte-reversed entropy — the order every
        // block explorer prints — is still 32 well-formed bytes, still builds, still
        // broadcasts, and reissues a completely different asset.
        let mut reversed = pset_builder::decode_entropy_hex(YES_ENTROPY).unwrap();
        reversed.reverse();

        let mut ctx = ExecutionContext::new();
        ctx.set_compile_param("YES_ISSUANCE_ENTROPY", hex_bytes(&reversed));
        ctx.set_compile_param("YES_TOKEN_ASSET", YES_ASSET);

        let inp = reissue_input(serde_json::json!({
            "entropy": "instance.YES_ISSUANCE_ENTROPY",
            "issued_asset": "instance.YES_TOKEN_ASSET"
        }));
        let err = resolve_issuance_entropy(&inp, &ctx).expect_err("reversed entropy must fail");
        assert!(
            err.to_string().contains("does not produce the declared asset"),
            "unexpected error: {err}"
        );

        // …and the correct order passes the same check.
        ctx.set_compile_param("YES_ISSUANCE_ENTROPY", YES_ENTROPY);
        assert!(resolve_issuance_entropy(&inp, &ctx).unwrap().is_some());
    }

    #[test]
    fn issuance_entropy_falls_back_to_provided_inputs() {
        // The old path stays working: no `entropy` reference, value from the instance
        // file's provided_inputs.
        let mut ctx = ExecutionContext::new();
        ctx.set_input(ResolvedInput {
            id: "yes_reissuance_in".to_string(),
            txid: "aa".repeat(32),
            vout: 0,
            amount_sat: 1,
            asset: "bb".repeat(32),
            issuance_entropy: Some(YES_ENTROPY.to_string()),
        });
        let entropy = resolve_issuance_entropy(&reissue_input(serde_json::json!({})), &ctx)
            .expect("should resolve")
            .expect("should be present");
        assert_eq!(hex_bytes(&entropy), YES_ENTROPY);
    }

    #[test]
    fn issuance_entropy_absent_is_reported_not_guessed() {
        let ctx = ExecutionContext::new();
        assert!(
            resolve_issuance_entropy(&reissue_input(serde_json::json!({})), &ctx)
                .expect("missing entropy is not an error, it is a None")
                .is_none()
        );
    }

    #[test]
    fn an_unresolvable_entropy_reference_is_an_error() {
        // Distinct from "absent": the manifest named a value and it was not there, which
        // is a broken manifest rather than a missing instance field.
        let ctx = ExecutionContext::new();
        let inp = reissue_input(serde_json::json!({ "entropy": "instance.NOT_SET" }));
        let err = resolve_issuance_entropy(&inp, &ctx).expect_err("should error");
        assert!(err.to_string().contains("does not resolve"), "unexpected: {err}");
    }

    /// A 32-byte id can only travel by a `$` form. The bare-expression path is arithmetic
    /// (`eval_expr` returns u64), which is exactly why `$inputs.` had to be added rather
    /// than relying on the existing evaluator.
    #[test]
    fn a_bare_input_expression_cannot_carry_an_asset_id() {
        let mut ctx = ExecutionContext::new();
        ctx.set_input_attr("in0", "issued_asset", &"22".repeat(32));

        assert!(
            eval::eval_expr_str("inputs.in0.issued_asset", &ctx).is_err(),
            "the numeric evaluator must reject a 32-byte id rather than mangle it",
        );
        assert_eq!(
            eval::resolve_input_ref("in0.issued_asset", &ctx).as_deref(),
            Some("22".repeat(32).as_str()),
            "the string path must return it intact",
        );
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
            ComputeSpec::Expr("$params.MY_KEY".to_string()),
        );
        let ci = InstanceCreate { fields };

        let result = eval_create_instance_fields(
            &ci,
            &ctx,
            std::path::Path::new("/nonexistent"),
            &std::collections::HashMap::new(),
            lwk_wollet::ElementsNetwork::LiquidTestnet,
            false,
            false,
        );

        assert_eq!(
            result.get("MY_KEY").map(String::as_str),
            Some("fresh"),
            "$params.KEY expressions must prefer params over compile_params",
        );
    }

    /// Task 07 — the lending_v3 manifest's `CreateOffer.create_instance` nested
    /// AssetAuth/AssetAuthVault cov-hash chain must reproduce the on-chain lending
    /// (collateral) covenant of a real offer. Drives the ACTUAL manifest file's
    /// create_instance with live offer 43ab4efe's resolved values, then folds the 2
    /// storage leaves and asserts the out[5] scriptPubKey matches byte-for-byte.
    #[test]
    fn lending_v3_create_offer_reproduces_live_offer_out5() {
        use crate::manifest::Manifest;

        // Locate examples/lending_v3 relative to the crate (CARGO_MANIFEST_DIR = txmanifest_lib).
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/lending_v3/txmanifest.json");
        let raw = std::fs::read_to_string(&manifest_path).expect("read lending_v3 manifest");
        let manifest: Manifest = Manifest::from_json_str(&raw).expect("parse lending_v3 manifest");
        let net = lwk_wollet::ElementsNetwork::LiquidTestnet;

        let (_class, _class_def, action) = manifest
            .find_template_action("CreateOffer")
            .expect("CreateOffer action exists");
        let ci = action.create_instance.as_ref().expect("CreateOffer has create_instance");

        // Live offer 43ab4efe parameters (same as examples/lending_recon.rs).
        let collateral = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
        let principal = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";
        let borrower_nft = "78d61185c79f855fac51a87c191b00266f02d28752f50b3d9092ccf6b978181e";
        let lender_nft = "213462821a5cdb96f435f5ea6597e8937359d6fd5a64b6ac8ef4262bc279fcfb";
        let protocol_fee = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";
        let out5 = "51201ae9d30d7a31f1393a289196a4dacc01fac95459540895db448aeca47fbd84e1";

        // Populate ctx as if inputs + action params were resolved.
        let mut ctx = ExecutionContext::new();
        // $params.* (offer terms + keeper + factory + zero-hash default)
        ctx.set_param("COLLATERAL_ASSET_ID", collateral);
        ctx.set_param("PRINCIPAL_ASSET_ID", principal);
        ctx.set_param("PROTOCOL_FEE_KEEPER_ASSET_ID", protocol_fee);
        ctx.set_param("COLLATERAL_AMOUNT", "21000");
        ctx.set_param("PRINCIPAL_AMOUNT", "1000");
        ctx.set_param("PRINCIPAL_INTEREST_RATE", "10000");
        ctx.set_param("LOAN_EXPIRATION_TIME", "2536857");
        ctx.set_param("ZERO_HASH", &"00".repeat(32));
        ctx.set_param("FACTORY_ASSET_ID", "0101010101010101010101010101010101010101010101010101010101010101");
        // Protocol message-type tag constant (a param default in the manifest; here set directly
        // as a compile param since the test drives create_instance without Step 1).
        ctx.set_compile_param("LENDING_PROGRAM_ID", "f80c6162");
        // $instance.* (issuance-resolved NFT asset ids)
        ctx.set_compile_param("BORROWER_NFT_ASSET_ID", borrower_nft);
        ctx.set_compile_param("LENDER_NFT_ASSET_ID", lender_nft);

        // Type hints from the template field + action param declarations.
        let mut hints: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        if let Some((_, template_def, _)) = manifest.find_template_action("CreateOffer") {
            for (fname, fdef) in &template_def.fields {
                hints.insert(fname.clone(), fdef.type_.clone());
            }
        }
        if let Some(params) = &action.params {
            for (pname, pdef) in params {
                hints.entry(pname.clone()).or_insert_with(|| pdef.type_.clone());
            }
        }

        let fields = eval_create_instance_fields(
            ci, &ctx, &manifest_path, &hints, net, false, true,
        );

        // The 5 nested hashes must match the independently-verified recon values.
        assert_eq!(fields.get("FINALIZED_LENDER_VAULT_COV_HASH").map(String::as_str),
            Some("686766f422bca200851234cc787902d105ae91e7acc97977ff32b84263b286c6"), "F_lender");
        assert_eq!(fields.get("LENDER_VAULT_COV_HASH").map(String::as_str),
            Some("54a0e779d4324f5f5ef45e0e615b34eb0091c4b88a08bfee3ce4fe0e760cf872"), "A_lender");
        assert_eq!(fields.get("FINALIZED_PROTOCOL_FEE_VAULT_COV_HASH").map(String::as_str),
            Some("9c2a221b8457112075bf80b46b32878e34a023e3f67653c54d041897926a49bb"), "F_proto");
        assert_eq!(fields.get("PROTOCOL_FEE_VAULT_COV_HASH").map(String::as_str),
            Some("2a887b2cbd477c94f4b14c03d32216ccb0faeb087ab08fd3862e105ddcdf5e71"), "A_proto");
        assert_eq!(fields.get("PRINCIPAL_OUTPUT_SCRIPT_HASH").map(String::as_str),
            Some("88c5f4e880bed03eb4e59f99f8d60534cd8c3dc9b405f2af72da2b8c358c7eb6"), "principal_out");

        // CURRENT_DEBT (task 10): principal + principal*bps/10000 = 1000 + 1000*10000/10000 = 2000.
        assert_eq!(fields.get("CURRENT_DEBT").map(String::as_str), Some("2000"), "current_debt");

        // Drive the ACTUAL lending_collateral utxo_type end-to-end: fold the computed create_instance
        // fields into ctx, resolve the utxo_type's compile_params + computed storage leaves, and
        // reproduce out[5]. This exercises the real extra_leaves wiring (task 10), not a hand copy.
        for (k, v) in &fields {
            ctx.set_compile_param(k, v);
        }
        let ut = manifest
            .utxo_type("lending_collateral")
            .expect("lending_collateral utxo_type exists");
        let base_params: std::collections::HashMap<String, String> =
            ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let (lending_params, lending_hints) = apply_utxo_compile_params(&base_params, &hints, ut);
        let leaves = ut.resolve_extra_leaf_payloads(&ctx).expect("resolve storage leaves");
        assert_eq!(leaves.len(), 2, "two storage slots");
        assert_eq!(leaves[0], vec![0u8; 32], "slot0 = is_active zero");
        let mut expect_slot1 = vec![0u8; 32];
        expect_slot1[24..32].copy_from_slice(&2000u64.to_be_bytes());
        assert_eq!(leaves[1], expect_slot1, "slot1 = current_debt u64 BE, right-aligned in 32 bytes");

        let lending_simf = manifest_path.parent().unwrap().join("lending.simf");
        let addr = crate::covenant::compute_covenant_address(
            &lending_simf, &lending_params, &lending_hints, &leaves, net, true,
        ).expect("compute lending covenant address");
        assert_eq!(format!("{:x}", addr.script_pubkey()), out5,
            "manifest utxo_type (create_instance chain + computed storage leaves) must reproduce live offer out[5]");

        // Task 11: LENDING_COV_SCRIPT_HASH = sha256(out[5] spk, WITH storage), computed via a
        // tapleaf-over-lending.simf that folds the same storage leaves.
        assert_eq!(fields.get("LENDING_COV_SCRIPT_HASH").map(String::as_str),
            Some("2f40d78cbd15bd847a995719d707e623520dae2e223f66d77a76599f95685b19"),
            "LENDING_COV_SCRIPT_HASH must equal sha256(out[5] scriptPubKey)");
        // Cross-check: it really is sha256 of the out[5] spk we just reproduced.
        {
            use lwk_wollet::elements::hashes::{sha256, Hash};
            let h = sha256::Hash::hash(addr.script_pubkey().as_bytes()).to_byte_array();
            let hh: String = h.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(fields.get("LENDING_COV_SCRIPT_HASH").map(String::as_str), Some(hh.as_str()));
        }
        // The lender_nft_script_auth covenant (out[3]) compiles from that script hash.
        let sa_ut = manifest.utxo_type("lender_nft_script_auth").expect("script_auth utxo_type");
        let (sa_params, sa_hints) = apply_utxo_compile_params(&{
            let m: std::collections::HashMap<String, String> =
                ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            m
        }, &hints, sa_ut);
        assert_eq!(sa_params.get("SCRIPT_HASH").map(String::as_str),
            Some("2f40d78cbd15bd847a995719d707e623520dae2e223f66d77a76599f95685b19"),
            "script_auth SCRIPT_HASH resolves to the with-storage lending cov hash");
        let sa_simf = manifest_path.parent().unwrap().join("script_auth.simf");
        crate::covenant::compute_covenant_address(&sa_simf, &sa_params, &sa_hints, &[], net, true)
            .expect("out[3] lender_nft_script_auth covenant address compiles");

        // out[4]: the wired OP_RETURN output reproduces the on-chain 50-byte lending metadata
        // (same offer params as examples/opreturn_recon.rs → identical payload).
        let op_out = action.outputs.as_ref().unwrap().iter()
            .find(|o| o.id == "creation_op_return").expect("creation_op_return output");
        let op_data = op_out.data.as_ref().expect("op_return has data");
        let op_bytes = eval::eval_op_return_data(op_data, &ctx, &hints)
            .expect("eval op_return");
        let op_hex: String = op_bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(op_bytes.len(), 50, "lending creation metadata is 50 bytes");
        assert_eq!(op_hex,
            "f80c6162a5502895799e276b4af246c821423b4ed5ec5e6b4e6df7a861606939d9a2fc38e80300000000000099b526001027",
            "out[4] OP_RETURN must reproduce the on-chain lending metadata for offer 43ab4efe");

        // out[1]: factory covenant recreated resolves to the fixed (2,0) factory address even in
        // the offer context (ISSUING_UTXOS_COUNT/REISSUANCE_FLAGS come from lending_contract fields).
        let fac_ut = manifest.utxo_type("issuance_factory").expect("issuance_factory utxo_type");
        let fac_base: std::collections::HashMap<String, String> =
            ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let (fac_params, fac_hints) = apply_utxo_compile_params(&fac_base, &hints, fac_ut);
        let fac_simf = manifest_path.parent().unwrap().join("issuance_factory.simf");
        let fac_addr = crate::covenant::compute_covenant_address(&fac_simf, &fac_params, &fac_hints, &[], net, true)
            .expect("factory covenant address");
        assert_eq!(format!("{:x}", fac_addr.script_pubkey()),
            "5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b",
            "out[1] factory covenant must be the fixed (2,0) address");

        // --- AcceptOffer (task 08) covenant outputs ---
        // ctx already holds every computed create_instance field as a compile param (set above).
        let base_now: std::collections::HashMap<String, String> =
            ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        // out[0]: active lending covenant (storage slot0 = is_active=1) — the storage-transition
        // address from examples/lending_active_recon.rs.
        let act_ut = manifest.utxo_type("lending_collateral_active").expect("active utxo_type");
        let (act_params, act_hints) = apply_utxo_compile_params(&base_now, &hints, act_ut);
        let act_leaves = act_ut.resolve_extra_leaf_payloads(&ctx).expect("active storage leaves");
        assert_eq!(act_leaves[0][31], 1, "active slot0 byte[31] = 1 (is_active)");
        let act_addr = crate::covenant::compute_covenant_address(
            &lending_simf, &act_params, &act_hints, &act_leaves, net, true).expect("active address");
        assert_eq!(format!("{:x}", act_addr.script_pubkey()),
            "51202451da2d003a9fd5cffe1ed523cded17cda7a39604f02642d56d503bdef3eb77",
            "AcceptOffer out[0] active lending covenant address (storage transition)");
        assert_ne!(act_addr.script_pubkey(), addr.script_pubkey(), "active differs from pending");

        // out[1]: principal AssetAuth(borrower_nft, 1, false) — cross-check sha256(spk) == PRINCIPAL_OUTPUT_SCRIPT_HASH.
        let pa_ut = manifest.utxo_type("principal_asset_auth").expect("principal_asset_auth utxo_type");
        let (pa_params, pa_hints) = apply_utxo_compile_params(&base_now, &hints, pa_ut);
        let pa_simf = manifest_path.parent().unwrap().join("asset_auth.simf");
        let pa_addr = crate::covenant::compute_covenant_address(&pa_simf, &pa_params, &pa_hints, &[], net, true)
            .expect("principal_asset_auth address");
        {
            use lwk_wollet::elements::hashes::{sha256, Hash};
            let pa_hash: String = sha256::Hash::hash(pa_addr.script_pubkey().as_bytes())
                .to_byte_array().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(pa_hash, fields.get("PRINCIPAL_OUTPUT_SCRIPT_HASH").cloned().unwrap(),
                "AcceptOffer out[1] AssetAuth spk hash must equal PRINCIPAL_OUTPUT_SCRIPT_HASH");
        }
    }

    /// Task 08 — RepayLoan (full repayment, NoRepayments phase).
    ///
    /// The lending covenant bakes `FINALIZED_LENDER_VAULT_COV_HASH` /
    /// `FINALIZED_PROTOCOL_FEE_VAULT_COV_HASH` into its params and, on the full-repayment path,
    /// enforces them as the script hashes of out[1]/out[2] (`validate_vaults` →
    /// `ensure_output_script_hash`). Those two hashes are themselves anchored: they are part of
    /// the create_instance chain that reproduces live offer 43ab4efe's out[5] byte-exactly
    /// (see `lending_v3_create_offer_reproduces_live_offer_out5`).
    ///
    /// So a repayment output is provably correct iff the utxo_type behind it compiles to a
    /// scriptPubKey whose sha256 equals that baked-in hash. That is what this asserts — an
    /// independent check of the vault utxo_types' param wiring (keeper/supplier roles, burn
    /// flags, is_active, the zero finalized-hash) against the anchored values.
    #[test]
    fn lending_v3_repay_loan_vault_outputs_match_covenant_hashes() {
        use crate::manifest::Manifest;
        use lwk_wollet::elements::hashes::{sha256, Hash};

        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/lending_v3/txmanifest.json");
        let raw = std::fs::read_to_string(&manifest_path).expect("read lending_v3 manifest");
        let manifest: Manifest = Manifest::from_json_str(&raw).expect("parse lending_v3 manifest");
        let net = lwk_wollet::ElementsNetwork::LiquidTestnet;

        let (_class, _class_def, create) = manifest
            .find_template_action("CreateOffer")
            .expect("CreateOffer action exists");
        let ci = create.create_instance.as_ref().expect("CreateOffer has create_instance");

        // Same live-offer 43ab4efe parameters as the out[5] reproduction test, so the vault
        // hashes computed here are the verified ones.
        let mut ctx = ExecutionContext::new();
        ctx.set_param("COLLATERAL_ASSET_ID", "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49");
        ctx.set_param("PRINCIPAL_ASSET_ID", "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5");
        ctx.set_param("PROTOCOL_FEE_KEEPER_ASSET_ID", "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5");
        ctx.set_param("COLLATERAL_AMOUNT", "21000");
        ctx.set_param("PRINCIPAL_AMOUNT", "1000");
        ctx.set_param("PRINCIPAL_INTEREST_RATE", "10000");
        ctx.set_param("LOAN_EXPIRATION_TIME", "2536857");
        ctx.set_param("ZERO_HASH", &"00".repeat(32));
        ctx.set_param("FACTORY_ASSET_ID", "0101010101010101010101010101010101010101010101010101010101010101");
        ctx.set_compile_param("LENDING_PROGRAM_ID", "f80c6162");
        ctx.set_compile_param("BORROWER_NFT_ASSET_ID", "78d61185c79f855fac51a87c191b00266f02d28752f50b3d9092ccf6b978181e");
        ctx.set_compile_param("LENDER_NFT_ASSET_ID", "213462821a5cdb96f435f5ea6597e8937359d6fd5a64b6ac8ef4262bc279fcfb");

        let mut hints: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        if let Some((_, template_def, _)) = manifest.find_template_action("CreateOffer") {
            for (fname, fdef) in &template_def.fields {
                hints.insert(fname.clone(), fdef.type_.clone());
            }
        }
        if let Some(params) = &create.params {
            for (pname, pdef) in params {
                hints.entry(pname.clone()).or_insert_with(|| pdef.type_.clone());
            }
        }

        let fields = eval_create_instance_fields(ci, &ctx, &manifest_path, &hints, net, false, true);
        for (k, v) in &fields {
            ctx.set_compile_param(k, v);
        }

        // ZERO_HASH must reach the instance: the vault utxo_types reference it by name to pick up
        // its declared `bytes32` type. Inlined as a literal it would infer as u64 (all digits).
        assert_eq!(fields.get("ZERO_HASH").map(String::as_str), Some("00".repeat(32).as_str()),
            "ZERO_HASH must be carried into the instance for the vault utxo_types to type it");
        assert_eq!(hints.get("ZERO_HASH").map(String::as_str), Some("bytes32"),
            "ZERO_HASH must be declared bytes32, not left to value-based inference");

        let base: std::collections::HashMap<String, String> =
            ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let vault_simf = manifest_path.parent().unwrap().join("asset_auth_vault.simf");

        // out[1] — the lender's finalized vault.
        let lender_ut = manifest.utxo_type("lender_vault_finalized").expect("lender_vault_finalized utxo_type");
        let (lp, lh) = apply_utxo_compile_params(&base, &hints, lender_ut);
        assert_eq!(lh.get("FINALIZED_VAULT_COV_HASH").map(String::as_str), Some("bytes32"),
            "the zero finalized-hash must carry a bytes32 hint into the compiler");
        let lender_addr = crate::covenant::compute_covenant_address(&vault_simf, &lp, &lh, &[], net, true)
            .expect("lender_vault_finalized address compiles");
        let lender_hash: String = sha256::Hash::hash(lender_addr.script_pubkey().as_bytes())
            .to_byte_array().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(Some(lender_hash.as_str()), fields.get("FINALIZED_LENDER_VAULT_COV_HASH").map(String::as_str),
            "RepayLoan out[1] spk hash must equal the FINALIZED_LENDER_VAULT_COV_HASH the covenant enforces");

        // out[2] — the protocol-fee finalized vault (keeper burn = false, unlike the lender's).
        let proto_ut = manifest.utxo_type("protocol_fee_vault_finalized").expect("protocol_fee_vault_finalized utxo_type");
        let (pp, ph) = apply_utxo_compile_params(&base, &hints, proto_ut);
        let proto_addr = crate::covenant::compute_covenant_address(&vault_simf, &pp, &ph, &[], net, true)
            .expect("protocol_fee_vault_finalized address compiles");
        let proto_hash: String = sha256::Hash::hash(proto_addr.script_pubkey().as_bytes())
            .to_byte_array().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(Some(proto_hash.as_str()), fields.get("FINALIZED_PROTOCOL_FEE_VAULT_COV_HASH").map(String::as_str),
            "RepayLoan out[2] spk hash must equal the FINALIZED_PROTOCOL_FEE_VAULT_COV_HASH the covenant enforces");

        // The two vaults must be distinct covenants — a keeper/burn-flag mix-up would collapse them.
        assert_ne!(lender_hash, proto_hash, "lender and protocol-fee vaults must be different covenants");

        // The repayment split must reproduce the covenant's own arithmetic, floor-division and all:
        //   total_fee     = 1000 * 10000/10000       = 1000
        //   protocol_fee  = 1000 * 1000/10000        =  100   (10% of the interest)
        //   lender share  = CURRENT_DEBT(2000) - 100 = 1900
        // Sum must be exactly the debt — the covenant's split_repayment_by_fees leaves no dust.
        let (_, _, repay) = manifest.find_template_action("RepayLoan").expect("RepayLoan action exists");
        let rp = repay.params.as_ref().expect("RepayLoan has params");
        let formula_of = |name: &str| {
            rp.get(name)
                .and_then(|p| p.compute.as_ref())
                .and_then(|c| c.as_expr())
                .map(str::to_string)
                .unwrap_or_else(|| panic!("{name} has a compute expression"))
        };
        let protocol_fee = crate::eval::eval_expr_str(&formula_of("TOTAL_PROTOCOL_FEE"), &ctx)
            .expect("TOTAL_PROTOCOL_FEE evaluates");
        let lender_amount = crate::eval::eval_expr_str(&formula_of("LENDER_VAULT_AMOUNT"), &ctx)
            .expect("LENDER_VAULT_AMOUNT evaluates");
        assert_eq!(protocol_fee, "100", "protocol fee = 10% of the 1000 interest");
        assert_eq!(lender_amount, "1900", "lender receives the debt less the protocol fee");
        let debt: u64 = fields.get("CURRENT_DEBT").unwrap().parse().unwrap();
        assert_eq!(
            protocol_fee.parse::<u64>().unwrap() + lender_amount.parse::<u64>().unwrap(),
            debt,
            "the two vault outputs must account for the whole debt exactly"
        );

        // The FullRepayment witness carries the debt, so its `instance.CURRENT_DEBT` ref must
        // resolve to a literal the SimplicityHL value parser can read.
        let offer_in = repay.inputs.as_ref().unwrap().iter()
            .find(|i| i.id == "active_offer_in").expect("active_offer_in input");
        let wits = crate::eval::resolve_witness_refs(
            offer_in.witnesses.as_ref().expect("active_offer_in has witnesses"), &ctx);
        assert_eq!(wits["PATH"]["value"].as_str(), Some("Right(Left(Right(2000)))"),
            "FullRepayment witness must resolve to PATH::Right(Left(Right(current_debt)))");

        // The offer input spends the ACTIVE covenant AcceptOffer produced — same storage, so the
        // same address (this is what the covenant re-derives from the witness debt and compares).
        let act_ut = manifest.utxo_type("lending_collateral_active").expect("active utxo_type");
        let (ap, ah) = apply_utxo_compile_params(&base, &hints, act_ut);
        let act_leaves = act_ut.resolve_extra_leaf_payloads(&ctx).expect("active storage leaves");
        let lending_simf = manifest_path.parent().unwrap().join("lending.simf");
        let act_addr = crate::covenant::compute_covenant_address(&lending_simf, &ap, &ah, &act_leaves, net, true)
            .expect("active address");
        assert_eq!(format!("{:x}", act_addr.script_pubkey()),
            "51202451da2d003a9fd5cffe1ed523cded17cda7a39604f02642d56d503bdef3eb77",
            "RepayLoan in[1] must be the same active covenant AcceptOffer created");
    }

    /// Task 10 — a computed u64 storage leaf encodes right-aligned, big-endian, in a
    /// 32-byte slot (the lending covenant's `current_debt` layout).
    #[test]
    fn encode_leaf_value_u64_be_padded_to_32() {
        let mut ctx = ExecutionContext::new();
        ctx.set_compile_param("CURRENT_DEBT", "2000");
        let item = serde_json::json!({
            "value": "instance.CURRENT_DEBT", "type": "u64", "endian": "be", "pad_to": 32, "align": "right"
        });
        let bytes = crate::eval::encode_leaf_value(&item, &ctx).expect("encode leaf");
        let mut expect = vec![0u8; 32];
        expect[24..32].copy_from_slice(&2000u64.to_be_bytes());
        assert_eq!(bytes, expect);
        // Left-aligned puts the value first.
        let item_left = serde_json::json!({
            "value": "8", "type": "u8", "pad_to": 4, "align": "left"
        });
        assert_eq!(crate::eval::encode_leaf_value(&item_left, &ctx).unwrap(), vec![8u8, 0, 0, 0]);
    }

    /// The dex (Tessera) example's `MakeOffer.create_instance` must compute MAKER_SPK
    /// from MAKER_PUB_KEY, and that hash must be what the offer address commits to.
    ///
    /// This is the load-bearing link in the example: tessera.simf enforces payment to a
    /// scriptPubKey *hash*, so the settle output can only be built if MAKER_SPK is derived
    /// from the same program the payout output targets — not pasted in by hand. Constructors
    /// pre-compute create_instance tapleaf fields into compile params before the PSET is
    /// built, which is what makes the offer address resolvable in the same transaction.
    #[test]
    fn dex_make_offer_computes_maker_spk_and_offer_address() {
        use crate::manifest::Manifest;
        use lwk_wollet::elements::hashes::{sha256, Hash};

        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/dex/txmanifest.json");
        let raw = std::fs::read_to_string(&manifest_path).expect("read dex manifest");
        let manifest: Manifest = Manifest::from_json_str(&raw).expect("parse dex manifest");
        let net = lwk_wollet::ElementsNetwork::LiquidTestnet;

        let (_class, template_def, action) = manifest
            .find_template_action("MakeOffer")
            .expect("MakeOffer method exists");
        let ci = action.create_instance.as_ref().expect("MakeOffer has create_instance");

        // Track the manifest's own settings — debug symbols change the CMR, so a hardcoded
        // value here would verify a compilation mode the CLI never actually runs.
        let compile_opts = manifest.compile_opts();
        let maker_pub_key = "e1512ae2f5b4ee8c12e9c57ccd0943273c6256f496516d3aefeaa16c32d3c05b";
        let lbtc_testnet = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
        let usdt_ish = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";

        // Populate ctx as if Step 1 had prompted for the offer terms.
        let mut ctx = ExecutionContext::new();
        ctx.set_param("OFFER_ASSET_ID", usdt_ish);
        ctx.set_param("OFFER_AMOUNT", "100000");
        ctx.set_param("ASSET_B", lbtc_testnet);
        ctx.set_param("AMOUNT_B", "50000");
        ctx.set_param("MAKER_PUB_KEY", maker_pub_key);
        ctx.set_param("TIMEOUT", "2000000");
        ctx.set_param("MAX_FEE", "5000");

        // Type hints from the template field + method param declarations (mirrors Step 7's pre-pass).
        let mut hints: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (fname, fdef) in &template_def.fields {
            hints.insert(fname.clone(), fdef.type_.clone());
        }
        if let Some(params) = &action.params {
            for (pname, pdef) in params {
                hints.entry(pname.clone()).or_insert_with(|| pdef.type_.clone());
            }
        }

        let fields = eval_create_instance_fields(ci, &ctx, &manifest_path, &hints, net, false, &compile_opts);

        // MAKER_SPK is sha256 of the maker_payout covenant's scriptPubKey — verify against the
        // program itself rather than a copied constant.
        let payout_simf = manifest_path.parent().unwrap().join("maker_payout.simf");
        let payout_params: std::collections::HashMap<String, String> =
            [("PUB_KEY".to_string(), maker_pub_key.to_string())].into_iter().collect();
        let payout_hints: std::collections::HashMap<String, String> =
            [("PUB_KEY".to_string(), "pubkey".to_string())].into_iter().collect();
        let payout_addr = crate::covenant::compute_covenant_address(
            &payout_simf, &payout_params, &payout_hints, &[], net, &compile_opts,
        )
        .expect("maker_payout covenant address compiles");
        let expect_spk_hash: String =
            sha256::Hash::hash(payout_addr.script_pubkey().as_bytes())
                .to_byte_array()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();

        assert_eq!(
            fields.get("MAKER_SPK").map(String::as_str),
            Some(expect_spk_hash.as_str()),
            "create_instance MAKER_SPK must equal sha256(maker_payout scriptPubKey) for MAKER_PUB_KEY"
        );

        // The plain `$params.*` fields carry through untouched.
        assert_eq!(fields.get("AMOUNT_B").map(String::as_str), Some("50000"));
        assert_eq!(fields.get("TIMEOUT").map(String::as_str), Some("2000000"));
        assert_eq!(fields.get("MAX_FEE").map(String::as_str), Some("5000"));

        // Drive the ACTUAL tessera_offer utxo_type end-to-end: fold the computed fields back into
        // ctx (as the constructor pre-pass does) and resolve the offer covenant address.
        for (k, v) in &fields {
            ctx.set_compile_param(k, v);
        }
        let ut = manifest.utxo_type("tessera_offer").expect("tessera_offer utxo_type exists");
        let base: std::collections::HashMap<String, String> =
            ctx.all_compile_params().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let (offer_params, offer_hints) = apply_utxo_compile_params(&base, &hints, ut);

        assert_eq!(
            offer_params.get("MAKER_SPK").map(String::as_str),
            Some(expect_spk_hash.as_str()),
            "the offer covenant compiles against the computed MAKER_SPK"
        );
        let offer_simf = manifest_path.parent().unwrap().join("tessera.simf");
        let offer_addr = crate::covenant::compute_covenant_address(
            &offer_simf, &offer_params, &offer_hints, &[], net, &compile_opts,
        )
        .expect("tessera_offer covenant address compiles from create_instance output");

        // Changing an offer term must move the offer address (the terms live in the tapleaf).
        let mut bumped = offer_params.clone();
        bumped.insert("AMOUNT_B".to_string(), "50001".to_string());
        let bumped_addr = crate::covenant::compute_covenant_address(
            &offer_simf, &bumped, &offer_hints, &[], net, &compile_opts,
        )
        .expect("bumped offer address compiles");
        assert_ne!(
            offer_addr.script_pubkey(),
            bumped_addr.script_pubkey(),
            "an offer's price is committed to by its address"
        );

        // But asset A and its amount are NOT terms — the covenant never inspects them on the
        // settle path, so the address must not move when they change (see tessera.simf).
        let mut other_side = offer_params.clone();
        other_side.insert("OFFER_ASSET_ID".to_string(), lbtc_testnet.to_string());
        other_side.insert("OFFER_AMOUNT".to_string(), "999".to_string());
        let other_side_addr = crate::covenant::compute_covenant_address(
            &offer_simf, &other_side, &offer_hints, &[], net, &compile_opts,
        )
        .expect("offer address compiles with a different asset A");
        assert_eq!(
            offer_addr.script_pubkey(),
            other_side_addr.script_pubkey(),
            "asset A and its amount are deliberately not offer terms — the offer is \
             'whatever sits in this UTXO, for AMOUNT_B of ASSET_B'"
        );
    }
}
