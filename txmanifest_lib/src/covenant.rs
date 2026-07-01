use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use lwk_wollet::elements::{
    hashes::{sha256, Hash as ElementsHash, HashEngine},
    secp256k1_zkp::Secp256k1,
    taproot::{ControlBlock, LeafVersion, TaprootMerkleBranch, TaprootSpendInfo},
    Address, AddressParams, BlockHash, Script, Transaction, TxOut,
};
use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::simplicity::bit_machine::{ExecTracker, FrameIter, NodeOutput};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::BitMachine;
use simplicityhl::{simplicity, Arguments, CompiledProgram, WitnessTypes, WitnessValues};

/// Signs `(key_label, kind, sighash)` and returns a 64-byte Schnorr signature.
type SigSigner = dyn Fn(&str, &str, &[u8; 32]) -> Result<[u8; 64]>;

/// Simplicity leaf version for Elements/Liquid.
fn simplicity_leaf_version() -> LeafVersion {
    simplicity::leaf_version()
}

/// The NUMS (Nothing-Up-My-Sleeve) internal key for covenant Taproot outputs.
/// = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
const NUMS_KEY_BYTES: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Compile a `.simf` file and return the Simplicity tapleaf hash (32 bytes, natural byte order).
///
/// This is an intermediate taproot value (TapLeafHash). To get the value that the Simplicity
/// `input_script_hash` jet returns for a UTXO at that covenant's address, use
/// `compute_covenant_script_hash` instead.
pub fn compute_tapleaf_hash(
    simf_path: &Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
) -> Result<[u8; 32]> {
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    let args_json = build_args_json(compile_params, type_hints)?;
    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    let compiled =
        CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
            .map_err(|e| anyhow::anyhow!("SimplicityHL compilation failed: {e}"))?;
    let commit = compiled.commit();
    let cmr = commit.cmr();
    let leaf_ver = simplicity_leaf_version();
    let script = Script::from(cmr.as_ref().to_vec());
    let tap_leaf = lwk_wollet::elements::taproot::TapLeafHash::from_script(&script, leaf_ver);
    Ok(tap_leaf.to_byte_array())
}

/// Compile a `.simf` file and return SHA256(scriptPubKey) of the resulting P2TR covenant address.
///
/// This is the value returned by the Simplicity `input_script_hash` jet for any UTXO locked at
/// that covenant address, and therefore the correct value for `*_COV_HASH` instance fields used
/// by `script_auth.simf` and similar programs that verify co-spending.
pub fn compute_covenant_script_hash(
    simf_path: &Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
    network: lwk_wollet::ElementsNetwork,
) -> Result<[u8; 32]> {
    let addr = compute_covenant_address(simf_path, compile_params, type_hints, &[], network)?;
    let spk = addr.script_pubkey();
    Ok(sha256::Hash::hash(spk.as_bytes()).to_byte_array())
}

/// Compile the SimplicityHL program from a `.simf` file and compile_params map.
///
/// Returns `Ok(())` if compilation succeeds. Used for the Step 9 dry-run check.
pub fn check_compile(
    simf_path: &Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
) -> Result<()> {
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    let args_json = build_args_json(compile_params, type_hints)?;
    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
        .map_err(|e| anyhow::anyhow!("SimplicityHL compilation failed: {e}"))?;
    Ok(())
}

/// Compile a named function from a `.simf` file and return the [`CompiledFunction`].
///
/// Used by the `simf_fn` compute hook to validate compilation before execution.
///
/// Requires the `simplicity_eval` feature: depends on the custom SimplicityHL
/// `TemplateProgram::compile_function` API, which is not in master.
#[cfg(feature = "simplicity_eval")]
pub fn compile_simf_function(
    simf_path: &Path,
    fn_name: Option<&str>,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
) -> Result<simplicityhl::CompiledFunction> {
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    let args_json = build_args_json(compile_params, type_hints)?;
    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    let template = simplicityhl::TemplateProgram::new(source, Box::new(ElementsJetHinter::new()))
        .map_err(|e| anyhow::anyhow!("SimplicityHL parse/analyse failed: {e}"))?;
    template
        .compile_function(fn_name, arguments)
        .map_err(|e| anyhow::anyhow!("SimplicityHL function compile failed: {e}"))
}

/// Compile and execute a named function from a `.simf` file, returning the output as a hex string.
///
/// `compile_params` supplies `param::` constants baked in at compile time.
/// `input_hex` is the runtime input value as a hex string (e.g. `"0d2a4b..."` or `"0x0d2a4b..."`).
/// The input is parsed against the function's `source_type()`; the output is returned as
/// the SimplicityHL value's string representation (typically `"0x..."` for integer/byte types).
///
/// Requires the `simplicity_eval` feature: depends on the custom SimplicityHL
/// `compile_function` API, which is not in master.
#[cfg(feature = "simplicity_eval")]
pub fn execute_simf_function(
    simf_path: &Path,
    fn_name: Option<&str>,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
    input_hex: &str,
) -> Result<String> {
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    let args_json = build_args_json(compile_params, type_hints)?;
    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    let template = simplicityhl::TemplateProgram::new(source, Box::new(ElementsJetHinter::new()))
        .map_err(|e| anyhow::anyhow!("SimplicityHL parse/analyse failed: {e}"))?;

    // Compile first to get the source type for input parsing.
    let compiled = template
        .compile_function(fn_name, arguments.clone())
        .map_err(|e| anyhow::anyhow!("SimplicityHL function compile failed: {e}"))?;

    let source_type = compiled.source_type();
    let input_value = simplicityhl::Value::parse_from_str(input_hex, &source_type)
        .map_err(|e| anyhow::anyhow!("Cannot parse input '{input_hex}' as {source_type}: {e}"))?;

    let output = compiled
        .execute(input_value)
        .map_err(|e| anyhow::anyhow!("SimplicityHL function execution failed: {e}"))?;

    // Strip the "0x" prefix SimplicityHL adds to integer/byte values.
    let s = output.to_string();
    Ok(s.strip_prefix("0x").unwrap_or(&s).to_string())
}

/// Stub used when the `simplicity_eval` feature is disabled. The `simf_fn` compute
/// hook relies on the custom SimplicityHL `compile_function` API, which is not in
/// master, so it fails at runtime here. Rebuild with `--features simplicity_eval`.
#[cfg(not(feature = "simplicity_eval"))]
pub fn execute_simf_function(
    _simf_path: &Path,
    _fn_name: Option<&str>,
    _compile_params: &HashMap<String, String>,
    _type_hints: &HashMap<String, String>,
    _input_hex: &str,
) -> Result<String> {
    anyhow::bail!(
        "The `simf_fn` compute hook requires the `simplicity_eval` feature \
         (custom SimplicityHL compile_function API, not in master). \
         Rebuild with `--features simplicity_eval`."
    )
}

// ── Jet debugger ─────────────────────────────────────────────────────────────

struct JetRecord {
    jet: String,
    success: bool,
    input_value: String,
    output_value: String,
    /// For eq_* jets: (lhs, rhs) so mismatches stand out.
    equality_check: Option<(String, String)>,
}

struct JetTracker(Vec<JetRecord>);

impl ExecTracker for JetTracker {
    fn visit_node(
        &mut self,
        node: &simplicity::RedeemNode,
        mut input: FrameIter,
        output: NodeOutput,
    ) {
        use simplicity::node::Inner;
        let Inner::Jet(jet) = node.inner() else {
            return;
        };

        let input_value = simplicity::Value::from_padded_bits(&mut input, &node.arrow().source)
            .expect("valid bit machine value");

        let (success, output_value) = match output {
            NodeOutput::NonTerminal => return,
            NodeOutput::JetFailed => (false, simplicity::Value::unit()),
            NodeOutput::Success(mut iter) => (
                true,
                simplicity::Value::from_padded_bits(&mut iter, &node.arrow().target)
                    .expect("valid bit machine value"),
            ),
        };

        let jet_name = jet.to_string();
        let equality_check = if jet_name.strip_prefix("eq_").is_some() {
            input_value
                .as_product()
                .map(|(l, r)| (l.to_value().to_string(), r.to_value().to_string()))
        } else {
            None
        };

        self.0.push(JetRecord {
            jet: jet_name,
            success,
            input_value: input_value.to_string(),
            output_value: output_value.to_string(),
            equality_check,
        });
    }
}

/// Execute a Simplicity covenant program against the given transaction environment (dry-run).
///
/// Compiles the program, builds the two-leaf Taproot control block, constructs the
/// `ElementsEnv`, satisfies the program with the provided witnesses, then runs the BitMachine.
/// Returns `Ok(())` if execution succeeds, or an error with details on failure.
///
/// `witnesses` is the raw manifest-file witness map for this input (the `witnesses` field on an
/// `Input` object).  Only entries with `"type": "simplicityhl"` are used; the type for each
/// witness is looked up from the compiled program's own `WitnessTypes` so callers never need to
/// specify SimplicityHL type syntax.
#[allow(clippy::too_many_arguments)]
pub fn dry_run_covenant(
    simf_path: &Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
    extra_leaf_payloads: &[Vec<u8>],
    witnesses: Option<&serde_json::Value>,
    sig_signer: Option<&SigSigner>,
    tx: Arc<Transaction>,
    witness_utxos: &[TxOut],
    input_index: u32,
    genesis_hash: BlockHash,
    debug_jets: bool,
) -> Result<()> {
    // Debug: all prints go to stdout so they interleave correctly with lifecycle output.
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(
        out,
        "[dry_run] ── input_index={input_index}  simf={}",
        simf_path.display()
    )
    .ok();
    writeln!(out, "[dry_run] compile_params ({}):", compile_params.len()).ok();
    for (k, v) in compile_params {
        writeln!(out, "[dry_run]   {k} = {v}").ok();
    }
    writeln!(
        out,
        "[dry_run] witnesses: {}",
        witnesses
            .map(|w| serde_json::to_string_pretty(w).unwrap_or_else(|_| "?".into()))
            .unwrap_or_else(|| "(none)".into())
    )
    .ok();

    // tx structure
    writeln!(
        out,
        "[dry_run] tx: {} inputs, {} outputs",
        tx.input.len(),
        tx.output.len()
    )
    .ok();
    writeln!(out, "[dry_run] witness_utxos[{}]:", witness_utxos.len()).ok();
    for (i, utxo) in witness_utxos.iter().enumerate() {
        use lwk_wollet::elements::hashes::{sha256, Hash as _, HashEngine as _};
        let script_bytes = utxo.script_pubkey.as_bytes();
        let script_hex: String = script_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut engine = sha256::HashEngine::default();
        engine.input(script_bytes);
        let script_sha256: String = sha256::Hash::from_engine(engine)
            .to_byte_array()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        writeln!(
            out,
            "[dry_run]   utxo[{i}] script={script_hex}  sha256={script_sha256}"
        )
        .ok();
    }
    writeln!(out, "[dry_run] tx outputs:").ok();
    for (i, txout) in tx.output.iter().enumerate() {
        let script_bytes = txout.script_pubkey.as_bytes();
        let script_hex: String = script_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let is_op_return = script_bytes.first() == Some(&0x6a);
        writeln!(
            out,
            "[dry_run]   out[{i}] script={script_hex}  op_return={is_op_return}"
        )
        .ok();
    }
    drop(out);

    // Compile
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    let args_json = build_args_json(compile_params, type_hints)?;
    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    let compiled =
        CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
            .map_err(|e| anyhow::anyhow!("SimplicityHL compilation failed: {e}"))?;
    let abi_meta = compiled
        .generate_abi_meta()
        .map_err(|e| anyhow::anyhow!("Cannot get ABI metadata: {e}"))?;

    {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(
            out,
            "[dry_run] witness_types ({}):",
            abi_meta.witness_types.iter().count()
        )
        .ok();
        for (name, ty) in abi_meta.witness_types.iter() {
            writeln!(out, "[dry_run]   {name}: {ty}").ok();
        }
    }

    // Get CMR; tapscript leaf = CMR (32 bytes) as required by Elements Simplicity validator
    let commit = compiled.commit();
    let script_cmr = commit.cmr();

    // Compute Simplicity tapleaf hash from CMR
    let leaf_ver = simplicity_leaf_version();
    let tap_leaf_hash: [u8; 32] = {
        let script = Script::from(script_cmr.as_ref().to_vec());
        lwk_wollet::elements::taproot::TapLeafHash::from_script(&script, leaf_ver).to_byte_array()
    };

    // Fold in extra leaves to build merkle root; collect sibling hashes for the Simplicity leaf.
    let secp = Secp256k1::new();
    let nums_key = lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&NUMS_KEY_BYTES)
        .context("Invalid NUMS key bytes")?;

    let mut merkle_root_bytes = tap_leaf_hash;
    let mut sibling_hashes: Vec<sha256::Hash> = Vec::new();
    for payload in extra_leaf_payloads {
        let extra = tapdata_hash(payload);
        sibling_hashes.push(sha256::Hash::from_byte_array(extra));
        merkle_root_bytes = build_tapbranch(merkle_root_bytes, extra);
    }

    let tap_node = tap_node_hash_from_bytes(merkle_root_bytes);
    let spend_info = TaprootSpendInfo::new_key_spend(&secp, nums_key, Some(tap_node));
    let parity = spend_info.output_key_parity();
    let merkle_branch = TaprootMerkleBranch::from_inner(sibling_hashes)
        .map_err(|_| anyhow::anyhow!("TaprootMerkleBranch is too long"))?;

    let control_block = ControlBlock {
        leaf_version: leaf_ver,
        output_key_parity: parity,
        internal_key: nums_key,
        merkle_branch,
    };

    // Convert TxOut UTXOs to ElementsUtxo
    let utxos: Vec<ElementsUtxo> = witness_utxos
        .iter()
        .map(|txout| ElementsUtxo::from(txout.clone()))
        .collect();

    // Build environment
    let env = ElementsEnv::new(
        tx,
        utxos,
        input_index,
        script_cmr,
        control_block,
        None,
        genesis_hash,
    );

    // Inject computed signatures (e.g. sig_hash_all) before building witness values.
    let injected: Option<serde_json::Value>;
    let effective_witnesses = if let (Some(signer), Some(w)) = (sig_signer, witnesses) {
        injected = Some(
            inject_computed_signatures(w, &env, signer)
                .context("Failed to compute Signature witnesses")?,
        );
        injected.as_ref()
    } else {
        witnesses
    };

    let witness_values =
        build_witness_values_from_types(effective_witnesses, &abi_meta.witness_types)
            .context("Cannot build witness values")?;

    {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(
            out,
            "[dry_run] WitnessValues ({}):",
            witness_values.iter().count()
        )
        .ok();
        for (name, val) in witness_values.iter() {
            writeln!(out, "[dry_run]   {name} = {val}").ok();
        }
    }

    if debug_jets {
        // Satisfy without the environment so SimplicityHL skips the internal execution
        // it uses for pruning — that internal run is what normally swallows the error
        // before we can attach our tracker.  Without pruning, all branches survive in
        // the redeem node; execution still follows only the live path (PATH = Left never
        // reaches the SIGNATURE branch), so the trace is accurate.
        let satisfied = compiled
            .satisfy_with_env(witness_values, None)
            .map_err(|e| anyhow::anyhow!("Cannot prepare witnesses for jet trace: {e}"))?;
        let redeem = satisfied.redeem();
        let mut mac = BitMachine::for_program(redeem)
            .map_err(|e| anyhow::anyhow!("BitMachine setup failed: {e}"))?;
        let mut tracker = JetTracker(vec![]);
        let result = mac.exec_with_tracker(redeem, &env, &mut tracker);

        // Print trace unconditionally — we want it even on failure.
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(
            out,
            "[jets] ── {} jet call(s) for input #{input_index}:",
            tracker.0.len()
        )
        .ok();
        for (i, rec) in tracker.0.iter().enumerate() {
            if let Some((lhs, rhs)) = &rec.equality_check {
                let matched = if lhs == rhs { "yes" } else { "NO " };
                writeln!(
                    out,
                    "[jets] #{i:>3}  {:<35}  {}  lhs={}  rhs={}  match={matched}{}",
                    rec.jet,
                    if rec.success { "ok  " } else { "FAIL" },
                    lhs,
                    rhs,
                    if !rec.success { " ← FAILED" } else { "" },
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "[jets] #{i:>3}  {:<35}  {}  in={}  out={}{}",
                    rec.jet,
                    if rec.success { "ok  " } else { "FAIL" },
                    rec.input_value,
                    rec.output_value,
                    if !rec.success { " ← FAILED" } else { "" },
                )
                .ok();
            }
        }
        drop(out);

        result.map_err(|e| anyhow::anyhow!("Simplicity execution failed: {e}"))?;
    } else {
        let satisfied = compiled
            .satisfy_with_env(witness_values, Some(&env))
            .map_err(|e| anyhow::anyhow!("Covenant satisfaction failed: {e}"))?;
        let redeem = satisfied.redeem();
        let mut mac = BitMachine::for_program(redeem)
            .map_err(|e| anyhow::anyhow!("BitMachine setup failed: {e}"))?;
        mac.exec(redeem, &env)
            .map_err(|e| anyhow::anyhow!("Simplicity execution failed: {e}"))?;
    }

    Ok(())
}

/// Finalize a Simplicity covenant PSET input by setting `final_script_witness`.
///
/// Compiles the program, satisfies it with the real transaction environment (which also prunes
/// the program), then serializes the pruned program + witness and injects the correct 4-item
/// Simplicity tapscript witness stack: `[witness, prog, cmr, control_block]`.
///
/// Call this for every covenant input BEFORE `wollet.finalize()` so the wallet finalizer only
/// has to handle wallet (non-Simplicity) inputs.
/// Inject computed signatures into the witnesses map for any `"type": "Signature"` entries.
///
/// For each such entry, the `sig_type` field selects the hash to sign (`"sig_hash_all"`
/// → `env.c_tx_env().sighash_all()`).  The `signer` callback receives
/// `(witness_name, sig_type, hash)` and returns a 64-byte BIP340 signature.
/// The entry is replaced with a `"type": "simplicityhl"` entry whose value is the hex-
/// encoded signature, ready for `build_witness_values_from_types`.
fn inject_computed_signatures(
    witnesses: &serde_json::Value,
    env: &ElementsEnv<Arc<Transaction>>,
    signer: &SigSigner,
) -> Result<serde_json::Value> {
    let mut obj = witnesses.as_object().cloned().unwrap_or_default();
    for (name, spec) in witnesses.as_object().into_iter().flatten() {
        if spec.get("type").and_then(|v| v.as_str()) != Some("Signature") {
            continue;
        }
        let sig_type = spec
            .get("sig_type")
            .and_then(|v| v.as_str())
            .unwrap_or("sig_hash_all");
        let hash: [u8; 32] = match sig_type {
            "sig_hash_all" => {
                let h = env.c_tx_env().sighash_all();
                let slice: &[u8] = h.as_ref();
                slice.try_into().expect("sha256 hash is 32 bytes")
            }
            other => anyhow::bail!("Unknown sig_type '{other}' for witness '{name}'"),
        };
        let sig_bytes = signer(name, sig_type, &hash)
            .with_context(|| format!("Failed to sign witness '{name}'"))?;
        let hex_str: String = sig_bytes.iter().map(|b| format!("{b:02x}")).collect();
        obj.insert(
            name.clone(),
            serde_json::json!({
                "type": "simplicityhl",
                "value": format!("0x{hex_str}"),
            }),
        );
    }
    Ok(serde_json::Value::Object(obj))
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_covenant_input(
    simf_path: &Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
    extra_leaf_payloads: &[Vec<u8>],
    witnesses: Option<&serde_json::Value>,
    sig_signer: Option<&SigSigner>,
    tx: Arc<Transaction>,
    witness_utxos: &[TxOut],
    input_index: u32,
    genesis_hash: BlockHash,
    pset_input: &mut lwk_wollet::elements::pset::Input,
) -> Result<()> {
    // Compile
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    let args_json = build_args_json(compile_params, type_hints)?;
    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    let compiled =
        CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
            .map_err(|e| anyhow::anyhow!("SimplicityHL compilation failed: {e}"))?;
    let abi_meta = compiled
        .generate_abi_meta()
        .map_err(|e| anyhow::anyhow!("Cannot get ABI metadata: {e}"))?;

    // CMR and tapscript leaf (CMR as 32-byte script)
    let commit = compiled.commit();
    let script_cmr = commit.cmr();
    let leaf_ver = simplicity_leaf_version();
    let tap_leaf_hash: [u8; 32] = {
        let script = Script::from(script_cmr.as_ref().to_vec());
        lwk_wollet::elements::taproot::TapLeafHash::from_script(&script, leaf_ver).to_byte_array()
    };

    // Build control block (same logic as dry_run_covenant)
    let secp = Secp256k1::new();
    let nums_key = lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&NUMS_KEY_BYTES)
        .context("Invalid NUMS key bytes")?;

    let mut merkle_root_bytes = tap_leaf_hash;
    let mut sibling_hashes: Vec<sha256::Hash> = Vec::new();
    for payload in extra_leaf_payloads {
        let extra = tapdata_hash(payload);
        sibling_hashes.push(sha256::Hash::from_byte_array(extra));
        merkle_root_bytes = build_tapbranch(merkle_root_bytes, extra);
    }

    let tap_node = tap_node_hash_from_bytes(merkle_root_bytes);
    let spend_info = TaprootSpendInfo::new_key_spend(&secp, nums_key, Some(tap_node));
    let parity = spend_info.output_key_parity();
    let merkle_branch = TaprootMerkleBranch::from_inner(sibling_hashes)
        .map_err(|_| anyhow::anyhow!("TaprootMerkleBranch is too long"))?;

    let control_block = ControlBlock {
        leaf_version: leaf_ver,
        output_key_parity: parity,
        internal_key: nums_key,
        merkle_branch,
    };

    // Build environment
    let utxos: Vec<ElementsUtxo> = witness_utxos
        .iter()
        .map(|txout| ElementsUtxo::from(txout.clone()))
        .collect();
    let env = ElementsEnv::new(
        tx,
        utxos,
        input_index,
        script_cmr,
        control_block.clone(),
        None,
        genesis_hash,
    );

    // Inject any computed signatures (e.g. sig_hash_all) before building witness values.
    let injected: Option<serde_json::Value>;
    let effective_witnesses = if let (Some(signer), Some(w)) = (sig_signer, witnesses) {
        injected = Some(
            inject_computed_signatures(w, &env, signer)
                .context("Failed to compute Signature witnesses")?,
        );
        injected.as_ref()
    } else {
        witnesses
    };

    let witness_values =
        build_witness_values_from_types(effective_witnesses, &abi_meta.witness_types)
            .context("Cannot build witness values")?;

    // Satisfy with the real environment — this populates witnesses AND prunes the program
    let satisfied = compiled
        .satisfy_with_env(witness_values, Some(&env))
        .map_err(|e| anyhow::anyhow!("Covenant satisfaction failed for finalization: {e}"))?;

    // Serialize pruned program + witness bits
    let (prog, witness) = satisfied.redeem().to_vec_with_witness();
    let cmr_bytes = script_cmr.as_ref().to_vec();
    let cb_bytes = control_block.serialize();

    // Simplicity tapscript witness: [witness_bits, program_bytes, cmr_script, control_block]
    pset_input.final_script_witness = Some(vec![witness, prog, cmr_bytes, cb_bytes]);
    Ok(())
}

/// Compute the Elements P2TR address for a Simplicity covenant.
///
/// The address encodes a Taproot tree whose root is built by starting with the Simplicity
/// program leaf and folding in each extra leaf via TapBranch in declaration order.
///
/// Internal key: the standard NUMS point (no key-path spend).
pub fn compute_covenant_address(
    simf_path: &Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
    extra_leaf_payloads: &[Vec<u8>],
    network: lwk_wollet::ElementsNetwork,
) -> Result<Address> {
    eprintln!(
        "[covenant] compute_covenant_address: {} extra leaf(s), simf={}",
        extra_leaf_payloads.len(),
        simf_path.display()
    );
    eprintln!(
        "[covenant] compile_params ({} entries):",
        compile_params.len()
    );
    for (k, v) in compile_params {
        let preview = if v.len() > 20 {
            format!("{}…", &v[..20])
        } else {
            v.clone()
        };
        eprintln!("[covenant]   {k} = {preview}");
    }

    // Build Arguments from compile_params (serde JSON round-trip)
    let args_json = build_args_json(compile_params, type_hints)?;
    eprintln!("[covenant] args_json:\n{args_json}");

    let arguments: Arguments = serde_json::from_str(&args_json)
        .with_context(|| format!("Failed to parse Arguments from JSON:\n{args_json}"))?;
    eprintln!("[covenant] Arguments parsed OK");

    // Compile the simf file
    let source = std::fs::read_to_string(simf_path)
        .with_context(|| format!("Cannot read simf file: {}", simf_path.display()))?;
    eprintln!("[covenant] simf source loaded ({} bytes)", source.len());

    let compiled =
        CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
            .map_err(|e| anyhow::anyhow!("SimplicityHL compilation failed: {e}"))?;
    eprintln!("[covenant] SimplicityHL compilation OK");

    // Get CMR; tapscript leaf = CMR (32 bytes) as required by Elements Simplicity validator
    let commit = compiled.commit();
    let cmr = commit.cmr();
    eprintln!("[covenant] cmr: {}", hex_bytes(cmr.as_ref()));

    // Compute the Simplicity tapleaf hash from CMR
    let leaf_ver = simplicity_leaf_version();
    let script = Script::from(cmr.as_ref().to_vec());
    let tap_leaf = lwk_wollet::elements::taproot::TapLeafHash::from_script(&script, leaf_ver);
    let tap_leaf_hash: [u8; 32] = tap_leaf.to_byte_array();
    eprintln!("[covenant] tap_leaf_hash: {}", hex_bytes(&tap_leaf_hash));

    // Build taproot tree: start from the Simplicity leaf, fold in extra leaves via TapBranch.
    let secp = Secp256k1::new();
    let nums_key = lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&NUMS_KEY_BYTES)
        .context("Invalid NUMS key bytes")?;

    let merkle_root = {
        let mut root = tap_leaf_hash;
        for (i, payload) in extra_leaf_payloads.iter().enumerate() {
            let extra = tapdata_hash(payload);
            eprintln!(
                "[covenant] extra_leaf[{i}] payload={} hash={}",
                hex_bytes(payload),
                hex_bytes(&extra)
            );
            root = build_tapbranch(root, extra);
        }
        root
    };
    eprintln!("[covenant] merkle_root: {}", hex_bytes(&merkle_root));

    let tap_node_hash = tap_node_hash_from_bytes(merkle_root);

    // Compute the tweaked output key using the tap node hash as the merkle root.
    let addr_params = network_to_params(network);
    let address = Address::p2tr(&secp, nums_key, Some(tap_node_hash), None, addr_params);
    eprintln!("[covenant] address: {address}");

    Ok(address)
}

/// Build `WitnessValues` from a manifest-file witness map using the compiled program's own
/// `WitnessTypes` so the caller never needs to specify SimplicityHL type syntax.
///
/// Only entries with `"type": "simplicityhl"` are processed.  Any witness declared in the
/// program but not supplied in `witnesses` is filled with a zero value — these are typically
/// signing witnesses (e.g. SIGNATURE) that live on branches pruned by the tx environment and
/// are never checked by the BitMachine; we need _some_ concrete value so `populate_witnesses`
/// can run before pruning.
fn build_witness_values_from_types(
    witnesses: Option<&serde_json::Value>,
    witness_types: &WitnessTypes,
) -> Result<WitnessValues> {
    use simplicityhl::parse::ParseFromStr as _;
    use simplicityhl::str::WitnessName;
    use simplicityhl::value::Value;

    let obj = witnesses.and_then(|v| v.as_object());

    let mut map = std::collections::HashMap::new();

    // Parse user-provided simplicityhl witnesses.
    if let Some(obj) = obj {
        for (name, def) in obj {
            if def.get("type").and_then(|v| v.as_str()) != Some("simplicityhl") {
                continue;
            }
            let value_str = match def.get("value").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let witness_name = WitnessName::parse_from_str(name)
                .map_err(|e| anyhow::anyhow!("Invalid witness name '{name}': {e}"))?;
            let Some(ty) = witness_types.get(&witness_name) else {
                continue;
            };
            let value = Value::parse_from_str(value_str, ty).map_err(|e| {
                anyhow::anyhow!("Cannot parse witness '{name}' = '{value_str}': {e}")
            })?;
            map.insert(witness_name, value);
        }
    }

    // Fill zero values for any witness not supplied — these live on pruned branches
    // (e.g. SIGNATURE on the cancel path when PATH = Left) and are never executed,
    // but populate_witnesses needs a concrete bit-vector for every node before pruning.
    for (name, ty) in witness_types.iter() {
        if !map.contains_key(name) {
            map.insert(name.shallow_clone(), zero_value_for_type(ty));
        }
    }

    Ok(WitnessValues::from(map))
}

/// Produce a structurally-valid zero/default value for a SimplicityHL `ResolvedType`.
/// Used to satisfy `populate_witnesses` for witnesses on pruned branches.
fn zero_value_for_type(ty: &simplicityhl::ResolvedType) -> simplicityhl::Value {
    use simplicityhl::num::U256;
    use simplicityhl::types::{TypeInner, UIntType};
    use simplicityhl::value::{UIntValue, Value, ValueConstructible};

    match ty.as_inner() {
        TypeInner::Boolean => Value::from(false),
        TypeInner::UInt(uint_ty) => Value::from(match uint_ty {
            UIntType::U1 => UIntValue::U1(0),
            UIntType::U2 => UIntValue::U2(0),
            UIntType::U4 => UIntValue::U4(0),
            UIntType::U8 => UIntValue::U8(0),
            UIntType::U16 => UIntValue::U16(0),
            UIntType::U32 => UIntValue::U32(0),
            UIntType::U64 => UIntValue::U64(0),
            UIntType::U128 => UIntValue::U128(0),
            UIntType::U256 => UIntValue::U256(U256::from_byte_array([0u8; 32])),
        }),
        TypeInner::Tuple(elements) => Value::tuple(elements.iter().map(|e| zero_value_for_type(e))),
        TypeInner::Either(left, right) => Value::left(zero_value_for_type(left), (**right).clone()),
        TypeInner::Option(inner) => Value::none((**inner).clone()),
        TypeInner::Array(elem, size) => {
            let zeros: Vec<Value> = (0..*size).map(|_| zero_value_for_type(elem)).collect();
            Value::array(zeros, (**elem).clone())
        }
        TypeInner::List(elem, bound) => Value::list(std::iter::empty(), (**elem).clone(), *bound),
        _ => Value::unit(),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Map a manifest `type` string to a SimplicityHL primitive type name.
fn manifest_to_simf_type(manifest_type: &str) -> Option<&'static str> {
    match manifest_type {
        "u8" => Some("u8"),
        "u16" | "liquid.u16" => Some("u16"),
        "u32" => Some("u32"),
        "u64" => Some("u64"),
        "liquid.asset_id" | "bytes32" => Some("u256"),
        "pubkey" => Some("u256"),
        "bool" | "u1" => Some("bool"),
        _ => None,
    }
}

/// Fallback name-convention inference when no manifest type hint is available.
fn infer_simf_type(name: &str) -> Option<&'static str> {
    let upper = name.to_uppercase();
    if upper.ends_with("_ASSET")
        || upper.ends_with("_TOKEN_ASSET")
        || upper.ends_with("_ASSET_ID")
        || upper.ends_with("_REISSUANCE_TOKEN")
        || upper.ends_with("_PUBLIC_KEY")
        || upper.ends_with("ORACLE_PUBLIC_KEY")
    {
        return Some("u256");
    }
    if upper.ends_with("_PER_TOKEN")
        || upper.ends_with("_AMOUNT_SAT")
        || upper.ends_with("_AMOUNT")
        || upper.ends_with("_SATS")
    {
        return Some("u64");
    }
    if upper.ends_with("_TIME") || upper.ends_with("_HEIGHT") || upper.ends_with("_BLOCK") {
        return Some("u32");
    }
    if upper.starts_with("WITH_") || upper.ends_with("_ENABLED") || upper.ends_with("_FLAG") {
        return Some("bool");
    }
    None
}

/// Infer a SimplicityHL type from a literal value string as a last resort.
/// Handles booleans and plain decimal integers.
fn infer_simf_type_from_value(value: &str) -> Option<&'static str> {
    if value == "true" || value == "false" {
        return Some("bool");
    }
    if !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()) {
        return Some("u64");
    }
    None
}

/// Fallback heuristic: returns true for compile_param names that *look* like asset IDs
/// (display-backward format), used only when no `liquid.asset_id` manifest type is declared.
/// Prefer declaring `"type": "liquid.asset_id"` in the manifest — the name check is a
/// best-effort fallback and misses unconventional names such as a bare `ASSET_ID`.
fn is_asset_id_param(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.ends_with("_ASSET")
        || upper.ends_with("_TOKEN_ASSET")
        || upper.ends_with("_ASSET_ID")
        || upper.ends_with("_REISSUANCE_TOKEN")
}

/// Build a JSON string suitable for `Arguments::deserialize` from a `HashMap<String, String>`.
///
/// Types are resolved first from `type_hints` (manifest-declared types), then by naming convention.
/// Params that cannot be typed are skipped with a warning.
///
/// Params declared with the manifest type `liquid.asset_id` are byte-reversed from Elements
/// display-backward to natural (MSB-first) order as required by SimplicityHL jets. Other u256
/// params (`bytes32` hashes, `pubkey`) are passed without reversal. For untyped params the
/// reversal decision falls back to the [`is_asset_id_param`] name heuristic.
fn build_args_json(
    params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
) -> Result<String> {
    let mut entries = Vec::new();
    for (name, value) in params {
        // Resolve the SimplicityHL type AND whether this value is a display-order
        // asset ID that must be byte-reversed. The declared manifest type
        // (`liquid.asset_id`) is the authoritative signal for reversal; the param
        // name is only consulted as a fallback when no type was declared.
        let (ty, is_asset_id): (&'static str, bool) = if let Some(manifest_type) =
            type_hints.get(name)
        {
            match manifest_to_simf_type(manifest_type) {
                Some(t) => (t, manifest_type == "liquid.asset_id"),
                None => {
                    eprintln!("[covenant] Unknown manifest type '{manifest_type}' for '{name}' — skipping");
                    continue;
                }
            }
        } else {
            match infer_simf_type(name).or_else(|| infer_simf_type_from_value(value)) {
                Some(t) => (t, is_asset_id_param(name)),
                None => {
                    eprintln!("[covenant] Cannot infer SimplicityHL type for '{name}' (value={value:?}) — skipping");
                    continue;
                }
            }
        };
        let formatted_value = if matches!(ty, "u8" | "u16" | "u32" | "u64" | "bool") {
            // decimal integer or boolean literal — pass as-is
            value.clone()
        } else if is_asset_id {
            // Asset ID in display-backward format → reverse to natural byte order for SimplicityHL.
            let hex = value.trim_start_matches("0x").trim_start_matches("0X");
            let padded = format!("{:0>64}", hex);
            let reversed: String = padded
                .as_bytes()
                .chunks(2)
                .rev()
                .flat_map(|pair| pair.iter().map(|&b| b as char))
                .collect();
            format!("0x{reversed}")
        } else {
            // u256 non-asset-ID (e.g. public key): natural byte order, no reversal.
            let hex = value.trim_start_matches("0x").trim_start_matches("0X");
            format!("0x{:0>64}", hex)
        };
        entries.push(format!(
            r#"  "{name}": {{ "value": "{formatted_value}", "type": "{ty}" }}"#
        ));
    }
    Ok(format!("{{\n{}\n}}", entries.join(",\n")))
}

/// Tagged SHA256 for "TapData/elements": SHA256(SHA256(tag) || SHA256(tag) || data).
fn tapdata_hash(data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapData/elements");
    let mut engine = sha256::HashEngine::default();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// TapBranch hash (Elements variant): SHA256(SHA256(tag) || SHA256(tag) || min(a,b) || max(a,b)).
fn build_tapbranch(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapBranch/elements");
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut engine = sha256::HashEngine::default();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(&lo);
    engine.input(&hi);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn tap_node_hash_from_bytes(bytes: [u8; 32]) -> lwk_wollet::elements::taproot::TapNodeHash {
    // TapNodeHash is the type used as the merkle root in p2tr().
    // It can be constructed from raw bytes via the Hash trait.
    lwk_wollet::elements::taproot::TapNodeHash::from_byte_array(bytes)
}

fn network_to_params(network: lwk_wollet::ElementsNetwork) -> &'static AddressParams {
    match network {
        lwk_wollet::ElementsNetwork::Liquid => &AddressParams::LIQUID,
        lwk_wollet::ElementsNetwork::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
        lwk_wollet::ElementsNetwork::ElementsRegtest { .. } => &AddressParams::ELEMENTS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adapted last-will book example must compile with the three pubkey params
    /// wired in. Guards the tutorial's `.simf` against compiler/syntax drift.
    #[test]
    fn last_will_book_example_compiles() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let simf_path = crate_dir.join("../examples/last_will/last_will.simf");

        let dummy_key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let mut params = HashMap::new();
        params.insert("INHERITOR_PUB_KEY".to_string(), dummy_key.to_string());
        params.insert("HOT_PUB_KEY".to_string(), dummy_key.to_string());
        params.insert("COLD_PUB_KEY".to_string(), dummy_key.to_string());
        params.insert("INHERIT_BLOCKS".to_string(), "25920".to_string());

        let mut hints = HashMap::new();
        hints.insert("INHERITOR_PUB_KEY".to_string(), "pubkey".to_string());
        hints.insert("HOT_PUB_KEY".to_string(), "pubkey".to_string());
        hints.insert("COLD_PUB_KEY".to_string(), "pubkey".to_string());
        hints.insert("INHERIT_BLOCKS".to_string(), "u16".to_string());

        check_compile(&simf_path, &params, &hints).expect("last_will.simf should compile");
    }

    /// `build_args_json` must include params whose type is inferred by naming convention
    /// (`WITH_*` → bool, `_AMOUNT` → u64) AND params whose type can only be determined
    /// from the literal value (`"true"/"false"` → bool, decimal string → u64).
    /// Without the value-based fallback, params like `WITH_ASSET_BURN: "true"` are silently
    /// dropped, causing SimplicityHL to fail with "Parameter … is missing an argument".
    #[test]
    fn build_args_json_handles_literal_bool_and_int_params() {
        let mut params = HashMap::new();
        params.insert("WITH_ASSET_BURN".to_string(), "true".to_string()); // name-inferred bool
        params.insert("SOME_FLAG".to_string(), "false".to_string()); // value-inferred bool
        params.insert("ASSET_AMOUNT".to_string(), "42".to_string()); // name-inferred u64
        params.insert("RAW_COUNT".to_string(), "7".to_string()); // value-inferred u64

        let hints = HashMap::new();
        let json = build_args_json(&params, &hints).expect("build_args_json");

        assert!(
            json.contains(r#""WITH_ASSET_BURN""#),
            "WITH_ASSET_BURN must not be dropped"
        );
        assert!(
            json.contains(r#""SOME_FLAG""#),
            "SOME_FLAG must not be dropped"
        );
        assert!(
            json.contains(r#""ASSET_AMOUNT""#),
            "ASSET_AMOUNT must not be dropped"
        );
        assert!(
            json.contains(r#""RAW_COUNT""#),
            "RAW_COUNT must not be dropped"
        );
        assert!(
            json.contains(r#""type": "bool""#),
            "bool type must appear in output"
        );
        assert!(
            json.contains(r#""type": "u64""#),
            "u64 type must appear in output"
        );
    }

    /// The `liquid.asset_id` manifest type — not the param name — must drive byte-reversal.
    /// Regression for `ASSET_ID`: a bare name the `is_asset_id_param` heuristic misses, yet
    /// declared `liquid.asset_id`, so it must still be reversed. A `bytes32` hash and a
    /// `pubkey` of the same width must NOT be reversed.
    #[test]
    fn asset_id_reversal_is_driven_by_declared_type_not_name() {
        let asset = "857e17708b6ec9ad0e2cc50a8faa8140b7ad253029443513850f14e4a95589b4";
        let reversed = "b48955a9e4140f85133544293025adb74081aa8f0ac52c0eadc96e8b70177e85";

        let mut params = HashMap::new();
        params.insert("ASSET_ID".to_string(), asset.to_string()); // bare name, heuristic misses it
        params.insert("SOME_HASH".to_string(), asset.to_string()); // bytes32 — must NOT reverse
        params.insert("SOME_KEY".to_string(), asset.to_string()); // pubkey — must NOT reverse

        let mut hints = HashMap::new();
        hints.insert("ASSET_ID".to_string(), "liquid.asset_id".to_string());
        hints.insert("SOME_HASH".to_string(), "bytes32".to_string());
        hints.insert("SOME_KEY".to_string(), "pubkey".to_string());

        let json = build_args_json(&params, &hints).expect("build_args_json");

        assert!(
            json.contains(&format!(r#""ASSET_ID": {{ "value": "0x{reversed}""#)),
            "ASSET_ID (liquid.asset_id) must be byte-reversed; got:\n{json}"
        );
        assert!(
            json.contains(&format!(r#""SOME_HASH": {{ "value": "0x{asset}""#)),
            "bytes32 hash must NOT be reversed; got:\n{json}"
        );
        assert!(
            json.contains(&format!(r#""SOME_KEY": {{ "value": "0x{asset}""#)),
            "pubkey must NOT be reversed; got:\n{json}"
        );
    }

    /// `infer_simf_type` covers naming conventions; `infer_simf_type_from_value` covers literals.
    #[test]
    fn type_inference_covers_all_literal_categories() {
        assert_eq!(infer_simf_type("WITH_ASSET_BURN"), Some("bool"));
        assert_eq!(infer_simf_type("SOME_ENABLED"), Some("bool"));
        assert_eq!(infer_simf_type("ASSET_AMOUNT"), Some("u64"));
        assert_eq!(infer_simf_type("UNKNOWN_PARAM"), None);

        assert_eq!(infer_simf_type_from_value("true"), Some("bool"));
        assert_eq!(infer_simf_type_from_value("false"), Some("bool"));
        assert_eq!(infer_simf_type_from_value("1"), Some("u64"));
        assert_eq!(infer_simf_type_from_value("0xdeadbeef"), None); // hex not handled
        assert_eq!(infer_simf_type_from_value(""), None);
    }

    /// `compute_tapleaf_hash` must produce the same bytes as compiling the program directly,
    /// extracting the CMR, and building the TapLeafHash.  The test also checks against the
    /// formula from the Simplicity C implementation (`make_tapleaf` in ops.c):
    ///
    ///   SHA256(SHA256("TapLeaf/elements") || SHA256("TapLeaf/elements") || 0xbe || 0x20 || cmr)
    ///
    /// where 0x20 is the compact-size encoding of 32 (the CMR length).
    /// If any path disagrees the script_pubkey written on-chain won't match what
    /// `finalize_covenant_input` produces when it tries to spend it.
    #[test]
    fn tapleaf_matches_compiled_cmr() {
        // Use script_auth.simf — single SCRIPT_HASH (u256) param, no witnesses needed.
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let simf_path = crate_dir.join("../examples/lending/script_auth.simf");

        let mut params = HashMap::new();
        params.insert(
            "SCRIPT_HASH".to_string(),
            // The NUMS point — a valid 32-byte value; content doesn't matter for this test.
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".to_string(),
        );

        let mut hints = HashMap::new();
        hints.insert("SCRIPT_HASH".to_string(), "bytes32".to_string());

        // Path A — the function under test.
        let hash_a =
            compute_tapleaf_hash(&simf_path, &params, &hints).expect("compute_tapleaf_hash");

        // Path B — compile directly, get CMR, use TapLeafHash::from_script.
        let source = std::fs::read_to_string(&simf_path).expect("read simf");
        let args_json = build_args_json(&params, &hints).expect("build_args_json");
        let arguments: Arguments = serde_json::from_str(&args_json).expect("parse Arguments");
        let compiled = CompiledProgram::new(
            source,
            arguments,
            false,
            Box::new(simplicityhl::ast::ElementsJetHinter::new()),
        )
        .expect("compile");

        let cmr = compiled.commit().cmr();
        let leaf_ver = simplicity_leaf_version();
        let script = Script::from(cmr.as_ref().to_vec());
        let hash_b = lwk_wollet::elements::taproot::TapLeafHash::from_script(&script, leaf_ver)
            .to_byte_array();

        // Path C — the raw tagged-hash formula from the Simplicity C implementation
        // (make_tapleaf in simplicity-sys/depend/simplicity/elements/ops.c):
        //   SHA256(tag || tag || leaf_version_byte || 0x20 || cmr_bytes)
        // where tag = SHA256("TapLeaf/elements") and 0x20 = compact_size(32).
        use lwk_wollet::elements::hashes::{sha256, Hash as _, HashEngine as _};
        let tag = sha256::Hash::hash(b"TapLeaf/elements");
        let mut engine = sha256::HashEngine::default();
        engine.input(tag.as_ref());
        engine.input(tag.as_ref());
        engine.input(&[0xbe]); // Simplicity leaf version
        engine.input(&[0x20]); // compact_size(32) — CMR is always 32 bytes
        engine.input(cmr.as_ref());
        let hash_c = sha256::Hash::from_engine(engine).to_byte_array();

        assert_eq!(
            hash_a, hash_b,
            "compute_tapleaf_hash must equal TapLeafHash::from_script"
        );
        assert_eq!(
            hash_b, hash_c,
            "TapLeafHash::from_script must equal Simplicity C make_tapleaf"
        );
    }

    /// Verify that `compute_covenant_script_hash` produces the same result regardless of whether
    /// extra compile params (those not referenced by `pre_lock.simf`) are included.
    ///
    /// This guards against the bug where `IssueUtilityNFTs` computes `PRE_LOCK_COV_HASH` using
    /// only the 15 explicit params from the manifest spec, while `LockCollateral` creates the
    /// pre_lock output using ALL instance fields as compile params. If extra params affect the
    /// CMR, the two code paths produce different addresses, making the loan protocol fail.
    #[test]
    fn pre_lock_script_hash_invariant_to_extra_params() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let simf_path = crate_dir.join("../examples/lending/pre_lock.simf");
        let network = lwk_wollet::ElementsNetwork::LiquidTestnet;

        // Helper to build the 15 explicit params + hints (matching the manifest.json
        // PRE_LOCK_COV_HASH spec, which is exactly what IssueUtilityNFTs passes).
        let mut explicit_params: HashMap<String, String> = HashMap::new();
        let mut explicit_hints: HashMap<String, String> = HashMap::new();

        let add = |p: &mut HashMap<String, String>,
                   h: &mut HashMap<String, String>,
                   name: &str,
                   val: &str,
                   ty: &str| {
            p.insert(name.to_string(), val.to_string());
            h.insert(name.to_string(), ty.to_string());
        };

        // Integer params
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "COLLATERAL_AMOUNT",
            "8000",
            "u64",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "PRINCIPAL_AMOUNT",
            "500",
            "u64",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "LOAN_EXPIRATION_TIME",
            "2479500",
            "u32",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "PRINCIPAL_INTEREST_RATE",
            "1000",
            "u16",
        );

        // Asset IDs (display-backward hex — build_args_json reverses them)
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "COLLATERAL_ASSET_ID",
            "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
            "liquid.asset_id",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "FIRST_PARAMETERS_NFT_ASSET_ID",
            "980c4a4baf261c9358cc5f555025133736a7d67fb02ff450ee8d6c558bb52d53",
            "liquid.asset_id",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "SECOND_PARAMETERS_NFT_ASSET_ID",
            "a691202df6b97e7d4af8a331e8239ee68e1a191acf38ad68418603a6bbb6c70b",
            "liquid.asset_id",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "BORROWER_NFT_ASSET_ID",
            "c922d6478c017687bd46b547dcd87d7b289bf2a67ca868dfd6eb6667a57d75e3",
            "liquid.asset_id",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "LENDER_NFT_ASSET_ID",
            "ae35e601cc340d9335c0be0d2638150adf6aea366b352b62a7c99602095cbc39",
            "liquid.asset_id",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "PRINCIPAL_ASSET_ID",
            "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
            "liquid.asset_id",
        );

        // Hash params (bytes32 — NOT reversed)
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "LENDING_COV_HASH",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "bytes32",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "PRINCIPAL_OUTPUT_SCRIPT_HASH",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "bytes32",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "PARAMETERS_NFT_OUTPUT_SCRIPT_HASH",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "bytes32",
        );
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "BORROWER_NFT_OUTPUT_SCRIPT_HASH",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "bytes32",
        );

        // Public key (NUMS x-only pubkey as 32-byte hex — not reversed)
        add(
            &mut explicit_params,
            &mut explicit_hints,
            "BORROWER_PUB_KEY",
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            "pubkey",
        );

        // Hash A: explicit params only (mirrors IssueUtilityNFTs PRE_LOCK_COV_HASH computation)
        let hash_a =
            compute_covenant_script_hash(&simf_path, &explicit_params, &explicit_hints, network)
                .expect("hash with explicit params");

        // Add the extra params that LockCollateral includes via compile_params_map
        // (all instance fields, including ones pre_lock.simf does NOT reference).
        let mut all_params = explicit_params.clone();
        let mut all_hints = explicit_hints.clone();
        add(
            &mut all_params,
            &mut all_hints,
            "COLLATERAL_DECIMALS_MANTISSA",
            "3",
            "u8",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "PRINCIPAL_DECIMALS_MANTISSA",
            "1",
            "u8",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "FIRST_PARAMETERS_ENCODED",
            "167288263934952",
            "u64",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "SECOND_PARAMETERS_ENCODED",
            "1677721608",
            "u64",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "PRINCIPAL_INTEREST_AMOUNT",
            "50",
            "u64",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "LENDER_PRINCIPAL_COV_HASH",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bytes32",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "PRE_LOCK_COV_HASH",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bytes32",
        );
        add(
            &mut all_params,
            &mut all_hints,
            "PRELOCK_PARAMETERS_NFT_SCRIPT_HASH",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "bytes32",
        );

        // Hash B: all params (mirrors how LockCollateral creates the pre_lock output)
        let hash_b = compute_covenant_script_hash(&simf_path, &all_params, &all_hints, network)
            .expect("hash with all params");

        let hex_a: String = hash_a.iter().map(|b| format!("{b:02x}")).collect();
        let hex_b: String = hash_b.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex_a, hex_b,
            "Extra unreferenced params must not change the covenant address.\n\
             If this fails, SimplicityHL is sensitive to extra params and LockCollateral \
             must filter compile_params to only those referenced by the target simf file."
        );
    }

    /// Verify that `compute_covenant_script_hash` for `pre_lock.simf` with the actual
    /// testnet instance params produces the same `PRE_LOCK_COV_HASH` that was written
    /// to `lending.instance.json` (73d1b960...).
    ///
    /// If this test fails it means the hash computation itself is wrong (e.g. wrong type hints,
    /// wrong asset-id byte order, or wrong network).  If it passes but SetupLending still
    /// fails the problem is that the on-chain pre_lock UTXO was created by an older run of
    /// LockCollateral (before the compute_tapleaf_hash → compute_covenant_script_hash fix).
    #[test]
    fn pre_lock_script_hash_matches_instance() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let simf_path = crate_dir.join("../examples/lending/pre_lock.simf");
        let network = lwk_wollet::ElementsNetwork::LiquidTestnet;

        let mut params: HashMap<String, String> = HashMap::new();
        let mut hints: HashMap<String, String> = HashMap::new();

        let add = |p: &mut HashMap<String, String>,
                   h: &mut HashMap<String, String>,
                   name: &str,
                   val: &str,
                   ty: &str| {
            p.insert(name.to_string(), val.to_string());
            h.insert(name.to_string(), ty.to_string());
        };

        // Values from lending.instance.json (the current testnet run).
        add(&mut params, &mut hints, "COLLATERAL_AMOUNT", "8000", "u64");
        add(&mut params, &mut hints, "PRINCIPAL_AMOUNT", "500", "u64");
        add(
            &mut params,
            &mut hints,
            "LOAN_EXPIRATION_TIME",
            "2479500",
            "u32",
        );
        add(
            &mut params,
            &mut hints,
            "PRINCIPAL_INTEREST_RATE",
            "1000",
            "u16",
        );

        add(
            &mut params,
            &mut hints,
            "COLLATERAL_ASSET_ID",
            "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
            "liquid.asset_id",
        );
        add(
            &mut params,
            &mut hints,
            "FIRST_PARAMETERS_NFT_ASSET_ID",
            "276f7f5af2d42b2471769c4d632d46c9430d73ca076832d15959d893d241bd52",
            "liquid.asset_id",
        );
        add(
            &mut params,
            &mut hints,
            "SECOND_PARAMETERS_NFT_ASSET_ID",
            "da9edb39f1228bd22b4c3fa12da79c1d183ad3f3a4f602128868385b9dd53693",
            "liquid.asset_id",
        );
        add(
            &mut params,
            &mut hints,
            "BORROWER_NFT_ASSET_ID",
            "dff993237bddb4f33fb9451f663a0b3b16f561902843ddb4f6a2e9f2730bbb61",
            "liquid.asset_id",
        );
        add(
            &mut params,
            &mut hints,
            "LENDER_NFT_ASSET_ID",
            "94dedbc53d8f0a9a0f524e116bd9f83ce6bd2981b601a99fa91af8760623de10",
            "liquid.asset_id",
        );
        add(
            &mut params,
            &mut hints,
            "PRINCIPAL_ASSET_ID",
            "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
            "liquid.asset_id",
        );

        add(
            &mut params,
            &mut hints,
            "LENDING_COV_HASH",
            "f4e0b5c74a7456e1e39b434f2af74dec206c882a54865fdc971405756f8eed70",
            "bytes32",
        );
        add(
            &mut params,
            &mut hints,
            "PRINCIPAL_OUTPUT_SCRIPT_HASH",
            "e318778137554371b56da63801e852e106dc427177e5330f39b8b5727be25ec5",
            "bytes32",
        );
        add(
            &mut params,
            &mut hints,
            "PARAMETERS_NFT_OUTPUT_SCRIPT_HASH",
            "aa933b2b5796d85fe815df2b5f304d93d210b4cf396aeb89c6f62aa57278f890",
            "bytes32",
        );
        add(
            &mut params,
            &mut hints,
            "BORROWER_NFT_OUTPUT_SCRIPT_HASH",
            "96c5df67482e1b9a5ee950efbbf082fac37e6326f836aec319c51ba866aa46c6",
            "bytes32",
        );
        add(
            &mut params,
            &mut hints,
            "BORROWER_PUB_KEY",
            "1d4c354f5f91613f50ba8f59361bc5fb0d0e01fbb90495b7fbfc744e8f5d2253",
            "pubkey",
        );

        let hash = compute_covenant_script_hash(&simf_path, &params, &hints, network)
            .expect("compute_covenant_script_hash");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        // Expected: SHA256(scriptPubKey of the pre_lock covenant address) computed
        // with the correct LENDING_COV_HASH (f4e0b5c7...) from the current instance.
        //
        // The old instance.json had PRE_LOCK_COV_HASH = 73d1b960... which was WRONG —
        // it was computed by eval_create_instance_fields using a stale LENDING_COV_HASH
        // loaded from the previously saved instance into ctx, before LENDING_COV_HASH
        // was freshly recomputed in the same run.  After the lifecycle.rs fix (guarding
        // ctx fallback with computed_field_names), re-running IssueUtilityNFTs will
        // produce PRE_LOCK_COV_HASH = a323dee... which matches the actual on-chain UTXO.
        assert_eq!(
            hex, "a323dee710635a3438d6d93dd4364aad580624b1a33c6d2495c803cfd92c5fbb",
            "Computed PRE_LOCK_COV_HASH does not match expected value.\nComputed: {hex}"
        );
    }
}
