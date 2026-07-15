#[cfg(feature = "simplicity_eval")]
use std::str::FromStr;

use anyhow::{bail, Result};
#[cfg(feature = "simplicity_eval")]
use lwk_wollet::elements::{hashes::Hash as ElementsHash, Txid};
#[cfg(feature = "simplicity_eval")]
use simplicityhl::num::U256;
#[cfg(feature = "simplicity_eval")]
use simplicityhl::value::ValueConstructible;

use crate::context::ExecutionContext;

/// Evaluate an expression string (arithmetic formula) and return the result as a String.
/// Used for action params with a `formula` field so they can be auto-computed.
pub fn eval_expr_str(expr: &str, ctx: &ExecutionContext) -> Result<String> {
    Ok(eval_expr(expr, ctx)?.to_string())
}

/// Evaluate an `amount_sat` JSON value → concrete u64.
/// Handles: null (→ 0), number literals, single variable references, arithmetic expressions.
pub fn eval_amount(value: &serde_json::Value, ctx: &ExecutionContext) -> Result<u64> {
    match value {
        serde_json::Value::Null => Ok(0),
        serde_json::Value::Number(n) => {
            n.as_u64()
                .ok_or_else(|| anyhow::anyhow!("amount_sat number is not a valid u64: {n}"))
        }
        serde_json::Value::String(s) => eval_expr(s.trim(), ctx),
        // { "value": "<expr>", "description": "..." } — documented amount field
        serde_json::Value::Object(m) => match m.get("value") {
            Some(v) => eval_amount(v, ctx),
            None => bail!("Unsupported amount_sat object (no 'value' field): {}", serde_json::Value::Object(m.clone())),
        },
        other => bail!("Unsupported amount_sat value: {other}"),
    }
}

/// Evaluate an `asset` JSON value → asset label string.
/// Returns "lbtc", a compile_params/params variable value, or a raw hex asset ID.
pub fn eval_asset_label(value: &serde_json::Value, ctx: &ExecutionContext) -> Result<String> {
    match value {
        serde_json::Value::String(s) => {
            let s = s.trim();
            if let Some(v) = resolve_ref(s, ctx) {
                Ok(v)
            } else {
                Ok(s.to_string())
            }
        }
        serde_json::Value::Object(m) if m.contains_key("if") => {
            bail!("Conditional asset expressions are not yet supported")
        }
        other => bail!("Unsupported asset value: {other}"),
    }
}

/// Resolve a destination string (e.g. "params.receive_address") → concrete address string.
/// Returns None if the reference cannot be resolved (caller treats it as a literal).
pub fn eval_destination_str(dest: &str, ctx: &ExecutionContext) -> Option<String> {
    resolve_ref(dest, ctx)
}

/// Evaluate an OP_RETURN `data` value into a raw byte payload.
///
/// Two forms are accepted:
///
/// 1. **String** — a `concat(a, b, …)` expression (or single reference / hex literal).
///    Each argument is resolved against `ctx` and decoded from hex; `liquid.asset_id`
///    arguments are byte-reversed to Elements-internal order.
///
/// 2. **Object** `{ "parts": [ … ] }` — an ordered list of typed fields, for exact
///    binary layouts (e.g. protocol metadata). Each part is one of:
///      - `{ "type": "liquid.asset_id", "value": <ref> }` → 32 bytes, internal (reversed) order
///      - `{ "type": "u64"|"u32"|"u16"|"u8", "value": <ref>, "endian": "le"|"be" }` (default le)
///      - `{ "type": "pubkey"|"bytes32"|"bytes", "value": <ref/hex> }` → raw bytes, natural order
///
/// All part types are protocol-agnostic. A fixed byte prefix (e.g. a protocol
/// "program id" / message-type tag) is just a `bytes` part whose value is a constant
/// (typically supplied as a documented param default), not a special op.
pub fn eval_op_return_data(
    data: &serde_json::Value,
    ctx: &ExecutionContext,
    type_hints: &std::collections::HashMap<String, String>,
) -> Result<Vec<u8>> {
    match data {
        serde_json::Value::String(expr) => eval_op_return_concat(expr, ctx, type_hints),
        serde_json::Value::Object(m) => {
            let parts = m
                .get("parts")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("OP_RETURN data object must have a 'parts' array"))?;
            let mut out = Vec::new();
            for part in parts {
                out.extend_from_slice(&eval_op_return_part(part, ctx)?);
            }
            Ok(out)
        }
        other => bail!("Unsupported OP_RETURN data value: {other}"),
    }
}

/// Encode a single typed OP_RETURN `parts` entry (see [`eval_op_return_data`]).
fn eval_op_return_part(
    part: &serde_json::Value,
    ctx: &ExecutionContext,
) -> Result<Vec<u8>> {
    let ty = part.get("type").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("OP_RETURN part missing 'type': {part}"))?;
    let value_ref = part.get("value").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("OP_RETURN part needs 'value': {part}"))?;
    let resolved = resolve_ref(value_ref, ctx)
        .unwrap_or_else(|| value_ref.trim_matches(['"', '\'']).to_string());
    match ty {
        "u8" | "u16" | "u32" | "u64" => {
            let n: u64 = resolved.trim().parse()
                .map_err(|_| anyhow::anyhow!("OP_RETURN '{value_ref}' = '{resolved}' is not an integer"))?;
            let width = match ty { "u8" => 1, "u16" => 2, "u32" => 4, _ => 8 };
            let le = part.get("endian").and_then(|v| v.as_str()) != Some("be");
            let full = n.to_le_bytes();
            let mut bytes = full[..width].to_vec();
            if !le { bytes.reverse(); }
            Ok(bytes)
        }
        "liquid.asset_id" => {
            let mut b = hex_to_bytes(&resolved)?;
            b.reverse(); // display → internal
            Ok(b)
        }
        "pubkey" | "bytes32" | "bytes" => hex_to_bytes(&resolved),
        other => bail!("Unsupported OP_RETURN part type '{other}'"),
    }
}

/// Encode a computed/typed taproot storage-leaf payload item.
///
/// Item shape: `{ "value": <ref|literal>, "type": "u8"|"u16"|"u32"|"u64"|"bytes32"|"bytes",
///                 "endian": "le"|"be"?, "pad_to": <bytes>?, "align": "left"|"right"? }`.
///
/// `value` is resolved via the standard ref resolver (`instance.X`, `params.X`, an input
/// field, or a literal fallback). Integer types encode to their natural width (default
/// little-endian, matching the OP_RETURN `parts` form); `bytes32`/`bytes` decode hex.
/// `pad_to` zero-pads the encoded bytes to that total width, on the left when
/// `align: "right"` (the default for a right-aligned integer, e.g. a u64 in bytes[24..32]
/// of a 32-byte slot) or on the right when `align: "left"`.
///
/// Used for dynamic storage slots such as the lending covenant's `current_debt` leaf.
pub fn encode_leaf_value(
    item: &serde_json::Value,
    ctx: &ExecutionContext,
) -> Result<Vec<u8>> {
    let value_ref = item.get("value").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("taproot leaf value item needs 'value': {item}"))?;
    let resolved = resolve_ref(value_ref, ctx)
        .unwrap_or_else(|| value_ref.trim_matches(['"', '\'']).to_string());
    encode_leaf_bytes(item, &resolved)
}

/// Encode a taproot leaf payload item given its already-resolved `value` string.
/// Split from [`encode_leaf_value`] so callers that resolve `value` themselves (e.g.
/// against an in-progress `create_instance` field map) can reuse the typed encoding.
pub fn encode_leaf_bytes(item: &serde_json::Value, resolved: &str) -> Result<Vec<u8>> {
    let ty = item.get("type").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("taproot leaf value item needs 'type': {item}"))?;

    let mut bytes = match ty {
        "u8" | "u16" | "u32" | "u64" => {
            let n: u64 = resolved.trim().parse()
                .map_err(|_| anyhow::anyhow!("taproot leaf value '{resolved}' is not an integer"))?;
            let width = match ty { "u8" => 1, "u16" => 2, "u32" => 4, _ => 8 };
            let le = item.get("endian").and_then(|v| v.as_str()) != Some("be");
            let full = n.to_le_bytes();
            let mut b = full[..width].to_vec();
            if !le { b.reverse(); }
            b
        }
        "bytes32" | "bytes" | "pubkey" => hex_to_bytes(&resolved)?,
        other => bail!("Unsupported taproot leaf value type '{other}'"),
    };

    if let Some(pad_to) = item.get("pad_to").and_then(|v| v.as_u64()).map(|n| n as usize) {
        if bytes.len() > pad_to {
            bail!("taproot leaf value '{resolved}' encodes to {} bytes, exceeds pad_to {pad_to}", bytes.len());
        }
        let pad = pad_to - bytes.len();
        // Default align for a padded value is "right" (value occupies the trailing bytes).
        let align_left = item.get("align").and_then(|v| v.as_str()) == Some("left");
        if align_left {
            bytes.resize(pad_to, 0u8); // value first, zeros trailing
        } else {
            let mut padded = vec![0u8; pad];
            padded.extend_from_slice(&bytes);
            bytes = padded;
        }
    }
    Ok(bytes)
}

/// Decode a (0x-prefixed or bare) even-length hex string into bytes.
fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    let hex = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if hex.len() % 2 != 0 {
        bail!("odd-length hex '{hex}'");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| anyhow::anyhow!("invalid hex '{hex}'"))
}

/// The `concat(a, b, …)` string form of an OP_RETURN payload (form 1 in [`eval_op_return_data`]).
fn eval_op_return_concat(
    expr: &str,
    ctx: &ExecutionContext,
    type_hints: &std::collections::HashMap<String, String>,
) -> Result<Vec<u8>> {
    let e = expr.trim();
    let inner = e
        .strip_prefix("concat(")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(e);
    let mut out = Vec::new();
    for raw in inner.split(',') {
        let arg = raw.trim();
        if arg.is_empty() {
            continue;
        }
        // The referenced key (last dotted segment) drives the asset-id reversal decision.
        let key = arg.rsplit('.').next().unwrap_or(arg);
        let is_asset = match type_hints.get(key) {
            Some(t) => t == "liquid.asset_id",
            None => {
                let u = key.to_uppercase();
                u.ends_with("_ASSET_ID") || u.ends_with("_ASSET")
            }
        };
        let resolved = resolve_ref(arg, ctx).unwrap_or_else(|| arg.trim_matches(['"', '\'']).to_string());
        let hex = resolved.trim().trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() % 2 != 0 {
            bail!("OP_RETURN data part '{arg}' resolved to odd-length hex '{hex}'");
        }
        let mut bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| anyhow::anyhow!("OP_RETURN data part '{arg}' is not valid hex: '{hex}'"))?;
        if is_asset {
            bytes.reverse();
        }
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Evaluate an inequality (`!=`) validation expression by comparing both operands
/// as strings.  String comparison (rather than the integer evaluator) lets this
/// work on 64-char asset-id hex values, e.g.
/// `params.COLLATERAL_ASSET_ID != params.PRINCIPAL_ASSET_ID`.
///
/// Returns:
///   - `Some(true)`  — the operands differ (validation passes)
///   - `Some(false)` — the operands are equal (validation is violated)
///   - `None`        — the expression is not a `!=` comparison, or an operand
///                     could not be resolved; the caller treats this as
///                     informational (not enforced).
///
/// Only `!=` is handled here. Equality/relational operators are intentionally
/// left unenforced so existing `==` / `>=` validations keep their current
/// (informational) behaviour.
pub fn eval_inequality_validation(expr: &str, ctx: &ExecutionContext) -> Option<bool> {
    // `split_once("!=")` only matches `!=`, never `==`, `>=`, or `<=`.
    let (lhs, rhs) = expr.split_once("!=")?;
    let lv = resolve_operand(lhs.trim(), ctx)?;
    let rv = resolve_operand(rhs.trim(), ctx)?;
    Some(lv != rv)
}

/// Resolve a single comparison operand: a context reference (`params.X`,
/// `instance.X`, `input.field`, …) or a bare/quoted literal.
fn resolve_operand(s: &str, ctx: &ExecutionContext) -> Option<String> {
    if let Some(v) = resolve_ref(s, ctx) {
        return Some(v);
    }
    let lit = s.trim_matches(['"', '\'']);
    if lit.is_empty() {
        None
    } else {
        Some(lit.to_string())
    }
}

/// Resolve a per-site covenant `compile_params` value.
///
/// The value may be a reference into the execution context — `params.X`,
/// `args.X`, `instance.X`, a resolved `input.field`, a bare action
/// param/arg name, or a bare compile-param name — in which case its current
/// value is returned. Anything that matches no reference is returned verbatim
/// as a literal (e.g. `"1"`, `"true"`, a raw hex value).
pub fn resolve_compile_param_value(value: &str, ctx: &ExecutionContext) -> String {
    let v = value.trim();
    if let Some(resolved) = resolve_ref(v, ctx) {
        return resolved;
    }
    // `resolve_ref` checks params/args (not compile_params) for a bare name;
    // fall back to a bare compile-param reference for parity with the
    // utxo_type `script.compile_params` form.
    if !v.contains('.') {
        if let Some(cp) = ctx.get_compile_param(v) {
            return cp.to_string();
        }
    }
    v.to_string()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn eval_expr(expr: &str, ctx: &ExecutionContext) -> Result<u64> {
    // 1. Direct numeric literal
    if let Ok(n) = expr.parse::<u64>() {
        return Ok(n);
    }

    // 2. Single variable reference (no operators)
    if let Some(v) = resolve_ref(expr, ctx) {
        return v
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("Variable '{expr}' = '{v}' is not a valid u64"));
    }

    // 3. Expand pow() calls, substitute all variable references, evaluate with evalexpr
    let pre = resolve_pow(expr, ctx);
    let substituted = substitute_vars(&pre, ctx);
    let val = evalexpr::eval_int(&substituted).map_err(|e| {
        anyhow::anyhow!("Cannot evaluate '{expr}' (substituted: '{substituted}'): {e}")
    })?;

    if val < 0 {
        bail!("Expression '{expr}' evaluated to negative value: {val}");
    }
    Ok(val as u64)
}

/// Look up a dotted reference (e.g. `params.pairs`, `collateral.amount_sat`) in ctx.
fn resolve_ref(name: &str, ctx: &ExecutionContext) -> Option<String> {
    // `fee` is a reserved keyword resolving to the current estimated network fee.
    // It starts at 0 and is recomputed from the tx vsize before signing, so an
    // amount like `will_in.amount_sat - fee` lands on the right value.
    if name == "fee" {
        return Some(ctx.fee().to_string());
    }
    if let Some(k) = name
        .strip_prefix("instance.")
        // Deprecated alias for `instance.` — remove after the transition release.
        .or_else(|| name.strip_prefix("compile_params."))
    {
        return ctx.get_compile_param(k).map(str::to_string);
    }
    if let Some(k) = name.strip_prefix("params.") {
        return ctx.get_param(k).map(str::to_string);
    }
    if let Some(k) = name.strip_prefix("args.") {
        return ctx.get_arg(k).map(str::to_string);
    }
    // Bare param/arg name without namespace prefix (e.g. "pairs" in a formula for the "pairs"
    // action param).  Check params then args as fallback.
    if !name.contains('.') {
        if let Some(v) = ctx.get_param(name) {
            return Some(v.to_string());
        }
        if let Some(v) = ctx.get_arg(name) {
            return Some(v.to_string());
        }
    }
    // input_id.field  (e.g. "collateral.amount_sat", "yes_rt.reissuance_token")
    if let Some(dot) = name.rfind('.') {
        let input_id = &name[..dot];
        let field = &name[dot + 1..];
        if let Some(inp) = ctx.get_input(input_id) {
            let from_input = match field {
                "amount_sat" => Some(inp.amount_sat.to_string()),
                "asset" => Some(inp.asset.clone()),
                _ => None,
            };
            if from_input.is_some() {
                return from_input;
            }
        }
        // Fall back to per-input derived attrs (e.g. reissuance_token, computed asset IDs)
        if let Some(v) = ctx.get_input_attr(input_id, field) {
            return Some(v.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// SimplicityHL on_input_resolved hook evaluator
// ---------------------------------------------------------------------------

/// Evaluate a SimplicityHL expression from an `on_input_resolved` hook.
///
/// `hook_input_id` is the key in `on_input_resolved`. The expression may reference
/// `{hook_input_id}.outpoint_hash`, `{hook_input_id}.vout`, and
/// `{hook_input_id}.contract_hash` as free variables; these are bound automatically
/// from the resolved UTXO in `ctx`.
///
/// Returns the computed value as a hex string suitable for storing in `compile_params`.
#[cfg(feature = "simplicity_eval")]
pub fn eval_simplicityhl_hook(
    expr: &str,
    hook_input_id: &str,
    ctx: &ExecutionContext,
) -> Result<String> {
    let resolved = ctx.get_input(hook_input_id).ok_or_else(|| {
        anyhow::anyhow!("Input '{}' not found in context", hook_input_id)
    })?;

    let txid = Txid::from_str(&resolved.txid)
        .map_err(|e| anyhow::anyhow!("Cannot parse txid '{}': {e}", resolved.txid))?;

    let txid_bytes: [u8; 32] = *txid.as_raw_hash().as_byte_array();

    // Provide the three variables the expression may reference.
    // contract_hash is all-zeros for no-contract new issuances.
    let mut bindings = std::collections::HashMap::new();
    bindings.insert(
        format!("{hook_input_id}.outpoint_hash"),
        simplicityhl::Value::u256(U256::from_byte_array(txid_bytes)),
    );
    bindings.insert(
        format!("{hook_input_id}.vout"),
        simplicityhl::Value::u32(resolved.vout),
    );
    bindings.insert(
        format!("{hook_input_id}.contract_hash"),
        simplicityhl::Value::u256(U256::from_byte_array([0u8; 32])),
    );

    match simplicityhl::eval_expression(expr.trim(), &bindings) {
        Ok(value) => {
            let s = value.to_string();
            let hex = s.strip_prefix("0x").unwrap_or(&s);
            // SimplicityHL outputs U256 values in natural (MSB-first, no reversal) byte order.
            // All compile_params representing asset IDs use Elements display-backward convention
            // (sha256::Midstate::DISPLAY_BACKWARD = true), so AssetId::from_str can parse them
            // correctly.  Reverse the byte pairs here to convert to that convention.
            let reversed: String = hex
                .as_bytes()
                .chunks(2)
                .rev()
                .flat_map(|pair| pair.iter().map(|&b| b as char))
                .collect();
            Ok(reversed)
        }
        Err(simplicityhl::EvalError::RequiresTransactionContext(jets)) => {
            bail!("Expression requires transaction context: {}", jets.join(", "))
        }
        Err(e) => bail!("SimplicityHL eval failed: {e}"),
    }
}

/// Stub used when the `simplicity_eval` feature is disabled — SimplicityHL hooks cannot be
/// evaluated without the SimplicityHL compiler. Rebuild with `--features simplicity_eval`.
#[cfg(not(feature = "simplicity_eval"))]
pub fn eval_simplicityhl_hook(
    _expr: &str,
    _hook_input_id: &str,
    _ctx: &ExecutionContext,
) -> Result<String> {
    bail!(
        "Simplicity/covenant support is not compiled in. \
         Rebuild with `--features simplicity_eval` (requires the SimplicityHL dependency)."
    )
}

// ---------------------------------------------------------------------------
// Derived param compute evaluator
// ---------------------------------------------------------------------------

/// Evaluate a `compute.expr` for a derived compile param.
///
/// Variable references: bare identifiers matching a compile param name are substituted,
/// as are `instance.KEY` prefixed forms (and the deprecated `compile_params.KEY` alias).
/// `pow(base, exp)` computes integer power
/// (e.g. `pow(10, COLLATERAL_DECIMALS_MANTISSA)`).  Result is a u64 string.
pub fn eval_param_compute_expr(expr: &str, ctx: &ExecutionContext) -> Result<u64> {
    let pre = resolve_pow(expr, ctx);
    let substituted = substitute_compile_param_vars(&pre, ctx);
    let val = evalexpr::eval_int(&substituted).map_err(|e| {
        anyhow::anyhow!(
            "Cannot evaluate compute expr '{}' (substituted: '{}'): {}",
            expr, substituted, e
        )
    })?;
    if val < 0 {
        bail!("Compute expr '{}' evaluated to negative: {}", expr, val);
    }
    Ok(val as u64)
}

/// Substitute bare compile param names (and `instance.KEY` / legacy `compile_params.KEY`) with their values.
fn substitute_compile_param_vars(expr: &str, ctx: &ExecutionContext) -> String {
    let bytes = expr.as_bytes();
    let mut result = String::with_capacity(expr.len() + 16);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let id_start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let token = &expr[id_start..i];

            // `instance` is the spec namespace; `compile_params` is the deprecated alias.
            if (token == "instance" || token == "compile_params")
                && i < bytes.len()
                && bytes[i] == b'.'
                && i + 1 < bytes.len()
                && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_')
            {
                i += 1; // consume dot
                let key_start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let key = &expr[key_start..i];
                match ctx.get_compile_param(key) {
                    Some(v) => result.push_str(v),
                    None => {
                        result.push_str(token);
                        result.push('.');
                        result.push_str(key);
                    }
                }
            } else if let Some(v) = ctx.get_compile_param(token) {
                result.push_str(v);
            } else {
                result.push_str(token);
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Pre-process `pow(base, exp)` calls, resolving variable exponents from ctx.
/// Only handles the form `pow(integer_literal, param_name_or_literal)`.
fn resolve_pow(expr: &str, ctx: &ExecutionContext) -> String {
    let mut s = expr.to_string();
    while let Some(pos) = s.find("pow(") {
        let inner_start = pos + 4;
        let Some(rel_close) = s[inner_start..].find(')') else { break };
        let inner = s[inner_start..inner_start + rel_close].to_string();
        let Some(comma) = inner.find(',') else { break };
        let base_s = inner[..comma].trim();
        let exp_s = inner[comma + 1..].trim();
        let base: Option<i64> = base_s.parse().ok();
        let exp: Option<i64> = exp_s
            .parse()
            .ok()
            .or_else(|| ctx.get_compile_param(exp_s).and_then(|v| v.parse().ok()))
            .or_else(|| ctx.get_param(exp_s).and_then(|v| v.parse().ok()))
            .or_else(|| ctx.get_arg(exp_s).and_then(|v| v.parse().ok()));
        match (base, exp) {
            (Some(b), Some(e)) if e >= 0 => {
                let computed = b.pow(e as u32).to_string();
                s.replace_range(pos..inner_start + rel_close + 1, &computed);
            }
            _ => break,
        }
    }
    s
}

/// Replace all resolvable `namespace.key` references with their values from ctx.
/// Unresolved references are left as-is so evalexpr can report them as unknown variables.
fn substitute_vars(expr: &str, ctx: &ExecutionContext) -> String {
    let bytes = expr.as_bytes();
    let mut result = String::with_capacity(expr.len() + 16);
    let mut i = 0;

    while i < bytes.len() {
        // Start of an identifier
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let id_start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let namespace = &expr[id_start..i];

            // Check for `.key` following the identifier
            if i < bytes.len()
                && bytes[i] == b'.'
                && i + 1 < bytes.len()
                && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_')
            {
                i += 1; // consume the dot
                let key_start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let key = &expr[key_start..i];

                let resolved = match namespace {
                    // `compile_params` is the deprecated alias for `instance`.
                    "instance" | "compile_params" => ctx.get_compile_param(key).map(str::to_string),
                    "params" => ctx.get_param(key).map(str::to_string),
                    "args" => ctx.get_arg(key).map(str::to_string),
                    input_id => {
                        let from_input = ctx.get_input(input_id).and_then(|inp| match key {
                            "amount_sat" => Some(inp.amount_sat.to_string()),
                            "asset" => Some(inp.asset.clone()),
                            _ => None,
                        });
                        from_input.or_else(|| ctx.get_input_attr(input_id, key).map(str::to_string))
                    }
                };

                if let Some(v) = resolved {
                    result.push_str(&v);
                } else {
                    // Leave unresolved so evalexpr gives a clear error
                    result.push_str(namespace);
                    result.push('.');
                    result.push_str(key);
                }
            } else if namespace == "fee" {
                // Reserved keyword: the estimated network fee.
                result.push_str(&ctx.fee().to_string());
            } else {
                // No dot: bare identifier. Try resolving as a param or arg (allows formulas
                // like "pairs * 2 * instance.COLLATERAL_PER_TOKEN" where "pairs" is an
                // action param).
                if let Some(v) = ctx.get_param(namespace).or_else(|| ctx.get_arg(namespace)) {
                    result.push_str(v);
                } else {
                    result.push_str(namespace);
                }
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod fee_keyword_tests {
    use super::*;
    use crate::context::ExecutionContext;

    #[test]
    fn fee_keyword_resolves_to_context_fee() {
        let mut ctx = ExecutionContext::new();
        ctx.set_param("amount", "100000");
        // Default fee is 0.
        assert_eq!(eval_amount(&serde_json::json!("amount - fee"), &ctx).unwrap(), 100000);
        // After estimation, `fee` reflects the set value.
        ctx.set_fee(250);
        assert_eq!(eval_amount(&serde_json::json!("amount - fee"), &ctx).unwrap(), 99750);
        // Bare `fee` resolves directly.
        assert_eq!(eval_amount(&serde_json::json!("fee"), &ctx).unwrap(), 250);
    }
}

#[cfg(test)]
mod op_return_data_tests {
    use super::*;
    use crate::context::ExecutionContext;
    use std::collections::HashMap;

    #[test]
    fn concat_reverses_asset_id_and_preserves_pubkey() {
        let mut ctx = ExecutionContext::new();
        // 32-byte x-only pubkey (natural order) and a 32-byte asset id in display order.
        let pubkey = "a19d31462a25b9ad26298473a967e0c188404c6f913a3bbf1da0f5402fe2d86d";
        let asset_display = "3cc22e157739d0bab9b1015396d7cfacf67b9a66275454e049dcef7bae8ea8f8";
        ctx.set_compile_param("BORROWER_PUB_KEY", pubkey);
        ctx.set_compile_param("PRINCIPAL_ASSET_ID", asset_display);

        let mut hints = HashMap::new();
        hints.insert("PRINCIPAL_ASSET_ID".to_string(), "liquid.asset_id".to_string());
        hints.insert("BORROWER_PUB_KEY".to_string(), "pubkey".to_string());

        let bytes = eval_op_return_data(
            &serde_json::json!("concat(instance.BORROWER_PUB_KEY, instance.PRINCIPAL_ASSET_ID)"),
            &ctx,
            &hints,
        )
        .unwrap();

        // 64 bytes total: pubkey natural-order, asset id reversed to Elements-internal order.
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(bytes.len(), 64);
        assert_eq!(to_hex(&bytes[..32]), pubkey);
        let mut asset_internal: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&asset_display[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        asset_internal.reverse();
        assert_eq!(&bytes[32..], asset_internal.as_slice());
    }

    #[test]
    fn parts_form_encodes_typed_50_byte_metadata() {
        let mut ctx = ExecutionContext::new();
        ctx.set_compile_param("PRINCIPAL_ASSET_ID", "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5");
        ctx.set_compile_param("PRINCIPAL_AMOUNT", "1000");
        ctx.set_compile_param("LOAN_EXPIRATION_TIME", "2536857");
        ctx.set_compile_param("PRINCIPAL_INTEREST_RATE", "10000");
        let data = serde_json::json!({ "parts": [
            { "type": "liquid.asset_id", "value": "instance.PRINCIPAL_ASSET_ID" },
            { "type": "u64", "value": "instance.PRINCIPAL_AMOUNT" },
            { "type": "u32", "value": "instance.LOAN_EXPIRATION_TIME" },
            { "type": "u16", "value": "instance.PRINCIPAL_INTEREST_RATE" }
        ]});
        let bytes = eval_op_return_data(&data, &ctx, &std::collections::HashMap::new()).unwrap();
        // 32 (asset) + 8 + 4 + 2 = 46 bytes (no program-id prefix here).
        assert_eq!(bytes.len(), 46);
        assert_eq!(&bytes[32..40], &1000u64.to_le_bytes());
        assert_eq!(&bytes[40..44], &2536857u32.to_le_bytes());
        assert_eq!(&bytes[44..46], &10000u16.to_le_bytes());
        // asset reversed to internal order (last internal byte = first display byte 0x38)
        assert_eq!(bytes[31], 0x38);
    }
}
