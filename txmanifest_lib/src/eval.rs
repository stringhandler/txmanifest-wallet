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
/// `compile_params.X`, `input.field`, …) or a bare/quoted literal.
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
/// `args.X`, `compile_params.X`, a resolved `input.field`, a bare action
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
    if let Some(k) = name.strip_prefix("compile_params.") {
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
/// as are `compile_params.KEY` prefixed forms.  `pow(base, exp)` computes integer power
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

/// Substitute bare compile param names (and `compile_params.KEY`) with their values.
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

            if token == "compile_params"
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
                        result.push_str("compile_params.");
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
                    "compile_params" => ctx.get_compile_param(key).map(str::to_string),
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
                // like "pairs * 2 * compile_params.COLLATERAL_PER_TOKEN" where "pairs" is an
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
