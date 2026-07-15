//! Pre-broadcast "clear signing" preview.
//!
//! Renders two confirmation screens from the manifest's author-supplied `ui`
//! metadata, right before the broadcast prompt:
//!
//!   1. **Action summary** — the one-line intent (`action.ui.action`), with
//!      `{ref}` / `{ref:symbol}` interpolation against the execution context.
//!   2. **Net-effect diff** — every input (a debit) and output (a credit),
//!      grouped by the account it touches (your wallet / a covenant / an
//!      external address / burned-or-data), with signed amounts and the asset
//!      symbol.
//!
//! This mirrors as closely as a host terminal can what a Ledger/Jade would show
//! for the same transaction. It is NOT a device trust boundary: the strings come
//! from the manifest, so their trustworthiness rests entirely on the manifest's
//! own publisher/authority signature chain, not on anything the device verifies.
//!
//! The asset registry is deliberately out of scope here — a couple of testnet
//! assets (tL-BTC, tUSD) are hardcoded; everything else renders in raw base units
//! against a shortened asset id.

use console::style;

use crate::context::ExecutionContext;
use crate::eval;
use crate::manifest::{Action, Input, Output};

// ---------------------------------------------------------------------------
// Asset registry (hardcoded stand-in — real lookup is out of scope)
// ---------------------------------------------------------------------------

/// Liquid **testnet** L-BTC policy asset id.
const TLBTC_ASSET_ID: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
/// Testnet USD asset id used by the lending examples.
const TUSD_ASSET_ID: &str = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";

/// Display metadata for an asset.
pub struct AssetMeta {
    pub symbol: String,
    /// Decimal places. `0` means the amount is shown verbatim in base units.
    pub precision: u8,
}

/// Resolve an asset label (`"lbtc"`) or asset-id hex to display metadata.
///
/// Only the two hardcoded testnet assets are "known"; anything else falls back
/// to a shortened id shown in raw base units (`precision = 0`).
pub fn lookup_asset(label: &str) -> AssetMeta {
    let l = label.trim().to_lowercase();
    match l.as_str() {
        "lbtc" | "bitcoin" | TLBTC_ASSET_ID => AssetMeta { symbol: "tL-BTC".into(), precision: 8 },
        TUSD_ASSET_ID => AssetMeta { symbol: "tUSD".into(), precision: 8 },
        // Unknown asset: show a short id, count in base units.
        other => {
            let sym = if other.len() > 12 {
                format!("{}…{}", &other[..6], &other[other.len() - 4..])
            } else {
                other.to_string()
            };
            AssetMeta { symbol: sym, precision: 0 }
        }
    }
}

/// Format a base-unit amount for display given the asset's precision.
/// `precision = 0` prints the integer verbatim; otherwise a fixed-point value
/// with trailing zeros (and a bare trailing dot) trimmed.
pub fn format_amount(base_units: u64, precision: u8) -> String {
    if precision == 0 {
        return base_units.to_string();
    }
    let divisor = 10u128.pow(precision as u32);
    let whole = base_units as u128 / divisor;
    let frac = base_units as u128 % divisor;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{frac:0width$}", width = precision as usize);
    let frac_trimmed = frac_str.trim_end_matches('0');
    format!("{whole}.{frac_trimmed}")
}

// ---------------------------------------------------------------------------
// Screen 1 — action summary
// ---------------------------------------------------------------------------

/// Interpolate a `{ref}` / `{ref:symbol}` template against the context.
///
/// - `{instance.X}` → the resolved value verbatim.
/// - `{instance.X:symbol}` → the asset symbol for the id/label `instance.X`
///   resolves to.
///
/// Unresolvable references are left as their literal `{...}` text so authoring
/// mistakes are visible rather than silently blank.
pub fn interpolate(template: &str, ctx: &ExecutionContext) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            // No closing brace — emit the remainder verbatim.
            out.push_str(&rest[open..]);
            return out;
        };
        let token = &after[..close];
        out.push_str(&resolve_token(token, ctx).unwrap_or_else(|| format!("{{{token}}}")));
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Resolve one `ref` or `ref:modifier` template token.
fn resolve_token(token: &str, ctx: &ExecutionContext) -> Option<String> {
    let (reference, modifier) = match token.split_once(':') {
        Some((r, m)) => (r.trim(), Some(m.trim())),
        None => (token.trim(), None),
    };
    let value = resolve_ref(reference, ctx)?;
    match modifier {
        Some("symbol") => Some(lookup_asset(&value).symbol),
        _ => Some(value),
    }
}

/// Resolve a context reference (`instance.X`, `params.X`, `input.field`, …).
/// Returns `None` when the reference doesn't resolve (rather than the literal),
/// so callers can flag authoring mistakes.
fn resolve_ref(reference: &str, ctx: &ExecutionContext) -> Option<String> {
    let resolved = eval::eval_asset_label(
        &serde_json::Value::String(reference.to_string()),
        ctx,
    )
    .ok()?;
    // `eval_asset_label` echoes unknown refs back as a literal; treat an
    // unchanged echo of a `namespace.key` reference as "unresolved".
    if resolved == reference && reference.contains('.') {
        None
    } else {
        Some(resolved)
    }
}

// ---------------------------------------------------------------------------
// Screen 2 — net-effect diff
// ---------------------------------------------------------------------------

/// One signed movement line within an account bucket.
struct Leg {
    credit: bool,
    /// Pre-formatted `amount symbol` string, or `None` for an auto/optional amount.
    amount: Option<String>,
    label: String,
}

/// An account and the movements that touch it, in author order.
struct Bucket {
    heading: String,
    legs: Vec<Leg>,
}

/// Render both preview screens to stdout.
pub fn render_preview(action: &Action, ctx: &ExecutionContext) {
    // -- Screen 1 --------------------------------------------------------
    if let Some(summary) = action.ui.as_ref().and_then(|u| u.action.as_deref()) {
        println!();
        println!("{}", style("=== Review action ===").bold().cyan());
        println!("  {}", style(interpolate(summary, ctx)).bold());
    }

    // -- Screen 2 --------------------------------------------------------
    let buckets = build_net_effect(action, ctx);
    if buckets.is_empty() {
        return;
    }
    println!();
    println!("{}", style("=== Net effect ===").bold().cyan());
    for bucket in &buckets {
        println!("  {}", style(format!("({})", bucket.heading)).bold());
        for leg in &bucket.legs {
            let sign = if leg.credit { style("+").green() } else { style("−").red() };
            match &leg.amount {
                Some(a) => println!("    {sign} {}  {}", style(a).yellow(), style(&leg.label).dim()),
                None => println!("    {sign} {}", style(&leg.label).dim()),
            }
        }
    }
}

/// Assemble the ordered list of account buckets from the action's inputs/outputs.
fn build_net_effect(action: &Action, ctx: &ExecutionContext) -> Vec<Bucket> {
    let mut buckets: Vec<Bucket> = Vec::new();

    let mut push = |heading: String, leg: Leg| {
        if let Some(b) = buckets.iter_mut().find(|b| b.heading == heading) {
            b.legs.push(leg);
        } else {
            buckets.push(Bucket { heading, legs: vec![leg] });
        }
    };

    for input in action.inputs.as_deref().unwrap_or_default() {
        if input.ui.as_ref().is_some_and(|u| u.hidden()) {
            continue;
        }
        let heading = input
            .ui
            .as_ref()
            .and_then(|u| u.group())
            .map(str::to_string)
            .unwrap_or_else(|| input_bucket(input, ctx));
        push(
            heading,
            Leg {
                credit: false,
                amount: input_amount(input, ctx).map(|(n, sym, prec)| {
                    format!("{} {sym}", format_amount(n, prec))
                }),
                label: input_label(input),
            },
        );
    }

    for output in action.outputs.as_deref().unwrap_or_default() {
        if output.ui.as_ref().is_some_and(|u| u.hidden()) {
            continue;
        }
        let heading = output
            .ui
            .as_ref()
            .and_then(|u| u.group())
            .map(str::to_string)
            .unwrap_or_else(|| output_bucket(output, ctx));
        push(
            heading,
            Leg {
                credit: true,
                amount: output_amount(output, ctx).map(|(n, sym, prec)| {
                    format!("{} {sym}", format_amount(n, prec))
                }),
                label: output_label(output),
            },
        );
    }

    buckets
}

// -- account-bucket derivation ------------------------------------------

fn input_bucket(input: &Input, _ctx: &ExecutionContext) -> String {
    if input.is_wallet_source() {
        "your wallet".into()
    } else if let Some(t) = input.utxo_type_name() {
        format!("covenant: {t}")
    } else {
        "other".into()
    }
}

fn output_bucket(output: &Output, ctx: &ExecutionContext) -> String {
    match &output.destination {
        serde_json::Value::String(s) if s == "wallet" || s == "change" => "your wallet".into(),
        serde_json::Value::String(other) => {
            // A `params.X` / `instance.X` destination resolves to an address.
            match eval::eval_destination_str(other, ctx) {
                Some(addr) => format!("address {}", short(&addr)),
                None => other.clone(),
            }
        }
        serde_json::Value::Object(m) => {
            if let Some(t) = m.get("utxo_type").and_then(|v| v.as_str()) {
                format!("covenant: {t}")
            } else if matches!(
                m.get("type").and_then(|v| v.as_str()),
                Some("op_return") | Some("burn")
            ) {
                "burned / protocol data".into()
            } else {
                output.destination_summary()
            }
        }
        _ => output.destination_summary(),
    }
}

// -- amount / asset resolution ------------------------------------------

/// `(base_units, symbol, precision)` for an input, or `None` if the amount is
/// not statically known (e.g. a `min_amount` constraint with no resolved UTXO).
fn input_amount(input: &Input, ctx: &ExecutionContext) -> Option<(u64, String, u8)> {
    let asset_label = input_asset(input, ctx);
    let meta = lookup_asset(&asset_label);
    // Prefer a resolved UTXO amount; fall back to a statically evaluable spec.
    let amount = ctx
        .get_input(&input.id)
        .map(|r| r.amount_sat)
        .filter(|n| *n > 0)
        .or_else(|| input.amount_sat.as_ref().and_then(|v| eval::eval_amount(v, ctx).ok()))?;
    Some((amount, meta.symbol, meta.precision))
}

fn input_asset(input: &Input, ctx: &ExecutionContext) -> String {
    if let Some(r) = ctx.get_input(&input.id) {
        if !r.asset.is_empty() && !r.asset.starts_with("STUB_ASSET") {
            return r.asset.clone();
        }
    }
    input
        .asset
        .as_ref()
        .and_then(|v| eval::eval_asset_label(v, ctx).ok())
        .unwrap_or_else(|| "lbtc".into())
}

/// `(base_units, symbol, precision)` for an output, or `None` when the amount is
/// auto/optional (change, fee) and not statically evaluable.
fn output_amount(output: &Output, ctx: &ExecutionContext) -> Option<(u64, String, u8)> {
    let asset_label = output
        .asset
        .as_ref()
        .and_then(|v| eval::eval_asset_label(v, ctx).ok())
        .unwrap_or_else(|| "lbtc".into());
    let meta = lookup_asset(&asset_label);
    let amount = output
        .amount_sat
        .as_ref()
        .and_then(|v| eval::eval_amount(v, ctx).ok())
        .filter(|n| *n > 0)?;
    Some((amount, meta.symbol, meta.precision))
}

// -- labels -------------------------------------------------------------

fn input_label(input: &Input) -> String {
    input
        .ui
        .as_ref()
        .and_then(|u| u.label())
        .or(input.description.as_deref())
        .unwrap_or(&input.id)
        .to_string()
}

fn output_label(output: &Output) -> String {
    let mut label = output
        .ui
        .as_ref()
        .and_then(|u| u.label())
        .or(output.description.as_deref())
        .unwrap_or(&output.id)
        .to_string();
    if output.optional.unwrap_or(false) && !label.ends_with("if any") {
        label.push_str(" (if any)");
    }
    label
}

fn short(s: &str) -> String {
    if s.len() > 16 {
        format!("{}…{}", &s[..8], &s[s.len() - 4..])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    const COLLATERAL_ID: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    const PRINCIPAL_ID: &str = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";

    #[test]
    fn format_amount_applies_precision() {
        assert_eq!(format_amount(100_000_000, 8), "1");
        assert_eq!(format_amount(20_000_000_000, 8), "200");
        assert_eq!(format_amount(3400, 8), "0.000034");
        assert_eq!(format_amount(1000, 0), "1000");
        assert_eq!(format_amount(0, 8), "0");
    }

    #[test]
    fn lookup_asset_knows_hardcoded_and_shortens_unknown() {
        assert_eq!(lookup_asset("lbtc").symbol, "tL-BTC");
        assert_eq!(lookup_asset(COLLATERAL_ID).symbol, "tL-BTC");
        assert_eq!(lookup_asset(PRINCIPAL_ID).symbol, "tUSD");
        let nft = lookup_asset("1c424b82d66f37b9efea9f55bb5fab6dd2524742f8cc2741ed1be185a848c507");
        assert_eq!(nft.precision, 0);
        assert!(nft.symbol.contains('…'));
    }

    /// Load CreateOffer from the real lending_v3 example and populate a context
    /// with its instance values.
    fn create_offer_ctx() -> (Manifest, ExecutionContext) {
        let src = include_str!("../../examples/lending_v3/txmanifest.json");
        let manifest: Manifest = serde_json::from_str(src).expect("parse example manifest");
        let mut ctx = ExecutionContext::new();
        for (k, v) in [
            ("PRINCIPAL_AMOUNT", "1000"),
            ("COLLATERAL_AMOUNT", "3400"),
            ("PRINCIPAL_ASSET_ID", PRINCIPAL_ID),
            ("COLLATERAL_ASSET_ID", COLLATERAL_ID),
            ("FACTORY_ASSET_ID", "c6b7a5fdf1a01787af534dc9252d1c99908d929a16f8862b8925dcf53d089c6b"),
            ("BORROWER_NFT_ASSET_ID", "1c424b82d66f37b9efea9f55bb5fab6dd2524742f8cc2741ed1be185a848c507"),
            ("LENDER_NFT_ASSET_ID", "7eae7d537d90257c78220a1fd89915b39a2cb293111914e5a2e20d965acf361f"),
        ] {
            ctx.set_compile_param(k, v);
        }
        (manifest, ctx)
    }

    fn create_offer(manifest: &Manifest) -> &Action {
        manifest
            .classes
            .as_ref()
            .and_then(|c| c.get("lending_contract"))
            .and_then(|c| c.methods.get("CreateOffer"))
            .expect("CreateOffer method")
    }

    #[test]
    fn interpolates_action_summary_with_symbols() {
        let (manifest, ctx) = create_offer_ctx();
        let action = create_offer(&manifest);
        let template = action.ui.as_ref().unwrap().action.as_ref().unwrap();
        let rendered = interpolate(template, &ctx);
        assert_eq!(
            rendered,
            "create an offer to borrow 1000 tUSD by locking 3400 tL-BTC as collateral"
        );
    }

    #[test]
    fn unresolved_reference_stays_literal() {
        let ctx = ExecutionContext::new();
        assert_eq!(interpolate("x {instance.NOPE} y", &ctx), "x {instance.NOPE} y");
    }

    #[test]
    fn net_effect_groups_by_account() {
        let (manifest, ctx) = create_offer_ctx();
        let action = create_offer(&manifest);
        let buckets = build_net_effect(action, &ctx);
        let headings: Vec<&str> = buckets.iter().map(|b| b.heading.as_str()).collect();
        assert!(headings.contains(&"your wallet"));
        assert!(headings.contains(&"covenant: issuance_factory"));
        assert!(headings.contains(&"covenant: lending_collateral"));

        // The collateral output lands in the lending covenant as a debit-free credit.
        let cov = buckets.iter().find(|b| b.heading == "covenant: lending_collateral").unwrap();
        let collateral_leg = cov.legs.iter().find(|l| l.credit).unwrap();
        assert_eq!(collateral_leg.amount.as_deref(), Some("0.000034 tL-BTC"));
    }
}
