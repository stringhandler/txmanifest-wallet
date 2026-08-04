//! Pre-broadcast "clear signing" preview.
//!
//! Renders three confirmation screens from the manifest's author-supplied `ui`
//! metadata, right before the broadcast prompt:
//!
//!   1. **Review action** — the one-line intent (`action.intent`), with
//!      `{ref}` / `{ref:symbol}` interpolation against the execution context.
//!   2. **Net effect** — the bottom line: what your wallet actually gains or
//!      loses, netted per asset. Assets that merely round-trip (an auth NFT
//!      spent and re-output) net to zero and are omitted, so a claim reads as
//!      just "− fee, + principal".
//!   3. **Detailed effect** — every input (a debit) and output (a credit),
//!      grouped by the account it touches (your wallet / a covenant / an
//!      external address / burned-or-data) and then by asset, so an asset
//!      leaving and returning reads together.
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
// Verified wallet delta (from the built PSET, unblinded by the wallet)
// ---------------------------------------------------------------------------

/// The wallet's exact net balance change for the built transaction, sourced from
/// `Wollet::get_details` (which unblinds the wallet's own confidential outputs).
/// Unlike the manifest-driven legs, this is authoritative — it reflects the real
/// selected inputs, change, and fee, not the statically declared amounts.
pub struct WalletDelta {
    /// Network fee in L-BTC base units (already reflected in the L-BTC balance).
    pub fee_sat: u64,
    /// `(asset label or id, signed base units)` — negative leaves the wallet.
    pub balances: Vec<(String, i64)>,
}

/// Render `- 0.000034 tL-BTC` style, returning `(is_credit, "amount symbol")`.
fn format_signed(units: i64, meta: &AssetMeta) -> (bool, String) {
    let credit = units >= 0;
    let text = format!("{} {}", format_amount(units.unsigned_abs(), meta.precision), meta.symbol);
    (credit, text)
}

// ---------------------------------------------------------------------------
// Screen 2 — net-effect diff
// ---------------------------------------------------------------------------

/// The bucket heading for the user's own wallet — the account the net summary is
/// computed over.
const WALLET_BUCKET: &str = "your wallet";

/// One signed movement line within an account bucket.
struct Leg {
    credit: bool,
    /// Amount in base units, or `None` when not known (auto/optional with no fee).
    units: Option<u64>,
    /// Asset display symbol, used to group and net same-asset legs. `None` for
    /// amount-less legs (e.g. an OP_RETURN data line).
    asset: Option<String>,
    /// Decimal places for `units`.
    precision: u8,
    label: String,
}

impl Leg {
    /// The `amount symbol` display string, when the amount is known.
    fn amount_text(&self) -> Option<String> {
        let units = self.units?;
        let sym = self.asset.as_deref()?;
        Some(format!("{} {sym}", format_amount(units, self.precision)))
    }
}

/// An account and the movements that touch it, in author order.
struct Bucket {
    heading: String,
    legs: Vec<Leg>,
}

/// Render the preview screens to stdout.
///
/// `fee_sat` is the network fee read from the built PSET (its explicit fee output);
/// it lets change outputs show exact values and is available whenever a PSET was
/// built, independent of whether `wallet` could be computed.
///
/// `wallet` is the authoritative wallet balance change from `Wollet::get_details`.
/// When present it is the source of the "Net effect" summary; otherwise that
/// summary is netted from the legs. Pass `None` when it couldn't be computed
/// (e.g. a dry run, or the wallet can't unblind the PSET).
pub fn render_preview(
    action: &Action,
    ctx: &ExecutionContext,
    fee_sat: Option<u64>,
    wallet: Option<&WalletDelta>,
) {
    // -- Screen 1 — what this action does --------------------------------
    if let Some(summary) = action.intent.as_deref() {
        println!();
        println!("{}", style("=== Review action ===").bold().cyan());
        println!("  {}", style(interpolate(summary, ctx)).bold());
    }

    // Exact change needs the fee (change = inputs − explicit outputs − fee),
    // read straight from the PSET's fee output.
    let buckets = build_net_effect(action, ctx, fee_sat);

    // -- Screen 2 — the bottom line: what your wallet actually gains/loses -
    render_net_summary(&buckets, fee_sat, wallet);

    // -- Screen 3 — every individual movement ----------------------------
    if !buckets.is_empty() {
        println!();
        println!("{}", style("=== Detailed effect ===").bold().cyan());
        for bucket in &buckets {
            println!("  {}", style(format!("({})", bucket.heading)).bold());
            for leg in &bucket.legs {
                let sign = if leg.credit { style("+").green() } else { style("−").red() };
                match leg.amount_text() {
                    Some(a) => println!("    {sign} {}  {}", style(a).yellow(), style(&leg.label).dim()),
                    None => println!("    {sign} {}", style(&leg.label).dim()),
                }
            }
        }
    }
}

/// Print the wallet's net position change, one line per asset, zeros omitted.
///
/// An asset that merely round-trips (e.g. an auth NFT spent and re-output) nets to
/// zero and is deliberately not shown — the point of this screen is what actually
/// leaves or joins the wallet. Prefers the verified `WalletDelta`; falls back to
/// netting the wallet bucket's legs when it isn't available.
fn render_net_summary(buckets: &[Bucket], fee_sat: Option<u64>, wallet: Option<&WalletDelta>) {
    let nets = wallet_nets(buckets, wallet);

    println!();
    println!("{}", style("=== Net effect ===").bold().cyan());
    if nets.is_empty() {
        println!("  {}", style("no net change to your wallet").dim());
        return;
    }
    for (meta, units, exact) in &nets {
        let (credit, text) = format_signed(*units, meta);
        let sign = if credit { style("+").green() } else { style("−").red() };
        let approx = if *exact { "" } else { "≈ " };
        println!("    {sign} {approx}{}", style(&text).yellow());
    }
    if let Some(line) = fee_line(fee_sat) {
        println!("      {}", style(line).dim());
    }
}

/// The informational network-fee line for the net summary.
///
/// The fee is already baked into the policy-asset net above (it is paid out of the
/// same wallet inputs), so this line is explicitly marked as included rather than
/// signed — a `−` here would invite double-counting.
fn fee_line(fee_sat: Option<u64>) -> Option<String> {
    let fee = fee_sat.filter(|f| *f > 0)?;
    let meta = lookup_asset("lbtc");
    Some(format!(
        "network fee: {} {} (included above)",
        format_amount(fee, meta.precision),
        meta.symbol,
    ))
}

/// The wallet's net position change per asset: `(asset, signed base units, exact?)`.
///
/// Assets that net to zero (a pure round-trip) are omitted. Prefers the verified
/// `WalletDelta`; otherwise nets the wallet bucket's legs, marking an asset inexact
/// if any of its legs had an unknown amount.
fn wallet_nets(buckets: &[Bucket], wallet: Option<&WalletDelta>) -> Vec<(AssetMeta, i64, bool)> {
    // Authoritative: already netted per asset by the wallet.
    if let Some(delta) = wallet {
        return delta
            .balances
            .iter()
            .filter(|(_, units)| *units != 0)
            .map(|(asset, units)| (lookup_asset(asset), *units, true))
            .collect();
    }

    let Some(bucket) = buckets.iter().find(|b| b.heading == WALLET_BUCKET) else {
        return Vec::new();
    };
    let mut order: Vec<String> = Vec::new();
    let mut acc: std::collections::HashMap<String, (u8, i64, bool)> = Default::default();
    for leg in &bucket.legs {
        let Some(sym) = leg.asset.clone() else { continue };
        let e = acc.entry(sym.clone()).or_insert_with(|| {
            order.push(sym.clone());
            (leg.precision, 0, true)
        });
        match leg.units {
            Some(n) => e.1 += if leg.credit { n as i64 } else { -(n as i64) },
            // An unknown amount makes this asset's net inexact.
            None => e.2 = false,
        }
    }
    order
        .into_iter()
        .filter_map(|sym| {
            let (prec, units, exact) = acc[&sym];
            // Drop assets that merely round-trip, but keep inexact ones visible.
            (units != 0 || !exact).then(|| (AssetMeta { symbol: sym, precision: prec }, units, exact))
        })
        .collect()
}


/// The policy-asset symbol the network fee is denominated in. (Registry is out of
/// scope; on testnet L-BTC is the fee/policy asset.)
const POLICY_SYMBOL: &str = "tL-BTC";

/// Assemble the ordered list of account buckets from the action's inputs/outputs.
///
/// `fee_sat` (when known, from the built PSET) lets change outputs show their exact
/// value via value conservation — `change(asset) = Σ inputs − Σ explicit outputs −
/// fee` — instead of an "(if any)" placeholder. Change is computed per asset symbol,
/// so a `lbtc` input and a policy-asset-id output net together, and the (possibly
/// several) per-purpose change legs of one asset collapse to a single exact line.
fn build_net_effect(action: &Action, ctx: &ExecutionContext, fee_sat: Option<u64>) -> Vec<Bucket> {
    use std::collections::BTreeMap;

    let inputs = action.inputs.as_deref().unwrap_or_default();
    let outputs = action.outputs.as_deref().unwrap_or_default();

    // Conservation sums, keyed by display symbol (so lbtc ≡ policy asset id).
    let mut in_by_sym: BTreeMap<String, (u8, u64)> = BTreeMap::new();
    let mut out_by_sym: BTreeMap<String, u64> = BTreeMap::new();
    for input in inputs {
        if let Some((n, sym, prec)) = input_amount(input, ctx) {
            let e = in_by_sym.entry(sym).or_insert((prec, 0));
            e.0 = prec;
            e.1 += n;
        }
    }
    for output in outputs {
        if is_change(output) {
            continue;
        }
        if let Some((n, sym, _)) = output_amount(output, ctx) {
            *out_by_sym.entry(sym).or_default() += n;
        }
    }
    // change(symbol) = inputs − explicit outputs − (fee, for the policy asset).
    let change_for = |sym: &str| -> Option<u64> {
        let fee = fee_sat?;
        let (_, total_in) = in_by_sym.get(sym).copied()?;
        let out = out_by_sym.get(sym).copied().unwrap_or(0);
        let fee_part = if sym == POLICY_SYMBOL { fee } else { 0 };
        Some(total_in.saturating_sub(out).saturating_sub(fee_part))
    };
    // How many change legs share each symbol (to relabel merged ones).
    let mut change_leg_count: BTreeMap<String, usize> = BTreeMap::new();
    for output in outputs {
        if is_change(output) {
            *change_leg_count.entry(output_asset_symbol(output, ctx)).or_default() += 1;
        }
    }

    let mut buckets: Vec<Bucket> = Vec::new();
    let mut push = |heading: String, leg: Leg| {
        if let Some(b) = buckets.iter_mut().find(|b| b.heading == heading) {
            b.legs.push(leg);
        } else {
            buckets.push(Bucket { heading, legs: vec![leg] });
        }
    };

    for input in inputs {
        if input.ui.as_ref().is_some_and(|u| u.hidden()) {
            continue;
        }
        let heading = input
            .ui
            .as_ref()
            .and_then(|u| u.group())
            .map(str::to_string)
            .unwrap_or_else(|| input_bucket(input, ctx));
        let amt = input_amount(input, ctx);
        push(
            heading,
            Leg {
                credit: false,
                units: amt.as_ref().map(|(n, _, _)| *n),
                asset: amt.as_ref().map(|(_, sym, _)| sym.clone()),
                precision: amt.as_ref().map(|(_, _, p)| *p).unwrap_or(0),
                label: input_label(input),
            },
        );
    }

    // Track which change symbols have already been emitted, so several per-purpose
    // change legs of the same asset produce a single exact line.
    let mut change_emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for output in outputs {
        if output.ui.as_ref().is_some_and(|u| u.hidden()) {
            continue;
        }
        let heading = output
            .ui
            .as_ref()
            .and_then(|u| u.group())
            .map(str::to_string)
            .unwrap_or_else(|| output_bucket(output, ctx));

        if is_change(output) {
            let sym = output_asset_symbol(output, ctx);
            if !change_emitted.insert(sym.clone()) {
                continue; // already showed this asset's (merged) change
            }
            let (prec, _) = in_by_sym.get(&sym).copied().unwrap_or((0, 0));
            let merged = change_leg_count.get(&sym).copied().unwrap_or(0) > 1;
            let label = if merged {
                "change back to your wallet".to_string()
            } else {
                output_base_label(output) // exact amount shown → no "(if any)"
            };
            match change_for(&sym) {
                // Skip a zero-value change output (none actually created).
                Some(0) => continue,
                Some(n) => push(
                    heading,
                    Leg { credit: true, units: Some(n), asset: Some(sym), precision: prec, label },
                ),
                // Fee unknown (e.g. dry run) — fall back to the placeholder label.
                None => push(
                    heading,
                    Leg {
                        credit: true,
                        units: None,
                        asset: Some(sym),
                        precision: prec,
                        label: output_label(output),
                    },
                ),
            }
            continue;
        }

        let amt = output_amount(output, ctx);
        push(
            heading,
            Leg {
                credit: true,
                units: amt.as_ref().map(|(n, _, _)| *n),
                asset: amt.as_ref().map(|(_, sym, _)| sym.clone()),
                precision: amt.as_ref().map(|(_, _, p)| *p).unwrap_or(0),
                label: output_label(output),
            },
        );
    }

    // Group each bucket's legs by asset so an asset going out and coming back reads
    // together. Stable sort by first-appearance order of the asset, so groups keep
    // their natural order and within a group debits stay before credits.
    for bucket in &mut buckets {
        let mut order: Vec<String> = Vec::new();
        let key = |leg: &Leg| leg.asset.clone().unwrap_or_default();
        for leg in &bucket.legs {
            let k = key(leg);
            if !order.contains(&k) {
                order.push(k);
            }
        }
        bucket
            .legs
            .sort_by_key(|leg| order.iter().position(|k| *k == key(leg)).unwrap_or(usize::MAX));
    }

    buckets
}

/// True when this output is wallet change (`destination: "change"`).
fn is_change(output: &Output) -> bool {
    matches!(&output.destination, serde_json::Value::String(s) if s == "change")
}

/// The display symbol for an output's asset (`tL-BTC`, `tUSD`, or a short id).
fn output_asset_symbol(output: &Output, ctx: &ExecutionContext) -> String {
    let label = output
        .asset
        .as_ref()
        .and_then(|v| eval::eval_asset_label(v, ctx).ok())
        .unwrap_or_else(|| "lbtc".into());
    lookup_asset(&label).symbol
}

// -- account-bucket derivation ------------------------------------------

fn input_bucket(input: &Input, _ctx: &ExecutionContext) -> String {
    if input.is_wallet_source() {
        WALLET_BUCKET.into()
    } else if let Some(t) = input.utxo_type_name() {
        format!("covenant: {t}")
    } else {
        "other".into()
    }
}

fn output_bucket(output: &Output, ctx: &ExecutionContext) -> String {
    match &output.destination {
        serde_json::Value::String(s) if s == "wallet" || s == "change" => WALLET_BUCKET.into(),
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
        if !r.asset.is_empty() {
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

/// The signer-facing label for an input.
///
/// `ui.label` is the **only** source. `description` is deliberately not a fallback:
/// it is developer prose (median 60 chars, 38% over 80, longest 1193 in this repo's
/// own examples) and dumping it into a one-line net-effect row wrecks the display.
/// More importantly, `description` is excluded from the manifest's registry hash so
/// it can be edited without re-signing — which means it must never appear on a
/// screen the user reads before authorising a transaction. Legs with no `ui.label`
/// fall back to their `id`, which `validate` flags.
fn input_label(input: &Input) -> String {
    input
        .ui
        .as_ref()
        .and_then(|u| u.label())
        .unwrap_or(&input.id)
        .to_string()
}

/// The output's label without any "(if any)" suffix. See [`input_label`] for why
/// `description` is not a fallback.
fn output_base_label(output: &Output) -> String {
    output
        .ui
        .as_ref()
        .and_then(|u| u.label())
        .unwrap_or(&output.id)
        .to_string()
}

/// The output's display label; appends "(if any)" for an optional output whose
/// amount isn't being shown exactly.
fn output_label(output: &Output) -> String {
    let mut label = output_base_label(output);
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
        let manifest: Manifest = Manifest::from_json_str(src).expect("parse example manifest");
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
            .contract_templates
            .as_ref()
            .and_then(|c| c.get("lending_contract"))
            .and_then(|c| c.actions.get("CreateOffer"))
            .expect("CreateOffer method")
    }

    /// The role is the machine-readable half of the hint and was declared-but-never-read until
    /// the run flow and `describe` started rendering it. Pin the accessor to the detailed form.
    #[test]
    fn ui_role_reads_detail_form_only() {
        use crate::manifest::UiSpec;
        let detail: UiSpec = serde_json::from_value(
            serde_json::json!({ "label": "the live loan", "role": "covenant" })
        ).unwrap();
        assert_eq!(detail.label(), Some("the live loan"));
        assert_eq!(detail.role(), Some("covenant"));

        // The bare-string shorthand carries a label and no role.
        let bare: UiSpec = serde_json::from_value(serde_json::json!("just a label")).unwrap();
        assert_eq!(bare.label(), Some("just a label"));
        assert_eq!(bare.role(), None);
    }

    #[test]
    fn interpolates_action_summary_with_symbols() {
        let (manifest, ctx) = create_offer_ctx();
        let action = create_offer(&manifest);
        let template = action.intent.as_ref().unwrap();
        let rendered = interpolate(template, &ctx);
        assert_eq!(
            rendered,
            "create an offer to borrow 1000 tUSD by locking 3400 tL-BTC as collateral"
        );
    }

    #[test]
    fn format_signed_directions_and_precision() {
        let lbtc = lookup_asset("lbtc");
        assert_eq!(format_signed(-3626, &lbtc), (false, "0.00003626 tL-BTC".to_string()));
        assert_eq!(format_signed(100_000_000, &lbtc), (true, "1 tL-BTC".to_string()));
        let nft = lookup_asset("1c424b82d66f37b9efea9f55bb5fab6dd2524742f8cc2741ed1be185a848c507");
        let (credit, text) = format_signed(1, &nft);
        assert!(credit);
        assert!(text.starts_with("1 "));
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
        let buckets = build_net_effect(action, &ctx, None);
        let headings: Vec<&str> = buckets.iter().map(|b| b.heading.as_str()).collect();
        assert!(headings.contains(&"your wallet"));
        assert!(headings.contains(&"covenant: issuance_factory"));
        assert!(headings.contains(&"covenant: lending_collateral"));

        // The collateral output lands in the lending covenant as a debit-free credit.
        let cov = buckets.iter().find(|b| b.heading == "covenant: lending_collateral").unwrap();
        let collateral_leg = cov.legs.iter().find(|l| l.credit).unwrap();
        assert_eq!(collateral_leg.amount_text().as_deref(), Some("0.000034 tL-BTC"));
    }

    #[test]
    fn net_effect_change_is_exact_and_merged() {
        use crate::context::ResolvedInput;
        let (manifest, mut ctx) = create_offer_ctx();
        // Resolve the two wallet L-BTC inputs to concrete UTXOs (49_470 sat each).
        for (id, asset) in [("collateral_in", COLLATERAL_ID), ("fee_input", "lbtc")] {
            ctx.set_input(ResolvedInput {
                id: id.into(),
                txid: "00".repeat(32),
                vout: 0,
                amount_sat: 49_470,
                asset: asset.into(),
                issuance_entropy: None,
            });
        }
        let action = create_offer(&manifest);
        // fee = 226 sat. change(tL-BTC) = 98_940 − 3_400 (locked) − 226 = 95_314 sat.
        let buckets = build_net_effect(action, &ctx, Some(226));
        let wallet = buckets.iter().find(|b| b.heading == "your wallet").unwrap();
        let change: Vec<String> = wallet
            .legs
            .iter()
            .filter(|l| l.credit && l.label.contains("change"))
            .filter_map(|l| l.amount_text())
            .collect();
        // The two per-purpose tL-BTC change legs collapse to one exact line.
        assert_eq!(change, vec!["0.00095314 tL-BTC".to_string()]);
        // And no "(if any)" placeholder remains on any change leg.
        assert!(!wallet.legs.iter().any(|l| l.label.contains("if any")));
    }

    #[test]
    fn net_effect_legs_grouped_by_asset() {
        use crate::context::ResolvedInput;
        let (manifest, mut ctx) = create_offer_ctx();
        for (id, asset) in [("collateral_in", COLLATERAL_ID), ("fee_input", "lbtc")] {
            ctx.set_input(ResolvedInput {
                id: id.into(), txid: "00".repeat(32), vout: 0,
                amount_sat: 49_470, asset: asset.into(), issuance_entropy: None,
            });
        }
        let action = create_offer(&manifest);
        let buckets = build_net_effect(action, &ctx, Some(226));
        let wallet = buckets.iter().find(|b| b.heading == "your wallet").unwrap();

        // Every asset's legs must be contiguous (no interleaving): once we leave an
        // asset's run we must never see that asset again.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut prev: Option<String> = None;
        for leg in &wallet.legs {
            let k = leg.asset.clone().unwrap_or_default();
            if prev.as_ref() != Some(&k) {
                assert!(!seen.contains(&k), "asset {k} legs are not contiguous");
                seen.insert(k.clone());
                prev = Some(k);
            }
        }
        // Sanity: the factory-asset debit and credit are adjacent.
        let factory_sym = lookup_asset(
            "c6b7a5fdf1a01787af534dc9252d1c99908d929a16f8862b8925dcf53d089c6b",
        )
        .symbol;
        let idxs: Vec<usize> = wallet.legs.iter().enumerate()
            .filter(|(_, l)| l.asset.as_deref() == Some(factory_sym.as_str()))
            .map(|(i, _)| i).collect();
        assert_eq!(idxs.len(), 2);
        assert_eq!(idxs[1], idxs[0] + 1);
    }

    /// ClaimPrincipal: the borrower NFT is spent and re-output (nets 0), L-BTC nets
    /// to just the fee, and the principal lands. The summary must show only the
    /// latter two — a round-tripping asset is noise.
    #[test]
    fn wallet_nets_omit_round_trips_and_keep_real_movement() {
        use crate::context::ResolvedInput;
        let src = include_str!("../../examples/lending_v3/txmanifest.json");
        let manifest: Manifest = Manifest::from_json_str(src).unwrap();
        let mut ctx = ExecutionContext::new();
        for (k, v) in [
            ("PRINCIPAL_AMOUNT", "1000"),
            ("PRINCIPAL_ASSET_ID", PRINCIPAL_ID),
            ("BORROWER_NFT_ASSET_ID", "a2f1d6000000000000000000000000000000000000000000000000000000001059"),
        ] {
            ctx.set_compile_param(k, v);
        }
        for (id, vout, amount, asset) in [
            ("principal_asset_auth_in", 0u32, 1000u64, PRINCIPAL_ID),
            ("borrower_nft_in", 1, 1, "a2f1d6000000000000000000000000000000000000000000000000000000001059"),
            ("fee_input", 2, 92_509, "lbtc"),
        ] {
            ctx.set_input(ResolvedInput {
                id: id.into(), txid: "00".repeat(32), vout,
                amount_sat: amount, asset: asset.into(), issuance_entropy: None,
            });
        }
        let action = manifest.contract_templates.as_ref().unwrap().get("lending_contract").unwrap()
            .actions.get("ClaimPrincipal").unwrap();
        let buckets = build_net_effect(action, &ctx, Some(195));
        let nets = wallet_nets(&buckets, None);

        let rendered: Vec<(String, i64)> =
            nets.iter().map(|(m, u, _)| (m.symbol.clone(), *u)).collect();
        // The NFT round-trip is gone; L-BTC is exactly −fee; principal is +1000.
        assert_eq!(rendered, vec![("tL-BTC".to_string(), -195), ("tUSD".to_string(), 1000)]);
        assert!(nets.iter().all(|(_, _, exact)| *exact));
    }

    #[test]
    fn fee_line_states_amount_and_that_it_is_already_counted() {
        assert_eq!(
            fee_line(Some(226)).as_deref(),
            Some("network fee: 0.00000226 tL-BTC (included above)")
        );
        // No fee known, or a zero fee, means no line at all.
        assert_eq!(fee_line(None), None);
        assert_eq!(fee_line(Some(0)), None);
    }

    #[test]
    fn wallet_nets_prefers_verified_delta() {
        let delta = WalletDelta {
            fee_sat: 226,
            balances: vec![("lbtc".into(), -3626), (PRINCIPAL_ID.into(), 0)],
        };
        // Verified source wins and still drops zero-net assets.
        let nets = wallet_nets(&[], Some(&delta));
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].0.symbol, "tL-BTC");
        assert_eq!(nets[0].1, -3626);
    }

    #[test]
    fn net_effect_without_fee_falls_back_to_placeholder() {
        use crate::context::ResolvedInput;
        let (manifest, mut ctx) = create_offer_ctx();
        ctx.set_input(ResolvedInput {
            id: "fee_input".into(),
            txid: "00".repeat(32),
            vout: 0,
            amount_sat: 49_470,
            asset: "lbtc".into(),
            issuance_entropy: None,
        });
        let action = create_offer(&manifest);
        let buckets = build_net_effect(action, &ctx, None); // fee unknown
        let wallet = buckets.iter().find(|b| b.heading == "your wallet").unwrap();
        // With no fee we cannot be exact, so change stays a labelled placeholder.
        assert!(wallet.legs.iter().any(|l| l.units.is_none() && l.label.contains("if any")));
    }
}
