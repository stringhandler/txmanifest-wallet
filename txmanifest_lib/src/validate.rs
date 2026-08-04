//! Static schema/sanity checks for a parsed manifest file.
//!
//! This module performs *structural* validation only — it does not touch the
//! network, the wallet, or the filesystem, and it does not compile any
//! SimplicityHL. It catches the obvious mistakes that would otherwise only
//! surface part-way through `run`: references to UTXO types that don't
//! exist, outputs with no amount, duplicate ids, malformed destinations, and so
//! on.
//!
//! Future work (compiling `.simf` leaves, checking formula references resolve,
//! verifying `canonical_cmr` values) can be layered on top of the same
//! [`Report`] type.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::manifest::{Action, Manifest};

/// Severity of a single validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A definite problem: the file will not run correctly as written.
    Error,
    /// A likely mistake or smell, but not necessarily fatal.
    Warning,
}

/// One finding produced by [`validate`].
#[derive(Debug, Clone)]
pub struct Issue {
    pub severity: Severity,
    /// Dot-path to the offending element, e.g. `actions.Pay.outputs.p2pk_out`.
    pub location: String,
    pub message: String,
}

/// The result of validating a manifest file.
#[derive(Debug, Default)]
pub struct Report {
    pub issues: Vec<Issue>,
}

impl Report {
    fn error(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Error,
            location: location.into(),
            message: message.into(),
        });
    }

    fn warn(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Warning,
            location: location.into(),
            message: message.into(),
        });
    }

    /// Number of error-severity issues.
    pub fn errors(&self) -> usize {
        self.issues.iter().filter(|i| i.severity == Severity::Error).count()
    }

    /// Number of warning-severity issues.
    pub fn warnings(&self) -> usize {
        self.issues.iter().filter(|i| i.severity == Severity::Warning).count()
    }

    /// True when there are no errors (warnings are allowed).
    pub fn is_ok(&self) -> bool {
        self.errors() == 0
    }
}

/// Declared manifest types visible to one action's `ui.action` references: the
/// enclosing contract template's fields (`instance.X`) plus the action's own
/// params (`params.X`). Keyed by bare name, which is how a token is looked up.
fn param_types(
    action: &Action,
    template: Option<&crate::manifest::ContractTemplate>,
) -> std::collections::BTreeMap<String, String> {
    let mut types = std::collections::BTreeMap::new();
    if let Some(template) = template {
        for (name, def) in &template.fields {
            types.insert(name.clone(), def.type_.clone());
        }
    }
    for (name, def) in action.params.iter().flatten() {
        types.insert(name.clone(), def.type_.clone());
    }
    types
}

/// Check one hook block's `set` values.
///
/// `set` is `ComputeSpec`-valued so that every "name → how to produce a value" map in
/// the format reads alike, but only the expression forms actually run in a hook: a
/// hook fires at a fixed point in the flow, with no `.simf` path, network or wallet
/// threaded through it. Rejecting the rest here — rather than at run time — keeps a
/// manifest from parsing cleanly and then silently skipping an assignment.
fn check_hook(report: &mut Report, loc: &str, hook: &crate::manifest::HookBlock) {
    use crate::manifest::ParamCompute;
    for (target, spec) in &hook.set {
        let tloc = format!("{loc}.set.{target}");
        let Some(compute) = spec.as_spec() else { continue }; // bare expression: fine
        match compute {
            ParamCompute::Expr { .. } => {}
            ParamCompute::Wallet { .. } => report.error(
                tloc,
                "a hook cannot take a value from the wallet: the value would differ per user, and an `instance.*` field feeds covenant addresses that must be reproducible from the manifest alone",
            ),
            ParamCompute::Tapleaf { .. } | ParamCompute::SimfFn { .. } => report.error(
                tloc,
                "only expression values run in a hook; compute a tapleaf or simf_fn as an action param or a create_instance field instead",
            ),
        }
    }
}

/// Run all structural checks against a parsed manifest file.
pub fn validate(manifest: &Manifest) -> Report {
    let mut report = Report::default();

    let utxo_types: BTreeSet<&str> = manifest
        .utxo_types
        .as_ref()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();

    // Collect every action, whether top-level or a class method, tagged with a
    // dot-path location and its bare name (for lifecycle cross-checks).
    let mut actions: Vec<(String, String, &Action, std::collections::BTreeMap<String, String>, bool)> =
        Vec::new();
    for (name, action) in &manifest.actions {
        actions.push((format!("actions.{name}"), name.clone(), action, param_types(action, None), false));
    }
    if let Some(contract_templates) = &manifest.contract_templates {
        for (cname, cdef) in contract_templates {
            for (aname, method) in &cdef.actions {
                actions.push((
                    format!("contract_templates.{cname}.actions.{aname}"),
                    aname.clone(),
                    method,
                    param_types(method, Some(cdef)),
                    true,
                ));
            }
            for (fname, fdef) in &cdef.fields {
                let floc = format!("contract_templates.{cname}.fields.{fname}");
                if let Some(desc) = &fdef.description {
                    if desc.trim().is_empty() {
                        report.warn(&floc, "description is present but empty");
                    }
                }
                if let Some(dv) = &fdef.default {
                    if dv.trim().is_empty() {
                        report.warn(floc, "default is present but empty");
                    }
                }
            }
        }
    }

    // --- Top-level sanity -------------------------------------------------
    if manifest.protocol.trim().is_empty() {
        report.warn("protocol", "protocol identifier is empty");
    }
    if let Some(chain) = &manifest.chain {
        let c = chain.to_lowercase();
        if !matches!(c.as_str(), "bitcoin" | "elements" | "liquid" | "cross-chain") {
            report.warn(
                "chain",
                format!("unrecognized chain '{chain}' (expected bitcoin, liquid/elements, or cross-chain)"),
            );
        }
    }
    if actions.is_empty() {
        report.warn("actions", "no actions or class methods are defined");
    }

    // Track which UTXO types get referenced so we can flag dead ones.
    let mut referenced: BTreeSet<String> = BTreeSet::new();

    for (loc, _bare, action, field_types, in_template) in &actions {
        check_action(&mut report, &utxo_types, &mut referenced, loc, action, *in_template);
        check_ui(&mut report, loc, action, field_types);
    }

    // --- Unreferenced UTXO types -----------------------------------------
    for name in &utxo_types {
        if !referenced.contains(*name) {
            report.warn(
                format!("utxo_types.{name}"),
                "declared but never referenced by any action",
            );
        }
    }

    report
}

fn check_action(
    report: &mut Report,
    utxo_types: &BTreeSet<&str>,
    referenced: &mut BTreeSet<String>,
    loc: &str,
    action: &Action,
    in_template: bool,
) {
    // --- Inputs ----------------------------------------------------------
    if let Some(inputs) = &action.inputs {
        let mut input_ids: BTreeSet<&str> = BTreeSet::new();
        for input in inputs {
            if !input_ids.insert(input.id.as_str()) {
                report.error(format!("{loc}.inputs"), format!("duplicate input id '{}'", input.id));
            }
            let iloc = format!("{loc}.inputs.{}", input.id);
            match &input.utxo_source {
                Value::String(s) if s == "wallet" => {}
                Value::Object(m) if m.contains_key("utxo_type") => {
                    match m["utxo_type"].as_str() {
                        Some(name) => {
                            referenced.insert(name.to_string());
                            if !utxo_types.contains(name) {
                                report.error(&iloc, format!("references unknown utxo_type '{name}'"));
                            }
                        }
                        None => report.error(&iloc, "utxo_source.utxo_type is not a string"),
                    }
                }
                Value::Object(m) if m.contains_key("if") => {} // conditional — not checked
                other => report.warn(&iloc, format!("unrecognized utxo_source: {other}")),
            }
            check_witnesses(report, &format!("{iloc}.witnesses"), &input.witnesses);
        }
    }

    // --- Outputs ---------------------------------------------------------
    if let Some(outputs) = &action.outputs {
        let mut output_ids: BTreeSet<&str> = BTreeSet::new();
        for output in outputs {
            if !output_ids.insert(output.id.as_str()) {
                report.error(format!("{loc}.outputs"), format!("duplicate output id '{}'", output.id));
            }
            let oloc = format!("{loc}.outputs.{}", output.id);
            let requires_amount = check_destination(report, utxo_types, referenced, &oloc, &output.destination);
            let optional = output.optional.unwrap_or(false);
            if requires_amount && output.amount_sat.is_none() && !optional {
                report.error(oloc, "missing amount_sat (required for this destination)");
            }
        }
    }

    // --- Hooks ------------------------------------------------------------
    for (field, hook) in [
        ("on_pre_broadcast", &action.on_pre_broadcast),
        ("on_post_broadcast", &action.on_post_broadcast),
    ] {
        if let Some(hook) = hook {
            check_hook(report, &format!("{loc}.{field}"), hook);
        }
    }
    for input in action.inputs.iter().flatten() {
        if let Some(hook) = &input.on_resolved {
            check_hook(report, &format!("{loc}.inputs.{}.on_resolved", input.id), hook);
        }
    }

    // --- Constructors -----------------------------------------------------
    // An action carrying `create_instance` is a constructor, and it constructs an
    // instance of the template it is declared in. A standalone action has no
    // enclosing template, so there is nothing for it to construct.
    if action.create_instance.is_some() && !in_template {
        report.error(
            format!("{loc}.create_instance"),
            "create_instance is only legal on an action inside a contract template;              the instance created is always of that template",
        );
    }
}

// ---------------------------------------------------------------------------
// Clear-signing UI budget
// ---------------------------------------------------------------------------

/// Maximum length of a per-leg `ui.label`.
///
/// A net-effect row renders as `± <amount> <symbol>  <label>`. On an 80-column
/// terminal the amount and symbol claim roughly the first 20 columns, so 64 leaves
/// the label a full line with margin. Labels do not interpolate, so this is a plain
/// character count.
pub const MAX_UI_LABEL: usize = 64;

/// Maximum **worst-case rendered** length of an `ui.action` summary.
///
/// `ui.action` is a template, so its authored length is not what a signer reads.
/// The budget is computed by substituting each `{token}` with the widest value it
/// could resolve to — see [`UI_TOKEN_AMOUNT_WIDTH`] and [`UI_TOKEN_SYMBOL_WIDTH`].
pub const MAX_UI_ACTION_RENDERED: usize = 160;

/// Widest rendering of a bare `{ref}` that resolves to a number.
///
/// `u64::MAX` is 18446744073709551615 — 20 digits. `format_amount` may insert a
/// decimal point for a non-zero precision (`184467440737.09551615`), so the worst
/// case is 21 characters. This is the "max number of 0s" bound.
pub const UI_TOKEN_AMOUNT_WIDTH: usize = 21;

/// Widest rendering of a `{ref:symbol}` token.
///
/// A known asset renders its ticker (`tL-BTC`); an unknown one renders an elided
/// id (`38fca2…50a5`, 11 chars). 12 leaves room for a wallet's own registry to
/// substitute a slightly longer friendly tag without blowing the budget.
pub const UI_TOKEN_SYMBOL_WIDTH: usize = 12;

/// Width of an untagged 32-byte value rendered in full: 64 hex characters.
///
/// This is why [`check_ui_action`] requires `:symbol` on asset-typed references —
/// a bare `{instance.SOME_ASSET_ID}` puts all 64 characters on the signer's screen
/// and defeats any budget.
pub const UI_RAW_HASH_WIDTH: usize = 64;

/// Manifest types that are 32-byte values and must never be rendered raw.
const HASHED_TYPES: &[&str] = &["liquid.asset_id", "bytes32", "pubkey", "u256"];

/// Split a `ui.action` template into its literal text and its `{token}` list.
fn split_template(template: &str) -> (String, Vec<String>) {
    let mut literal = String::new();
    let mut tokens = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        literal.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            literal.push_str(&rest[open..]);
            return (literal, tokens);
        };
        tokens.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    literal.push_str(rest);
    (literal, tokens)
}

/// Check one action's `ui` metadata: label lengths, the rendered-width budget, and
/// that every asset-typed reference is tagged `:symbol`.
///
/// `field_types` maps a reference name (template field or action param) to its
/// declared manifest type, so `{instance.X}` can be classified.
fn check_ui(
    report: &mut Report,
    loc: &str,
    action: &Action,
    field_types: &std::collections::BTreeMap<String, String>,
) {
    // -- per-leg labels ---------------------------------------------------
    let mut check_label = |leg_loc: String, label: Option<&str>| {
        if let Some(label) = label {
            let len = label.chars().count();
            if len > MAX_UI_LABEL {
                report.error(
                    leg_loc,
                    format!(
                        "ui.label is {len} chars, over the {MAX_UI_LABEL}-char budget \
                         (it shares a line with the amount and asset symbol)"
                    ),
                );
            }
        }
    };
    for input in action.inputs.iter().flatten() {
        check_label(format!("{loc}.inputs.{}", input.id), input.ui_label());
    }
    for output in action.outputs.iter().flatten() {
        check_label(format!("{loc}.outputs.{}", output.id), output.ui_label());
    }

    // -- action summary ---------------------------------------------------
    let Some(template) = action.intent.as_deref() else {
        return;
    };
    let uloc = format!("{loc}.intent");
    let (literal, tokens) = split_template(template);

    let mut worst = literal.chars().count();
    for token in &tokens {
        let (reference, modifier) = match token.split_once(':') {
            Some((r, m)) => (r.trim(), Some(m.trim())),
            None => (token.trim(), None),
        };
        // `instance.X` / `params.X` → X; a bare name stays as-is.
        let key = reference.rsplit('.').next().unwrap_or(reference);
        let declared = field_types.get(key).map(String::as_str);
        let is_hashed = declared.is_some_and(|t| HASHED_TYPES.contains(&t));

        match modifier {
            Some("symbol") => worst += UI_TOKEN_SYMBOL_WIDTH,
            Some(other) => {
                report.warn(&uloc, format!("unknown token modifier ':{other}' in '{{{token}}}'"));
                worst += UI_TOKEN_AMOUNT_WIDTH;
            }
            None if is_hashed => {
                // The whole point of the tag: a wallet substitutes a friendly name
                // for the id. Rendered raw this is 64 characters of hex.
                report.error(
                    &uloc,
                    format!(
                        "'{{{token}}}' is a {} and must be tagged '{{{reference}:symbol}}' — \
                         rendered raw it is {UI_RAW_HASH_WIDTH} hex characters, and a wallet \
                         cannot substitute a friendly asset name",
                        declared.unwrap_or("32-byte value"),
                    ),
                );
                worst += UI_RAW_HASH_WIDTH;
            }
            None => worst += UI_TOKEN_AMOUNT_WIDTH,
        }
    }

    if worst > MAX_UI_ACTION_RENDERED {
        report.error(
            &uloc,
            format!(
                "worst-case rendered length is {worst} chars, over the \
                 {MAX_UI_ACTION_RENDERED}-char budget ({} literal + {} token(s) at up to \
                 {UI_TOKEN_AMOUNT_WIDTH} chars each)",
                literal.chars().count(),
                tokens.len(),
            ),
        );
    }
}

/// Witness `type` values the runtime knows how to consume. Anything else is
/// silently ignored by covenant satisfaction, so flag it here.
///
/// - `simplicityhl` — a concrete witness value (`build_witness_values_from_types`)
/// - `Signature`    — a computed BIP340 signature (`inject_computed_signatures`)
/// - `taproot_leaf` — selects the spend leaf (e.g. `SPEND_PATH`)
const KNOWN_WITNESS_TYPES: &[&str] = &["simplicityhl", "Signature", "taproot_leaf"];

/// Validate an input's (or action's) `witnesses` map.
///
/// The runtime only feeds a witness to the BitMachine when its definition is an
/// object carrying a recognized `type`. A bare scalar (e.g. `"FOO": 1`) or an
/// object missing/with an unknown `type` is silently dropped and zero-filled,
/// which produces a covenant that fails at `run` time with no hint as to why —
/// exactly the failure this check exists to surface statically.
fn check_witnesses(report: &mut Report, loc: &str, witnesses: &Option<Value>) {
    let Some(witnesses) = witnesses else { return };
    let Some(map) = witnesses.as_object() else {
        report.error(loc.to_string(), "witnesses must be an object (name → definition)");
        return;
    };
    for (name, def) in map {
        let wloc = format!("{loc}.{name}");
        let Some(obj) = def.as_object() else {
            report.error(
                wloc,
                format!(
                    "witness '{name}' must be an object like \
                     {{\"type\": \"simplicityhl\", \"simplicity_type\": \"u32\", \"value\": \"1\"}}; \
                     a bare value is silently ignored and zero-filled at run time"
                ),
            );
            continue;
        };
        match obj.get("type").and_then(Value::as_str) {
            None => report.error(
                wloc,
                format!("witness '{name}' is missing a string \"type\" and will be ignored at run time"),
            ),
            Some("simplicityhl") => {
                let value_ok = obj.get("value").and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty());
                if !value_ok {
                    report.error(
                        wloc,
                        format!("simplicityhl witness '{name}' is missing a non-empty string \"value\""),
                    );
                }
            }
            Some("Signature") => {
                if obj.get("sig_type").and_then(Value::as_str).is_none() {
                    report.error(
                        wloc,
                        format!("Signature witness '{name}' is missing a string \"sig_type\""),
                    );
                }
            }
            Some("taproot_leaf") => {}
            Some(other) => report.warn(
                wloc,
                format!(
                    "witness '{name}' has unrecognized type '{other}' (expected one of: {})",
                    KNOWN_WITNESS_TYPES.join(", ")
                ),
            ),
        }
    }
}

/// Validate an output `destination` and return whether it requires an explicit
/// `amount_sat` (covenant, wallet, address, and script_hash destinations do;
/// change, op_return/burn, fee, and conditional destinations do not).
fn check_destination(
    report: &mut Report,
    utxo_types: &BTreeSet<&str>,
    referenced: &mut BTreeSet<String>,
    oloc: &str,
    destination: &Value,
) -> bool {
    match destination {
        // "change" auto-computes its amount; any other string is treated as a
        // wallet keyword or an address/param expression and needs an amount.
        Value::String(s) => s != "change",
        Value::Object(m) => {
            if let Some(name) = m.get("utxo_type").and_then(Value::as_str) {
                referenced.insert(name.to_string());
                if !utxo_types.contains(name) {
                    report.error(oloc.to_string(), format!("destination references unknown utxo_type '{name}'"));
                }
                true
            } else if m.contains_key("script_hash") {
                true
            } else if let Some(t) = m.get("type").and_then(Value::as_str) {
                match t {
                    "op_return" | "burn" | "fee" => false,
                    other => {
                        report.error(oloc.to_string(), format!("unknown destination type '{other}'"));
                        false
                    }
                }
            } else if m.contains_key("if") {
                false // conditional — not checked
            } else {
                report.error(oloc.to_string(), format!("unrecognized destination: {destination}"));
                false
            }
        }
        other => {
            report.error(oloc.to_string(), format!("destination must be a string or object, got {other}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    /// Build a manifest with a single action whose one wallet input carries the
    /// given `witnesses` JSON, then validate it.
    fn validate_with_input_witnesses(witnesses: Value) -> Report {
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "manifest_version": "1",
            "protocol": "test",
            "actions": {
                "A": {
                    "inputs": [
                        { "id": "in0", "utxo_source": "wallet", "witnesses": witnesses }
                    ]
                }
            }
        }))
        .expect("test manifest should deserialize");
        validate(&manifest)
    }

    fn has_error_at(report: &Report, loc: &str) -> bool {
        report
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.location == loc)
    }

    #[test]
    fn bare_integer_witness_is_flagged() {
        // Regression: `"INPUT_ASSET_INDEX": 1` used to be silently zero-filled at
        // run time, producing a covenant failure with no static warning.
        let report = validate_with_input_witnesses(serde_json::json!({
            "INPUT_ASSET_INDEX": 1
        }));
        assert!(
            has_error_at(&report, "actions.A.inputs.in0.witnesses.INPUT_ASSET_INDEX"),
            "expected an error for the bare-integer witness, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn well_formed_witnesses_pass() {
        let report = validate_with_input_witnesses(serde_json::json!({
            "INPUT_ASSET_INDEX": { "type": "simplicityhl", "simplicity_type": "u32", "value": "1" },
            "SIGNATURE": { "type": "Signature", "sig_type": "sig_hash_all" },
            "SPEND_PATH": { "type": "taproot_leaf", "source": { "type": "formula", "expr": "leaf" } }
        }));
        assert_eq!(report.errors(), 0, "unexpected errors: {:?}", report.issues);
    }

    #[test]
    fn simplicityhl_without_value_is_flagged() {
        let report = validate_with_input_witnesses(serde_json::json!({
            "FOO": { "type": "simplicityhl", "simplicity_type": "u32" }
        }));
        assert!(has_error_at(&report, "actions.A.inputs.in0.witnesses.FOO"));
    }

    #[test]
    fn missing_type_is_flagged() {
        let report = validate_with_input_witnesses(serde_json::json!({
            "FOO": { "value": "1" }
        }));
        assert!(has_error_at(&report, "actions.A.inputs.in0.witnesses.FOO"));
    }

    #[test]
    fn unknown_type_is_a_warning_not_error() {
        let report = validate_with_input_witnesses(serde_json::json!({
            "FOO": { "type": "mystery" }
        }));
        assert_eq!(report.errors(), 0, "unexpected errors: {:?}", report.issues);
        assert!(report.warnings() >= 1);
    }

    // -- clear-signing UI budget ------------------------------------------

    /// Build a one-method contract template whose method carries the given `ui`,
    /// with `PRINCIPAL_ASSET_ID` (an asset) and `AMOUNT` (a u64) declared as fields.
    fn validate_with_ui(intent: Option<&str>, legs: Value) -> Report {
        let manifest: Manifest = Manifest::from_json_str(&serde_json::json!({
            "manifest_version": "1",
            "protocol": "test",
            "contract_templates": { "T": {
                "fields": {
                    "PRINCIPAL_ASSET_ID": { "type": "liquid.asset_id" },
                    "AMOUNT": { "type": "u64" }
                },
                "actions": { "M": { "intent": intent, "outputs": legs } }
            }}
        }).to_string())
        .expect("test manifest should parse");
        validate(&manifest)
    }

    fn errors_at(report: &Report, loc: &str) -> Vec<String> {
        report
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Error && i.location == loc)
            .map(|i| i.message.clone())
            .collect()
    }

    #[test]
    fn over_long_ui_label_is_an_error() {
        let long = "x".repeat(MAX_UI_LABEL + 1);
        let report = validate_with_ui(
            None,
            serde_json::json!([
                { "id": "o0", "destination": "change", "ui": { "label": long } }
            ]),
        );
        let errs = errors_at(&report, "contract_templates.T.actions.M.outputs.o0");
        assert!(
            errs.iter().any(|m| m.contains("over the")),
            "expected a label-length error, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn label_at_the_budget_is_accepted() {
        let exact = "x".repeat(MAX_UI_LABEL);
        let report = validate_with_ui(
            None,
            serde_json::json!([
                { "id": "o0", "destination": "change", "ui": { "label": exact } }
            ]),
        );
        assert_eq!(report.errors(), 0, "unexpected errors: {:?}", report.issues);
    }

    #[test]
    fn untagged_asset_reference_is_an_error() {
        // The whole point of `:symbol`: a bare asset ref renders 64 hex characters
        // and gives a wallet nothing to substitute a friendly name for.
        let report = validate_with_ui(
            Some("send {instance.PRINCIPAL_ASSET_ID}"),
            serde_json::json!([]),
        );
        let errs = errors_at(&report, "contract_templates.T.actions.M.intent");
        assert!(
            errs.iter().any(|m| m.contains(":symbol")),
            "expected an untagged-asset error, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn tagged_asset_reference_is_accepted() {
        let report = validate_with_ui(
            Some("send {instance.AMOUNT} {instance.PRINCIPAL_ASSET_ID:symbol}"),
            serde_json::json!([]),
        );
        assert_eq!(report.errors(), 0, "unexpected errors: {:?}", report.issues);
    }

    #[test]
    fn action_budget_counts_worst_case_not_template_length() {
        // Short template, but each bare numeric token can render 21 chars, so the
        // worst case is what must be measured.
        let tokens = "{instance.AMOUNT} ".repeat(8);
        let report = validate_with_ui(
            Some(tokens.as_str()),
            serde_json::json!([]),
        );
        let errs = errors_at(&report, "contract_templates.T.actions.M.intent");
        assert!(
            errs.iter().any(|m| m.contains("worst-case rendered")),
            "expected a worst-case budget error, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn create_instance_outside_a_template_is_an_error() {
        // A standalone action has no enclosing template, so there is nothing for it
        // to construct — and the old `create_instance.template` let it name any.
        let manifest: Manifest = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t",
                 "actions": { "A": { "create_instance": { "fields": {} } } } }"#,
        )
        .expect("test manifest should parse");
        let report = validate(&manifest);
        assert!(
            errors_at(&report, "actions.A.create_instance")
                .iter()
                .any(|m| m.contains("inside a contract template")),
            "expected a placement error, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn create_instance_inside_a_template_is_accepted() {
        let manifest: Manifest = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t",
                 "contract_templates": { "T": { "fields": {},
                   "actions": { "A": { "create_instance": { "fields": {} } } } } } }"#,
        )
        .expect("test manifest should parse");
        assert_eq!(validate(&manifest).errors(), 0);
    }

    // -- hooks -------------------------------------------------------------

    /// Build a manifest whose single action carries `on_pre_broadcast.set`.
    fn validate_with_hook(set: Value) -> Report {
        let manifest: Manifest = Manifest::from_json_str(
            &serde_json::json!({
                "manifest_version": "1",
                "protocol": "test",
                "actions": { "A": { "on_pre_broadcast": { "set": set } } }
            })
            .to_string(),
        )
        .expect("test manifest should parse");
        validate(&manifest)
    }

    #[test]
    fn hook_accepts_expression_values_in_both_spellings() {
        // The bare string is what every existing hook already writes; the structured
        // form must mean the same thing.
        let report = validate_with_hook(serde_json::json!({
            "instance.A": "params.X * 2",
            "params.B": { "type": "expr", "expr": "params.X + 1" }
        }));
        assert_eq!(report.errors(), 0, "unexpected errors: {:?}", report.issues);
    }

    #[test]
    fn hook_rejects_wallet_values() {
        // A wallet value differs per user; an instance field feeds covenant addresses.
        let report = validate_with_hook(serde_json::json!({
            "instance.KEY": { "type": "wallet", "wallet": "key" }
        }));
        assert!(
            errors_at(&report, "actions.A.on_pre_broadcast.set.instance.KEY")
                .iter()
                .any(|m| m.contains("wallet")),
            "expected a wallet rejection, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn hook_rejects_tapleaf_and_simf_fn() {
        for spec in [
            serde_json::json!({ "type": "tapleaf", "simf": "./a.simf" }),
            serde_json::json!({ "type": "simf_fn", "simf": "./a.simf" }),
        ] {
            let report = validate_with_hook(serde_json::json!({ "instance.H": spec }));
            assert!(
                !errors_at(&report, "actions.A.on_pre_broadcast.set.instance.H").is_empty(),
                "expected a rejection, got: {:?}",
                report.issues
            );
        }
    }

    #[test]
    fn on_resolved_hooks_are_checked_too() {
        // The input hook and the action hook are one type now, so one rule covers both.
        let manifest: Manifest = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t", "actions": { "A": { "inputs": [
                 { "id": "in0", "utxo_source": "wallet", "on_resolved": { "set": {
                   "instance.K": { "type": "wallet", "wallet": "key" } } } } ] } } }"#,
        )
        .expect("test manifest should parse");
        let report = validate(&manifest);
        assert!(
            !errors_at(&report, "actions.A.inputs.in0.on_resolved.set.instance.K").is_empty(),
            "expected the input hook to be checked, got: {:?}",
            report.issues
        );
    }
}
