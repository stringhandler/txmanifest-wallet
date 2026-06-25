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

/// Run all structural checks against a parsed manifest file.
pub fn validate(manifest: &Manifest) -> Report {
    let mut report = Report::default();

    let utxo_types: BTreeSet<&str> = manifest
        .utxo_types
        .as_ref()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();

    let class_names: BTreeSet<&str> = manifest
        .classes
        .as_ref()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();

    // Collect every action, whether top-level or a class method, tagged with a
    // dot-path location and its bare name (for lifecycle cross-checks).
    let mut actions: Vec<(String, String, &Action)> = Vec::new();
    for (name, action) in &manifest.actions {
        actions.push((format!("actions.{name}"), name.clone(), action));
    }
    if let Some(classes) = &manifest.classes {
        for (cname, cdef) in classes {
            for (mname, method) in &cdef.methods {
                actions.push((format!("classes.{cname}.methods.{mname}"), mname.clone(), method));
            }
            for (fname, fdef) in &cdef.fields {
                let floc = format!("classes.{cname}.fields.{fname}");
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

    for (loc, _bare, action) in &actions {
        check_action(&mut report, &utxo_types, &class_names, &mut referenced, loc, action);
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

    // --- Lifecycle transitions reference real actions --------------------
    if let Some(lifecycle) = &manifest.lifecycle {
        let action_names: BTreeSet<&str> = actions.iter().map(|(_, bare, _)| bare.as_str()).collect();
        if let Some(transitions) = lifecycle.get("transitions").and_then(Value::as_object) {
            for key in transitions.keys() {
                if !action_names.contains(key.as_str()) {
                    report.warn(
                        "lifecycle.transitions",
                        format!("transition '{key}' does not match any action"),
                    );
                }
            }
        }
    }

    report
}

fn check_action(
    report: &mut Report,
    utxo_types: &BTreeSet<&str>,
    class_names: &BTreeSet<&str>,
    referenced: &mut BTreeSet<String>,
    loc: &str,
    action: &Action,
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
                                report.error(iloc, format!("references unknown utxo_type '{name}'"));
                            }
                        }
                        None => report.error(iloc, "utxo_source.utxo_type is not a string"),
                    }
                }
                Value::Object(m) if m.contains_key("if") => {} // conditional — not checked
                other => report.warn(iloc, format!("unrecognized utxo_source: {other}")),
            }
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

    // --- Validations -----------------------------------------------------
    if let Some(validations) = &action.validations {
        let mut validation_ids: BTreeSet<&str> = BTreeSet::new();
        for v in validations {
            if !validation_ids.insert(v.id.as_str()) {
                report.error(format!("{loc}.validations"), format!("duplicate validation id '{}'", v.id));
            }
            let vloc = format!("{loc}.validations.{}", v.id);
            match v.rule.type_.as_str() {
                "arithmetic" => {
                    if v.rule.expr.as_deref().unwrap_or("").trim().is_empty() {
                        report.error(vloc, "arithmetic rule has no expr");
                    }
                }
                "utxo_exists" => match v.rule.utxo_type.as_deref() {
                    Some(name) => {
                        referenced.insert(name.to_string());
                        if !utxo_types.contains(name) {
                            report.error(vloc, format!("utxo_exists references unknown utxo_type '{name}'"));
                        }
                    }
                    None => report.error(vloc, "utxo_exists rule is missing utxo_type"),
                },
                other => report.warn(vloc, format!("unknown validation rule type '{other}'")),
            }
        }
    }

    // --- Constructor / create_instance -----------------------------------
    if action.is_constructor && action.create_instance.is_none() {
        report.warn(loc.to_string(), "is_constructor is true but there is no create_instance block");
    }
    if let Some(ci) = &action.create_instance {
        if !class_names.contains(ci.class.as_str()) {
            report.error(
                format!("{loc}.create_instance"),
                format!("references unknown class '{}'", ci.class),
            );
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
