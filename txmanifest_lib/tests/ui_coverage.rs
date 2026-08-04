//! Every action and every transaction leg must declare its clear-signing UI text.
//!
//! `ui.label` is the only source of signer-facing text for a leg — `preview.rs`
//! deliberately does not fall back to `description`, because `description` is
//! developer prose that sits outside the manifest's registry hash and so must never
//! reach a screen the user reads before authorising a transaction. A leg with no
//! `ui.label` renders as its bare manifest id (`active_offer_in`), which tells a
//! signer nothing.
//!
//! This walks every example rather than one, so a leg added later cannot quietly
//! ship label-less.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tx_manifest_lib::manifest::{Action, Manifest};

/// Examples not yet migrated to explicit UI text, with the reason.
///
/// These predate the clear-signing work. They are NOT permanently excused: the
/// `exemptions_are_still_needed` test fails once an entry is fully covered, so the
/// list shrinks to nothing rather than rotting.
const EXEMPT: &[(&str, &str)] = &[
    ("last_will", "11 legs / 4 actions, no ui text authored yet"),
    (
        "lending",
        "90 legs / 10 actions; largely superseded by lending_v3",
    ),
    (
        "lending_v2",
        "90 legs / 9 actions; wire-compat variant of lending",
    ),
    ("p2pk", "7 legs / 2 actions, no ui text authored yet"),
];

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples")
}

/// `(example_name, parsed manifest)` for every example, sorted by name.
fn examples() -> Vec<(String, Manifest)> {
    let mut found: Vec<(String, Manifest)> = std::fs::read_dir(examples_dir())
        .expect("examples/ should exist")
        .filter_map(|entry| {
            let dir = entry.ok()?.path();
            let path = dir.join("txmanifest.json");
            if !path.is_file() {
                return None;
            }
            let name = dir.file_name()?.to_string_lossy().to_string();
            let raw = std::fs::read_to_string(&path).ok()?;
            let manifest = Manifest::from_json_str(&raw)
                .unwrap_or_else(|e| panic!("{name}/txmanifest.json should parse: {e}"));
            Some((name, manifest))
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Every action in a manifest, standalone or template method, keyed by a dot-path.
fn all_actions(manifest: &Manifest) -> BTreeMap<String, &Action> {
    let mut out: BTreeMap<String, &Action> = manifest
        .actions
        .iter()
        .map(|(n, a)| (n.clone(), a))
        .collect();
    for (tname, template) in manifest.contract_templates.iter().flatten() {
        for (aname, method) in &template.actions {
            out.insert(format!("{tname}.{aname}"), method);
        }
    }
    out
}

/// Missing-UI findings for one manifest, as human-readable dot-paths.
fn ui_gaps(manifest: &Manifest) -> Vec<String> {
    let mut gaps = Vec::new();
    for (action_name, action) in all_actions(manifest) {
        // The one-line summary of intent — the first clear-signing screen.
        if action.intent.as_deref().is_none() {
            gaps.push(format!("{action_name}: no intent summary"));
        }
        for input in action.inputs.iter().flatten() {
            if input.ui_label().is_none() {
                gaps.push(format!("{action_name}.inputs.{}: no ui.label", input.id));
            }
            if input.ui_role().is_none() {
                gaps.push(format!("{action_name}.inputs.{}: no ui.role", input.id));
            }
        }
        for output in action.outputs.iter().flatten() {
            if output.ui_label().is_none() {
                gaps.push(format!("{action_name}.outputs.{}: no ui.label", output.id));
            }
            if output.ui_role().is_none() {
                gaps.push(format!("{action_name}.outputs.{}: no ui.role", output.id));
            }
        }
    }
    gaps
}

fn is_exempt(name: &str) -> bool {
    EXEMPT.iter().any(|(n, _)| *n == name)
}

#[test]
fn every_leg_declares_ui_label_and_role() {
    let examples = examples();
    assert!(!examples.is_empty(), "no example manifests were discovered");

    let mut failures = Vec::new();
    for (name, manifest) in &examples {
        if is_exempt(name) {
            continue;
        }
        for gap in ui_gaps(manifest) {
            failures.push(format!("  {name}/{gap}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} leg(s) missing clear-signing UI text:\n{}\n\n\
         `ui.label` is what a signer reads; there is no `description` fallback.",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn exemptions_are_still_needed() {
    // An exemption that no longer applies is worse than none: it silently stops
    // enforcing a rule the example already satisfies. Fail so the entry is removed.
    let examples = examples();
    let mut stale = Vec::new();

    for (name, _reason) in EXEMPT {
        match examples.iter().find(|(n, _)| n == name) {
            None => stale.push(format!("  '{name}' is exempt but no such example exists")),
            Some((_, manifest)) if ui_gaps(manifest).is_empty() => stale.push(format!(
                "  '{name}' is fully covered now — remove it from EXEMPT"
            )),
            Some(_) => {}
        }
    }

    assert!(
        stale.is_empty(),
        "stale UI-coverage exemptions:\n{}",
        stale.join("\n")
    );
}
