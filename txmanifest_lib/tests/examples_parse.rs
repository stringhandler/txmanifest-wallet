//! Every manifest under `examples/` must deserialize into [`Manifest`].
//!
//! This is the guard rail for schema work: it fails the moment an example uses a
//! key the Rust model does not know about (once `deny_unknown_fields` is on), or
//! the model gains a required field the examples do not set. Both are exactly the
//! cross-repo drift this repo is meant to be the source of truth for.

use std::path::{Path, PathBuf};

use tx_manifest_lib::manifest::Manifest;

/// Absolute path to the workspace-level `examples/` directory.
fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples")
}

/// Every `examples/*/txmanifest.json`, sorted for stable failure output.
fn example_manifests() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(examples_dir())
        .expect("examples/ should exist")
        .filter_map(|entry| {
            let path = entry.ok()?.path().join("txmanifest.json");
            path.is_file().then_some(path)
        })
        .collect();
    found.sort();
    found
}

#[test]
fn every_example_manifest_parses() {
    let manifests = example_manifests();
    assert!(!manifests.is_empty(), "no example manifests were discovered");

    let mut failures = Vec::new();
    for path in &manifests {
        let raw = std::fs::read_to_string(path).expect("read example manifest");
        if let Err(err) = Manifest::from_json_str(&raw) {
            let name = path.parent().and_then(Path::file_name).unwrap_or_default();
            failures.push(format!("  {}: {err}", name.to_string_lossy()));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} example manifests failed to parse:\n{}",
        failures.len(),
        manifests.len(),
        failures.join("\n")
    );
}
