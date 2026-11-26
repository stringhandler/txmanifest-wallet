//! Every manifest under `examples/` must deserialize into [`Manifest`] and pass `validate`.
//!
//! This is the guard rail for schema work: it fails the moment an example uses a
//! key the Rust model does not know about (once `deny_unknown_fields` is on), or
//! the model gains a required field the examples do not set. Both are exactly the
//! cross-repo drift this repo is meant to be the source of truth for.

use std::path::{Path, PathBuf};

use txmanifest_core::manifest::Manifest;
use txmanifest_core::validate;

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
    assert!(
        !manifests.is_empty(),
        "no example manifests were discovered"
    );

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

/// Every example must also pass `validate --strict` cleanly: its programs compile, match
/// their pinned hashes, and name a compiler version. Examples are what a new user copies
/// first; one that fails validation belongs in `tests/fixtures/`, not here.
#[test]
fn every_example_manifest_validates() {
    let mut failures = Vec::new();
    for path in &example_manifests() {
        let raw = std::fs::read_to_string(path).expect("read example manifest");
        let manifest = Manifest::from_json_str(&raw).expect("parsed by the test above");
        let mut report = validate::validate(&manifest);
        report.extend(validate::validate_programs(
            &manifest,
            path.parent().expect("manifest has a directory"),
        ));
        let report = report.strict();
        if !report.is_ok() || report.warnings() > 0 {
            let name = path.parent().and_then(Path::file_name).unwrap_or_default();
            for issue in &report.issues {
                failures.push(format!(
                    "  {}: {} — {}",
                    name.to_string_lossy(),
                    issue.location,
                    issue.message
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "example manifests have validation issues:\n{}",
        failures.join("\n")
    );
}

/// A caller with no filesystem (a web page) hands the programs over in memory. It must get
/// the findings the file-reading check gives: none for an example with its programs, and
/// an error naming each program when they are left out.
#[test]
fn examples_validate_the_same_from_memory() {
    let mut with_programs = 0;
    for path in &example_manifests() {
        let dir = path.parent().expect("manifest has a directory");
        let name = dir.file_name().unwrap_or_default().to_string_lossy();
        let raw = std::fs::read_to_string(path).expect("read example manifest");
        let manifest = Manifest::from_json_str(&raw).expect("parsed by the test above");

        let (pins, _) = txmanifest_core::programs::resolve(&manifest);
        let files: std::collections::BTreeMap<String, Vec<u8>> = pins
            .values()
            .map(|pin| {
                let bytes = std::fs::read(dir.join(&pin.source)).expect("read example program");
                (pin.source.clone(), bytes)
            })
            .collect();

        let report = validate::validate_programs_in_memory(&manifest, &files).strict();
        let found: Vec<_> = report.issues.iter().map(|i| &i.message).collect();
        assert!(found.is_empty(), "{name}: {found:?}");

        if files.is_empty() {
            continue;
        }
        with_programs += 1;
        let none = std::collections::BTreeMap::new();
        let report = validate::validate_programs_in_memory(&manifest, &none);
        for pin in pins.values() {
            let wanted = format!("{} was not supplied", pin.source);
            assert!(
                report.issues.iter().any(|i| i.message.contains(&wanted)),
                "{name}: no finding says {wanted}"
            );
        }
    }
    assert!(with_programs > 0, "no example has a program");
}
