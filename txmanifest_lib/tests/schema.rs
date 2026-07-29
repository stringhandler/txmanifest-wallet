//! The published JSON Schema must stay in lockstep with the Rust model, and every
//! example manifest must satisfy it.
//!
//! These two tests are what make the schema trustworthy for downstream repos. Without
//! the first, the checked-in file quietly becomes a fiction the moment someone edits
//! `manifest.rs`. Without the second, the schema could be self-consistent and still
//! reject the manifests this engine actually runs.

use std::path::{Path, PathBuf};

use tx_manifest_lib::schema::{json_schema, json_schema_string, SCHEMA_PATH};

/// Workspace root — one level up from this crate.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn checked_in_schema_path() -> PathBuf {
    workspace_root().join(SCHEMA_PATH)
}

/// Every `examples/*/txmanifest.json`, sorted for stable output.
fn example_manifests() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(workspace_root().join("examples"))
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
fn checked_in_schema_matches_the_model() {
    let path = checked_in_schema_path();
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} is missing ({err}).\n\nRegenerate it:\n  cargo run -p tx-manifest-lib --example gen_schema",
            path.display()
        )
    });

    assert_eq!(
        on_disk,
        json_schema_string(),
        "\n{} is out of date with the Rust model in manifest.rs.\n\n\
         Regenerate it:\n  cargo run -p tx-manifest-lib --example gen_schema\n",
        path.display()
    );
}

/// Compile the generated schema for validation.
fn compiled_schema() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&json_schema())
        .expect("the generated schema should itself be a valid draft-07 schema")
}

#[test]
fn schema_rejects_an_unknown_field() {
    // Guards the `additionalProperties: false` that `deny_unknown_fields` produces.
    // If this ever passes, the schema has stopped catching typos in downstream repos
    // and is worse than useless — it would be actively reassuring about broken files.
    let bad = serde_json::json!({
        "manifest_version": "0.1.0",
        "protocol": "test",
        "actions": { "A": { "inputs": [
            { "id": "in0", "utxo_source": "wallet", "from_addres": "typo" }
        ] } }
    });
    assert!(
        compiled_schema().validate(&bad).is_err(),
        "schema must reject a misspelled field"
    );
}

#[test]
fn schema_accepts_the_authoring_keys() {
    // `$schema` at the root, `$comment` at depth — both stripped by the parser, so
    // both must validate or the schema and the engine disagree.
    let ok = serde_json::json!({
        "$schema": tx_manifest_lib::schema::SCHEMA_ID,
        "$comment": "file-level note",
        "manifest_version": "0.1.0",
        "protocol": "test",
        "actions": { "A": { "inputs": [
            { "id": "in0", "utxo_source": "wallet", "$comment": "why this input exists" }
        ] } }
    });
    let schema = compiled_schema();
    let result = schema.validate(&ok);
    if let Err(errors) = result {
        let joined: Vec<String> = errors.map(|e| format!("{e} at /{}", e.instance_path)).collect();
        panic!("authoring keys should validate, got:\n{}", joined.join("\n"));
    }
}

#[test]
fn every_example_manifest_validates_against_the_schema() {
    let compiled = compiled_schema();
    let manifests = example_manifests();
    assert!(!manifests.is_empty(), "no example manifests were discovered");

    let mut failures = Vec::new();
    for path in &manifests {
        let raw = std::fs::read_to_string(path).expect("read example manifest");
        let instance: serde_json::Value =
            serde_json::from_str(&raw).expect("example manifest should be valid JSON");

        let name = path
            .parent()
            .and_then(Path::file_name)
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Bound to a local declared *after* `instance` so the borrowing error
        // iterator is dropped before the value it borrows from.
        let result = compiled.validate(&instance);
        if let Err(errors) = result {
            for error in errors {
                failures.push(format!("  {name}: {error} at /{}", error.instance_path));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} schema violation(s) across {} example manifests:\n{}",
        failures.len(),
        manifests.len(),
        failures.join("\n")
    );
}
