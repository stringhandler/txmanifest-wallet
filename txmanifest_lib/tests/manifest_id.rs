//! The registry id must hold over the manifests this engine actually ships, not just
//! over the hand-written fixtures in `canonical.rs`.
//!
//! Two properties matter to a registry. The id must be **stable** under changes that
//! carry no meaning — otherwise a reformat silently invalidates a signature — and the
//! bytes it is computed over must still be a **complete** manifest, or the id vouches
//! for something the engine would not run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tx_manifest_lib::canonical::{canonical_bytes, manifest_id_hex, UNHASHED_KEYS};
use tx_manifest_lib::manifest::Manifest;

/// Every `examples/*/txmanifest.json`, sorted for stable output.
fn example_manifests() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut found: Vec<PathBuf> = std::fs::read_dir(root.join("examples"))
        .expect("examples/ should exist")
        .filter_map(|entry| {
            let path = entry.ok()?.path().join("txmanifest.json");
            path.is_file().then_some(path)
        })
        .collect();
    found.sort();
    assert!(!found.is_empty(), "no example manifests found");
    found
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// Prose and layout are not identity: reformatting a shipped manifest must leave its id
/// alone. This is the promise that lets an author fix indentation after signing.
#[test]
fn reformatting_a_shipped_manifest_keeps_its_id() {
    for path in example_manifests() {
        let raw = read(&path);
        let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        let pretty = serde_json::to_string_pretty(&value).expect("re-serialises");
        let compact = serde_json::to_string(&value).expect("re-serialises");

        let id = manifest_id_hex(&raw).expect("id");
        assert_eq!(id, manifest_id_hex(&pretty).expect("id"), "{}", path.display());
        assert_eq!(id, manifest_id_hex(&compact).expect("id"), "{}", path.display());
    }
}

/// The preimage must lose nothing but prose. If canonicalization ever dropped a key the
/// engine reads, the id would attest to a file that behaves differently from the one on
/// disk — the exact failure a registry cannot detect.
///
/// Checked against an independent stripper rather than against `canonicalize` itself:
/// comparing the function to its own output would only prove idempotence.
#[test]
fn canonical_form_loses_nothing_but_prose() {
    /// Remove [`UNHASHED_KEYS`] at every depth, touching nothing else.
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.retain(|k, _| !UNHASHED_KEYS.contains(&k.as_str()));
                map.values_mut().for_each(strip);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }

    for path in example_manifests() {
        let raw = read(&path);

        let mut expected: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        strip(&mut expected);

        let bytes = canonical_bytes(&raw).expect("canonical bytes");
        let canonical_text = String::from_utf8(bytes).expect("canonical form is UTF-8");
        let actual: serde_json::Value = serde_json::from_str(&canonical_text).expect("valid JSON");

        // Object comparison is key-order-insensitive, which is the point: only the
        // *content* has to match, since sorting is what canonicalization is for.
        assert_eq!(actual, expected, "canonicalizing {} changed its content", path.display());

        // And the bytes a registry stores must still load as a runnable manifest.
        Manifest::from_json_str(&canonical_text)
            .unwrap_or_else(|err| panic!("{} canonical form no longer parses: {err}", path.display()));
    }
}

/// Unhashed keys are unhashed everywhere, at every depth, in real files.
#[test]
fn shipped_manifests_hash_no_developer_prose() {
    for path in example_manifests() {
        let bytes = canonical_bytes(&read(&path)).expect("canonical bytes");
        let text = String::from_utf8(bytes).expect("canonical form is UTF-8");
        for key in UNHASHED_KEYS {
            assert!(!text.contains(key), "{} still hashes '{key}'", path.display());
        }
    }
}

/// Distinct examples must land on distinct ids — a cheap smoke test that the digest is
/// actually a function of the content and not of, say, the first N bytes.
#[test]
fn distinct_examples_get_distinct_ids() {
    let mut seen: HashMap<String, PathBuf> = HashMap::new();
    for path in example_manifests() {
        let id = manifest_id_hex(&read(&path)).expect("id");
        if let Some(other) = seen.insert(id.clone(), path.clone()) {
            panic!("{} and {} share id {id}", other.display(), path.display());
        }
    }
}

/// The root `signatures` block is the one unhashed key the engine reads, and it is legal
/// at the root *only*. Nowhere else declares the field, so `deny_unknown_fields` rejects
/// it — the guarantee that stops "unhashed" from being something that can appear at any
/// depth. Asserted here because it is a property of the model, not of the canonicaliser,
/// and a stray `#[serde(flatten)]` somewhere could quietly undo it.
#[test]
fn signatures_are_a_root_only_key() {
    let root = r#"{ "manifest_version": "0.3.0", "protocol": "t", "actions": {},
                    "signatures": [ { "public_key": "aa", "signature": "bb" } ] }"#;
    Manifest::from_json_str(root).expect("a root signatures block must parse");

    let nested = r#"{ "manifest_version": "0.3.0", "protocol": "t",
                      "actions": { "A": {
                        "signatures": [ { "public_key": "aa", "signature": "bb" } ] } } }"#;
    let err = Manifest::from_json_str(nested).expect_err("a nested block must be rejected");
    assert!(err.to_string().contains("signatures"), "{err}");
}
