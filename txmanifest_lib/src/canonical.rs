//! Canonical form and registry identity for a manifest.
//!
//! A manifest is meant to be signed and published under a stable id. Hashing the
//! file bytes would make that id depend on things that carry no meaning — key
//! order, indentation, and prose — so a reformat or a typo fix in a description
//! would mint a new id and invalidate the signature.
//!
//! [`canonicalize`] therefore reduces a manifest to the subset that determines
//! what a transaction *does* and what a signer *reads*, and [`manifest_id`] hashes
//! that.
//!
//! # What is excluded, and why that is safe
//!
//! Only developer prose is dropped: [`UNHASHED_KEYS`]. The rule is not "prose vs
//! structure" but **"can a user read it before authorising?"**
//!
//! - `description` — developer documentation. `preview.rs` deliberately does *not*
//!   fall back to it, so it never reaches a confirmation screen.
//! - `$comment` / `$schema` — authoring conventions, already stripped at parse time.
//!
//! Everything a signer reads — `ui.action`, `ui.label`, `ui.role` — **is** hashed.
//! Excluding it would let an attacker rewrite the confirmation screen while keeping
//! a valid signature, which is precisely the attack clear signing exists to stop.
//!
//! # Limits
//!
//! This implements structural canonicalization (key ordering, whitespace, prose
//! removal). It does **not** yet do full [RFC 8785][jcs] JCS: numeric literals are
//! re-serialised by `serde_json` rather than normalised per the spec, and strings
//! are not Unicode-normalised (NFC). Manifests carry amounts as strings and ASCII
//! identifiers, so neither bites today — but a registry accepting third-party files
//! should close both before treating an id as adversarially collision-resistant.
//!
//! [jcs]: https://www.rfc-editor.org/rfc/rfc8785

use anyhow::{Context, Result};
use lwk_wollet::elements::hashes::{sha256, Hash as _, HashEngine as _};
use serde_json::{Map, Value};

/// Keys removed before hashing: documentation that may change without re-signing.
///
/// `description` is included deliberately — see the module docs. If it ever becomes
/// signer-visible again, it must move back into the hash.
pub const UNHASHED_KEYS: [&str; 3] = ["description", "$comment", "$schema"];

/// Domain separator for the manifest id, in the style of BIP-340 tagged hashes.
///
/// Tagging keeps a manifest id from ever colliding with a hash computed for another
/// purpose (a script hash, a tapleaf) over coincidentally identical bytes.
pub const MANIFEST_ID_TAG: &str = "txmanifest/id/v1";

/// Reduce a parsed manifest to its canonical form: [`UNHASHED_KEYS`] removed at any
/// depth, and every object's keys in sorted order.
///
/// Array order is preserved — input and output ordering is consensus-relevant.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            // serde_json's Map is a BTreeMap unless `preserve_order` is on; rebuilding
            // through a sorted Vec makes the ordering explicit either way.
            let mut entries: Vec<(&String, &Value)> = map
                .iter()
                .filter(|(k, _)| !UNHASHED_KEYS.contains(&k.as_str()))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, v) in entries {
                out.insert(k.clone(), canonicalize(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// The exact bytes hashed by [`manifest_id`]: canonical JSON, compact, UTF-8.
///
/// Exposed so a registry can store or re-verify the preimage rather than trusting a
/// bare digest, and so another implementation can diff its own canonical form.
pub fn canonical_bytes(raw: &str) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_str(raw).context("manifest is not valid JSON")?;
    let canonical = canonicalize(&value);
    serde_json::to_vec(&canonical).context("canonical form should serialise")
}

/// The manifest's registry id: a tagged SHA-256 over [`canonical_bytes`].
///
/// `sha256(sha256(tag) || sha256(tag) || canonical_bytes)`, per BIP-340's tagged
/// hash construction.
pub fn manifest_id(raw: &str) -> Result<[u8; 32]> {
    let bytes = canonical_bytes(raw)?;
    let tag = sha256::Hash::hash(MANIFEST_ID_TAG.as_bytes());
    let mut engine = sha256::HashEngine::default();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(&bytes);
    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}

/// [`manifest_id`] as lowercase hex — the form a registry key would take.
pub fn manifest_id_hex(raw: &str) -> Result<String> {
    Ok(manifest_id(raw)?.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{
        "manifest_version": "0.1.0",
        "protocol": "test",
        "description": "the original prose",
        "actions": { "A": {
            "description": "does a thing",
            "outputs": [
                { "id": "o0", "destination": "change",
                  "description": "developer note",
                  "ui": { "label": "change back to you", "role": "change" } }
            ]
        }}
    }"#;

    #[test]
    fn editing_a_description_does_not_change_the_id() {
        // The whole point: prose churn must not mint a new registry entry.
        let edited = BASE
            .replace("the original prose", "completely rewritten, much longer prose")
            .replace("developer note", "a different note entirely");
        assert_eq!(manifest_id(BASE).unwrap(), manifest_id(&edited).unwrap());
    }

    #[test]
    fn reformatting_does_not_change_the_id() {
        // Key order and whitespace are not meaning.
        let value: Value = serde_json::from_str(BASE).unwrap();
        let reformatted = serde_json::to_string_pretty(&value).unwrap();
        let compact = serde_json::to_string(&value).unwrap();
        assert_eq!(manifest_id(BASE).unwrap(), manifest_id(&reformatted).unwrap());
        assert_eq!(manifest_id(BASE).unwrap(), manifest_id(&compact).unwrap());
    }

    #[test]
    fn editing_signer_visible_text_does_change_the_id() {
        // `ui.label` is what the user reads before authorising. If this ever passes,
        // a manifest could be re-skinned without invalidating its signature.
        let attacked = BASE.replace("change back to you", "change back to you (safe)");
        assert_ne!(manifest_id(BASE).unwrap(), manifest_id(&attacked).unwrap());
    }

    #[test]
    fn changing_structure_changes_the_id() {
        let attacked = BASE.replace("\"destination\": \"change\"", "\"destination\": \"wallet\"");
        assert_ne!(manifest_id(BASE).unwrap(), manifest_id(&attacked).unwrap());
    }

    #[test]
    fn array_order_is_significant() {
        // Input/output ordering is consensus-relevant — covenants introspect by index.
        let two = r#"{"manifest_version":"1","protocol":"t","actions":{"A":{"outputs":[
            {"id":"a","destination":"change"},{"id":"b","destination":"change"}]}}}"#;
        let swapped = r#"{"manifest_version":"1","protocol":"t","actions":{"A":{"outputs":[
            {"id":"b","destination":"change"},{"id":"a","destination":"change"}]}}}"#;
        assert_ne!(manifest_id(two).unwrap(), manifest_id(swapped).unwrap());
    }

    #[test]
    fn canonical_bytes_carry_no_unhashed_keys() {
        let bytes = canonical_bytes(BASE).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for key in UNHASHED_KEYS {
            assert!(!text.contains(key), "canonical form still contains '{key}'");
        }
        assert!(text.contains("change back to you"), "ui.label must be hashed");
    }

    #[test]
    fn id_is_tagged() {
        // A bare sha256 over the same preimage must not equal the tagged id.
        let bytes = canonical_bytes(BASE).unwrap();
        let untagged = sha256::Hash::hash(&bytes).to_byte_array();
        assert_ne!(manifest_id(BASE).unwrap(), untagged);
    }
}
