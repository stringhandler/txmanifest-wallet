//! Canonical form and registry identity for a manifest.
//!
//! A manifest is meant to be signed and published under a stable id. Hashing the
//! file bytes would make that id depend on things that carry no meaning — key
//! order, indentation, and prose — so a reformat or a typo fix in a comment would
//! mint a new id and invalidate the signature.
//!
//! [`canonicalize`] therefore reduces a manifest to the subset that determines
//! what a transaction *does* and what a signer *reads*, and [`manifest_id`] hashes
//! that.
//!
//! # What is excluded, and why that is safe
//!
//! Two kinds of key are dropped, and they are safe for **different reasons**. Conflating
//! them is how a hole gets added by analogy, so they are stated separately.
//!
//! ## Developer prose: [`UNHASHED_KEYS`]
//!
//! The rule is not "prose vs structure" but **"can a user read it before authorising?"**
//!
//! The format answers that question in the key name rather than leaving it to be
//! rediscovered per field. `$comment` is developer prose and is stripped before
//! deserialization, so no amount of engine code can leak it onto a screen — that is
//! what makes dropping it from the hash safe, rather than a promise nobody enforces.
//! `$schema` is an editor hint, stripped the same way.
//!
//! Everything a signer reads — `ui.action`, `ui.label`, `ui.role`, `ui_help` — **is**
//! hashed. Excluding it would let an attacker rewrite the confirmation screen while
//! keeping a valid signature, which is precisely the attack clear signing exists to
//! stop. `ui_help` counts: it is the text a user reads while deciding what value to
//! type into a prompt, and steering that is as good as steering the screen.
//!
//! This is why the format has no `description`. It was a single key doing both jobs —
//! unhashed like a comment, yet printed to the user like a label — and the invariant
//! above could only be stated, not enforced.
//!
//! ## Publisher signatures: [`UNHASHED_ROOT_KEYS`]
//!
//! `signatures` fails *both* halves of the rule above — the engine must read it to
//! verify it, and a wallet does show who signed — so it is unhashed on a different
//! argument entirely: **its content is checked against the hash**. A prose key is
//! trusted; a signature key is verified. An attacker who rewrites an entry produces one
//! that fails [`crate::signature::verify`], and cannot assert anything not derived from
//! a public key and this id.
//!
//! Excluding it is also what makes the block useful. A signature that changed the id
//! would invalidate every other signature over the same file, so only the first signer
//! could ever exist; excluded, any number of parties sign the same id independently, in
//! any order, and stripping the block back off leaves the id untouched.
//!
//! The corollary is that the file cannot prove its own signature set: removing an entry
//! is as invisible as adding one. Trust policy must therefore be "I require key X",
//! which fails closed, and never "show me who signed", which an attacker fills in.
//!
//! Unhashed at the **root only**. Nested, `signatures` is a key no model type declares,
//! so `deny_unknown_fields` rejects the file outright — deliberately, because "unhashed"
//! must not be a property that can appear at arbitrary depth.
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
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Keys removed before hashing: documentation that may change without re-signing.
///
/// Identical to [`crate::manifest::STRIPPED_KEYS`], and necessarily so: a key is safe
/// to leave out of the hash exactly when the parser guarantees it can never reach a
/// user. Anything added here that the parser still deserializes is a hole.
pub const UNHASHED_KEYS: [&str; 2] = ["$comment", "$schema"];

/// Keys removed before hashing **at the root only**: the signatures over this very id.
///
/// Unlike [`UNHASHED_KEYS`] these are parsed and read — see the module docs for why that
/// is safe here and nowhere else.
pub const UNHASHED_ROOT_KEYS: [&str; 1] = ["signatures"];

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
    canonicalize_inner(value, false)
}

/// [`canonicalize`] for a whole manifest document: also drops [`UNHASHED_ROOT_KEYS`].
///
/// Separate from [`canonicalize`] because the root is the only place those keys are
/// legal, and a function that dropped them at any depth would quietly launder a nested
/// `signatures` key that the parser is supposed to reject.
pub fn canonicalize_document(value: &Value) -> Value {
    canonicalize_inner(value, true)
}

fn canonicalize_inner(value: &Value, is_root: bool) -> Value {
    match value {
        Value::Object(map) => {
            // serde_json's Map is a BTreeMap unless `preserve_order` is on; rebuilding
            // through a sorted Vec makes the ordering explicit either way.
            let mut entries: Vec<(&String, &Value)> = map
                .iter()
                .filter(|(k, _)| !UNHASHED_KEYS.contains(&k.as_str()))
                .filter(|(k, _)| !(is_root && UNHASHED_ROOT_KEYS.contains(&k.as_str())))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, v) in entries {
                out.insert(k.clone(), canonicalize_inner(v, false));
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| canonicalize_inner(item, false)).collect())
        }
        other => other.clone(),
    }
}

/// The exact bytes hashed by [`manifest_id`]: canonical JSON, compact, UTF-8.
///
/// Exposed so a registry can store or re-verify the preimage rather than trusting a
/// bare digest, and so another implementation can diff its own canonical form.
pub fn canonical_bytes(raw: &str) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_str(raw).context("manifest is not valid JSON")?;
    let canonical = canonicalize_document(&value);
    serde_json::to_vec(&canonical).context("canonical form should serialise")
}

/// The manifest's registry id: a tagged SHA-256 over [`canonical_bytes`].
///
/// `sha256(sha256(tag) || sha256(tag) || canonical_bytes)`, per BIP-340's tagged
/// hash construction.
pub fn manifest_id(raw: &str) -> Result<[u8; 32]> {
    Ok(tagged_hash(MANIFEST_ID_TAG, &canonical_bytes(raw)?))
}

/// BIP-340's tagged hash: `sha256(sha256(tag) || sha256(tag) || message)`.
///
/// Shared with [`crate::signature`], which tags again rather than signing a manifest id
/// directly, so that one key signing for several purposes can never be replayed across
/// them.
pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(message);
    engine.finalize().into()
}

/// [`manifest_id`] as lowercase hex — the form a registry key would take.
pub fn manifest_id_hex(raw: &str) -> Result<String> {
    Ok(manifest_id(raw)?.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{
        "manifest_version": "0.3.0",
        "protocol": "test",
        "$comment": "the original prose",
        "actions": { "A": {
            "$comment": "does a thing",
            "params": { "amount": { "type": "u64", "ui_help": "how much to send" } },
            "outputs": [
                { "id": "o0", "destination": "change",
                  "$comment": "developer note",
                  "ui": { "label": "change back to you", "role": "change" } }
            ]
        }}
    }"#;

    #[test]
    fn editing_a_comment_does_not_change_the_id() {
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
    fn editing_prompt_help_does_change_the_id() {
        // `ui_help` is read by a user deciding what to type. Rewriting "how much to
        // send" into "enter the attacker's amount" must invalidate the signature, or
        // the prompt is a steering surface with no integrity behind it.
        let attacked = BASE.replace("how much to send", "how much to send (any value is fine)");
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
        let two = r#"{"manifest_version": "0.3.0","protocol":"t","actions":{"A":{"outputs":[
            {"id":"a","destination":"change"},{"id":"b","destination":"change"}]}}}"#;
        let swapped = r#"{"manifest_version": "0.3.0","protocol":"t","actions":{"A":{"outputs":[
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
        assert!(text.contains("how much to send"), "ui_help must be hashed");
    }

    /// A pinned vector. The id is the registry's primary key and the thing signatures
    /// commit to, so it must not move when the hash implementation is swapped, the JSON
    /// crate is upgraded, or this module is refactored — none of which a behavioural test
    /// would catch. If this fails, every published id and signature just broke.
    #[test]
    fn the_id_of_a_fixed_manifest_never_moves() {
        const PINNED: &str =
            r#"{"manifest_version":"0.3.0","protocol":"test","actions":{"A":{"outputs":[{"id":"o0","destination":"change"}]}}}"#;
        // Preimage, for an implementation in another language to diff against:
        // {"actions":{"A":{"outputs":[{"destination":"change","id":"o0"}]}},
        //  "manifest_version":"0.3.0","protocol":"test"}
        assert_eq!(
            manifest_id_hex(PINNED).unwrap(),
            "b9efb57ed611668af0c97f3bae1b1fa9bfd1c4d61b945e3e5a1200faf7462168"
        );
    }

    /// Signing must not change what was signed — the property the whole scheme rests on.
    #[test]
    fn a_root_signatures_block_is_not_hashed() {
        let signed = BASE.replace(
            "\"protocol\": \"test\",",
            "\"protocol\": \"test\", \"signatures\": [{\"public_key\": \"aa\", \"signature\": \"bb\"}],",
        );
        assert_eq!(manifest_id(BASE).unwrap(), manifest_id(&signed).unwrap());
        let text = String::from_utf8(canonical_bytes(&signed).unwrap()).unwrap();
        assert!(!text.contains("signatures"), "the block must not reach the preimage");
    }

    /// Only at the root. Nested, `signatures` is a key no model type declares — so the
    /// parser rejects the file — but the canonicaliser must not launder it in the
    /// meantime, or "unhashed" becomes a property that can hide at any depth.
    #[test]
    fn a_nested_signatures_key_is_still_hashed() {
        let nested = BASE.replace(
            "\"params\": {",
            "\"signatures\": [{\"public_key\": \"aa\"}], \"params\": {",
        );
        assert_ne!(manifest_id(BASE).unwrap(), manifest_id(&nested).unwrap());
    }

    #[test]
    fn id_is_tagged() {
        // A bare sha256 over the same preimage must not equal the tagged id.
        let bytes = canonical_bytes(BASE).unwrap();
        let untagged: [u8; 32] = Sha256::digest(&bytes).into();
        assert_ne!(manifest_id(BASE).unwrap(), untagged);
    }
}
