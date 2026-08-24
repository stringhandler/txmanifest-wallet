//! Publisher signatures that travel inside the manifest.
//!
//! A manifest is published under its [`crate::canonical::manifest_id`]. A `signatures`
//! block at the root lets the endorsement of that id travel in the same file, so a
//! verifier with no network — an air-gapped signer, an offline review — can check it.
//!
//! # What a signature here does and does not mean
//!
//! It means: *this file is byte-for-byte what the holder of key K published.* It does
//! **not** mean the file is trustworthy, because the file supplies the key. Trust in K
//! has to come from somewhere else — a registry, a pinned key, an operator decision.
//!
//! So [`verified_keys`] returns *which keys verified*, never a bool, and a caller must
//! ask "did key K sign?" and fail closed when it did not. A UI that renders "✓ Signed"
//! off a key the file itself supplied is worse than one that renders nothing: an
//! attacker writes their own entry and buys the checkmark for free. That is the exact
//! failure clear signing exists to prevent, reintroduced one layer up.
//!
//! The same reasoning caps the block ([`MAX_SIGNATURES`]) and rejects a repeated key:
//! a list of plausible-looking strangers is a display attack, not an endorsement.
//!
//! # Why the message is tagged twice
//!
//! A signature commits to `tagged("txmanifest/signature/v1", manifest_id)`, not to the
//! id itself. The id is already domain-separated, so signing it directly would be sound
//! today — but the key that signs a manifest is a key that also signs transaction
//! sighashes and covenant witnesses through one generic "sign these 32 bytes" helper.
//! Tagging again means a signature made for one purpose can never be presented as the
//! other, whatever that helper is later pointed at, and leaves room to bind a role or an
//! expiry into the message without changing what a v1 entry looks like.

use anyhow::{bail, Context, Result};
use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{manifest_id, tagged_hash};
use crate::report::Report;

/// Domain separator for what a publisher signs. See the module docs.
pub const SIGNATURE_TAG: &str = "txmanifest/signature/v1";

/// Root key holding the signature list.
pub const SIGNATURES_KEY: &str = "signatures";

/// Most signatures one manifest may carry.
///
/// Not a resource limit — 16 entries is nothing to hash. It bounds how much unverified,
/// attacker-supplied identity a file can put in front of a reader.
pub const MAX_SIGNATURES: usize = 16;

/// One endorsement of a manifest id.
///
/// Deliberately carries *only* what the signature covers. Any other field — a role, a
/// timestamp, a display name — would be unsigned and therefore free for anyone to edit:
/// `"role": "auditor"` relabelled to `"publisher"` costs an attacker nothing. If such a
/// field is ever wanted it has to go into the signed message, not beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// BIP-340 x-only public key, 64 lowercase hex characters.
    pub public_key: String,
    /// BIP-340 Schnorr signature over [`signing_message`], 128 lowercase hex characters.
    pub signature: String,
}

/// The 32 bytes a publisher signs for `manifest_id`.
pub fn signing_message(manifest_id: &[u8; 32]) -> [u8; 32] {
    tagged_hash(SIGNATURE_TAG, manifest_id)
}

fn decode_hex<const N: usize>(hex: &str, what: &str) -> Result<[u8; N]> {
    if hex.len() != N * 2 {
        bail!("{what} must be {} hex characters, got {}", N * 2, hex.len());
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("{what} is not valid hex"))?;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign a manifest id with a raw 32-byte secret key.
pub fn sign(manifest_id: &[u8; 32], secret: &[u8; 32]) -> Result<ManifestSignature> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(secret).context("not a valid secp256k1 secret key")?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let message = Message::from_digest(signing_message(manifest_id));
    let signature = secp.sign_schnorr(&message, &keypair);
    let (public_key, _parity) = keypair.x_only_public_key();
    Ok(ManifestSignature {
        public_key: encode_hex(&public_key.serialize()),
        signature: encode_hex(&signature.serialize()),
    })
}

/// Check one entry against a manifest id, returning its public key on success.
pub fn verify(manifest_id: &[u8; 32], entry: &ManifestSignature) -> Result<String> {
    let key_bytes: [u8; 32] = decode_hex(&entry.public_key, "public_key")?;
    let sig_bytes: [u8; 64] = decode_hex(&entry.signature, "signature")?;

    let public_key = XOnlyPublicKey::from_slice(&key_bytes)
        .context("public_key is not a valid x-only BIP340 key")?;
    let signature = schnorr::Signature::from_slice(&sig_bytes)
        .context("signature is not a valid BIP340 signature")?;
    let message = Message::from_digest(signing_message(manifest_id));

    Secp256k1::new()
        .verify_schnorr(&signature, &message, &public_key)
        .context("signature does not verify against this manifest id")?;
    Ok(encode_hex(&public_key.serialize()))
}

/// The `signatures` entries a raw manifest carries, in file order.
///
/// An absent block is an empty list; a malformed one is an error, because "unsigned" and
/// "signed with something this build cannot read" must never look alike to a caller.
pub fn signatures_of(raw: &str) -> Result<Vec<ManifestSignature>> {
    let document: Value = serde_json::from_str(raw).context("manifest is not valid JSON")?;
    let Some(block) = document.get(SIGNATURES_KEY) else {
        return Ok(Vec::new());
    };
    parse_entries(block)
}

/// Deserialize the block, tolerating an author's `$comment` inside an entry.
///
/// The entry type is `deny_unknown_fields`, and the manifest parser strips authoring
/// keys before it deserializes anything — so without this, a `$comment` beside a
/// signature would load fine through `Manifest` and fail here. One file, two answers, is
/// how a "signed" state and an "unreadable" state get confused.
fn parse_entries(block: &Value) -> Result<Vec<ManifestSignature>> {
    serde_json::from_value(crate::canonical::canonicalize(block))
        .context("`signatures` is not a list of signature entries")
}

/// Every key whose signature over this file verifies.
///
/// Returns keys, not a verdict: see the module docs for why a bool would be the wrong
/// shape. Entries that do not verify are reported by [`check_signatures`]; here they are
/// simply absent, so a caller asking "did key K sign?" cannot accidentally accept one.
pub fn verified_keys(raw: &str) -> Result<Vec<String>> {
    let id = manifest_id(raw)?;
    Ok(signatures_of(raw)?
        .iter()
        .filter_map(|entry| verify(&id, entry).ok())
        .collect())
}

/// Add a signature to a manifest document, returning the new file text.
///
/// Replaces an existing entry for the same key rather than appending a second: one key
/// signing one id twice says nothing extra, and a duplicate is rejected on load anyway.
/// The id is unchanged by this — that is the whole reason the block is unhashed.
pub fn attach(raw: &str, entry: ManifestSignature) -> Result<String> {
    let mut document: Value = serde_json::from_str(raw).context("manifest is not valid JSON")?;
    let object = document
        .as_object_mut()
        .context("manifest root is not a JSON object")?;

    let mut entries: Vec<ManifestSignature> = match object.get(SIGNATURES_KEY) {
        Some(block) => parse_entries(block).context("existing `signatures` block")?,
        None => Vec::new(),
    };
    entries.retain(|existing| existing.public_key != entry.public_key);
    entries.push(entry);
    if entries.len() > MAX_SIGNATURES {
        bail!("a manifest may carry at most {MAX_SIGNATURES} signatures");
    }

    object.insert(SIGNATURES_KEY.to_string(), serde_json::to_value(&entries)?);
    let mut text = serde_json::to_string_pretty(&document)?;
    text.push('\n');
    Ok(text)
}

/// Check the `signatures` block: shape, uniqueness, count, and whether each entry
/// actually verifies against this file's id.
///
/// A signature that does not verify is an **error**, not a warning. The block survives
/// any edit to the manifest — that is what excluding it from the hash buys — so an
/// author who changes a label leaves a well-formed entry behind that now attests to
/// nothing. Left as a warning it would read as "signed" to everything that does not
/// check, and a stale signature is worse than none.
pub fn check_signatures(raw: &str) -> Report {
    let mut report = Report::default();

    let entries = match signatures_of(raw) {
        Ok(entries) => entries,
        Err(err) => {
            report.error(SIGNATURES_KEY, format!("{err:#}"));
            return report;
        }
    };
    if entries.is_empty() {
        return report;
    }

    if entries.len() > MAX_SIGNATURES {
        report.error(
            SIGNATURES_KEY,
            format!("{} signatures; at most {MAX_SIGNATURES} are allowed", entries.len()),
        );
    }

    let id = match manifest_id(raw) {
        Ok(id) => id,
        Err(err) => {
            report.error(SIGNATURES_KEY, format!("cannot compute this manifest's id: {err:#}"));
            return report;
        }
    };

    let mut seen: Vec<&str> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let loc = format!("{SIGNATURES_KEY}[{index}]");

        if seen.contains(&entry.public_key.as_str()) {
            report.error(&loc, format!("{} has already signed this manifest", entry.public_key));
        }
        seen.push(&entry.public_key);

        if let Err(err) = verify(&id, entry) {
            report.error(
                &loc,
                format!(
                    "{err:#}. A signature is over the manifest's id, so editing the manifest \
                     leaves any earlier signature behind, well-formed and meaningless — \
                     re-sign the file, or remove the entry."
                ),
            );
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::manifest_id;

    const MANIFEST: &str = r#"{
        "manifest_version": "0.3.0",
        "protocol": "test",
        "actions": { "Pay": { "outputs": [
            { "id": "o0", "destination": "change", "ui": { "label": "to you" } }
        ] } }
    }"#;

    /// Two distinct 32-byte secrets, written out rather than generated so a failure is
    /// reproducible.
    const PUBLISHER: [u8; 32] = [0x11; 32];
    const AUDITOR: [u8; 32] = [0x22; 32];

    fn sign_with(raw: &str, secret: &[u8; 32]) -> ManifestSignature {
        sign(&manifest_id(raw).unwrap(), secret).expect("signing should succeed")
    }

    #[test]
    fn a_signature_verifies_against_the_manifest_it_was_made_over() {
        let entry = sign_with(MANIFEST, &PUBLISHER);
        let id = manifest_id(MANIFEST).unwrap();
        assert_eq!(verify(&id, &entry).unwrap(), entry.public_key);
    }

    /// The message is *not* the manifest id. A key that signs transaction sighashes and
    /// covenant witnesses through one generic 32-byte signer must not be able to produce
    /// a manifest endorsement by accident, or have one replayed as something else.
    #[test]
    fn the_signed_message_is_domain_separated_from_the_id() {
        let id = manifest_id(MANIFEST).unwrap();
        assert_ne!(signing_message(&id), id);

        // And a signature over the bare id must not pass as a manifest signature.
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&PUBLISHER).unwrap());
        let wrong = secp.sign_schnorr(&Message::from_digest(id), &keypair);
        let (public_key, _) = keypair.x_only_public_key();
        let entry = ManifestSignature {
            public_key: encode_hex(&public_key.serialize()),
            signature: encode_hex(&wrong.serialize()),
        };
        assert!(verify(&id, &entry).is_err(), "an untagged signature must not verify");
    }

    /// Signing must not change what was signed. Everything else here depends on it: it is
    /// what lets a second party countersign without invalidating the first.
    #[test]
    fn attaching_a_signature_leaves_the_id_alone() {
        let once = attach(MANIFEST, sign_with(MANIFEST, &PUBLISHER)).unwrap();
        assert_eq!(manifest_id(MANIFEST).unwrap(), manifest_id(&once).unwrap());

        let twice = attach(&once, sign_with(&once, &AUDITOR)).unwrap();
        assert_eq!(manifest_id(MANIFEST).unwrap(), manifest_id(&twice).unwrap());

        let keys = verified_keys(&twice).unwrap();
        assert_eq!(keys.len(), 2, "both parties should be present: {keys:?}");
        assert!(check_signatures(&twice).is_ok(), "{:?}", check_signatures(&twice).issues);
    }

    /// A signature survives an edit to the manifest, still well-formed and now worthless.
    /// It has to be reported, or it reads as an endorsement of text nobody endorsed.
    #[test]
    fn editing_a_signed_manifest_invalidates_the_signature() {
        let signed = attach(MANIFEST, sign_with(MANIFEST, &PUBLISHER)).unwrap();
        let edited = signed.replace("to you", "to you (safe)");

        assert!(verified_keys(&edited).unwrap().is_empty(), "a stale key must not be listed");
        let report = check_signatures(&edited);
        assert!(!report.is_ok(), "a stale signature must be an error");
        assert!(
            report.issues[0].message.contains("re-sign"),
            "the message should say what to do: {}",
            report.issues[0].message
        );
    }

    /// One key, one endorsement of one id. A second entry for the same key adds nothing
    /// and pads the list a reader is shown.
    #[test]
    fn a_key_cannot_appear_twice() {
        let once = attach(MANIFEST, sign_with(MANIFEST, &PUBLISHER)).unwrap();
        let again = attach(&once, sign_with(&once, &PUBLISHER)).unwrap();
        assert_eq!(signatures_of(&again).unwrap().len(), 1, "re-signing must replace");

        // A hand-built duplicate — both entries valid, so the only complaint left is the
        // repetition itself.
        let mut document: Value = serde_json::from_str(&once).unwrap();
        let entries = document[SIGNATURES_KEY].as_array_mut().unwrap();
        entries.push(entries[0].clone());
        let doubled = serde_json::to_string(&document).unwrap();

        let report = check_signatures(&doubled);
        assert!(!report.is_ok(), "a repeated key must be flagged");
        assert!(
            report.issues.iter().any(|i| i.message.contains("already signed")),
            "{:?}",
            report.issues
        );
    }

    /// `verified_keys` is the trust-facing API, so it must never surface a key whose
    /// signature failed — a caller matching against a trusted list would then accept a
    /// forged entry that merely names the right key.
    #[test]
    fn a_forged_entry_is_absent_from_the_verified_list() {
        let honest = sign_with(MANIFEST, &PUBLISHER);
        let forged = ManifestSignature {
            public_key: honest.public_key.clone(),
            signature: "00".repeat(64),
        };
        let signed = attach(MANIFEST, forged).unwrap();
        assert!(verified_keys(&signed).unwrap().is_empty());
        assert!(!check_signatures(&signed).is_ok());
    }

    /// An author's `$comment` beside a signature loads through the manifest parser, so it
    /// must load here too — one file cannot be readable to one path and broken to another.
    #[test]
    fn an_authoring_comment_beside_a_signature_is_tolerated() {
        let entry = sign_with(MANIFEST, &PUBLISHER);
        let raw = format!(
            r#"{{ "manifest_version": "0.3.0", "protocol": "test", "actions": {{}},
                  "signatures": [ {{ "$comment": "release key",
                                     "public_key": "{}", "signature": "{}" }} ] }}"#,
            entry.public_key, entry.signature
        );
        assert_eq!(signatures_of(&raw).unwrap().len(), 1);
    }
}
