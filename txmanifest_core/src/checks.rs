//! Rules that decide whether a manifest's registry id is *unambiguous*.
//!
//! Separate from the checks in `tx-manifest-lib::validate`, which ask whether a manifest
//! will run. These ask whether it is safe to sign, so they live where a signing tool can
//! reach them without building an execution engine.

use serde_json::Value;

use crate::canonical;
use crate::report::Report;

/// Check that this file's registry id is *unambiguous*.
///
/// `tx-manifest-lib`'s `validate` asks whether a manifest will run. This asks a
/// different question: given that the file is about to be hashed, signed and published under
/// [`crate::canonical::manifest_id`], can that id mean anything other than exactly this
/// file? Two ways in, and neither shows up as a runtime fault:
///
/// * **Non-integer numbers.** `1.0`, `1e2` and `1.5` all parse, and every JSON library
///   re-serialises them its own way — `100.0` here, `1e2` there. The id would then
///   depend on which implementation computed it, so a registry could not verify a
///   signature it did not produce itself. Integers are re-serialised identically by
///   every implementation, which is why the rule is "integers only" rather than a
///   full [RFC 8785][jcs] number normalisation.
/// * **Non-NFC strings.** `é` written as one code point and as `e` + U+0301 render
///   identically on screen and hash differently. RFC 8785 deliberately leaves Unicode
///   normalisation to the application, so this cannot be fixed downstream of the
///   author: it has to be a rule about what a manifest may contain. Left unchecked, a
///   look-alike manifest could show a signer the same confirmation screen, character
///   for character, under a different id.
///
/// Takes the raw text rather than a `Manifest` because both hazards are lost in
/// parsing: `amount_sat: 1.0` becomes the same `Value` as `1e0`, and the model has no
/// slot in which the difference survives. The walk covers the canonical form, so
/// `$comment` and `$schema` — which are not hashed — are exempt.
///
/// [jcs]: https://www.rfc-editor.org/rfc/rfc8785
pub fn validate_canonical(raw: &str) -> Report {
    let mut report = Report::default();
    // A file that is not JSON at all is reported by the parser, not here.
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        check_canonical_value(&mut report, "", &canonical::canonicalize_document(&value));
    }
    report
}

/// Append a key or an index to a dot-path location.
fn child_loc(parent: &str, key: &str) -> String {
    if parent.is_empty() { key.to_string() } else { format!("{parent}.{key}") }
}

fn check_canonical_value(report: &mut Report, loc: &str, value: &Value) {
    match value {
        // `is_f64` is the whole test: serde_json parses `1`, `-1` and anything that fits
        // an integer into i64/u64, and *everything* else — a fraction, an exponent, a
        // trailing `.0`, an integer too large for 64 bits — into f64. So one predicate
        // catches every number whose written form a re-serialiser could change.
        Value::Number(n) if n.is_f64() => report.error(
            loc,
            format!(
                "{n} is not an integer. A fractional, exponent or `.0` number is \
                 re-serialised differently by different JSON libraries, so the manifest \
                 id would depend on which one computed it. Write it as an integer, or as \
                 a string if it is an amount."
            ),
        ),
        Value::String(text) => check_nfc(report, loc, text, "value"),
        Value::Object(map) => {
            for (key, nested) in map {
                let child = child_loc(loc, key);
                check_nfc(report, &child, key, "key");
                check_canonical_value(report, &child, nested);
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                check_canonical_value(report, &format!("{loc}[{index}]"), nested);
            }
        }
        _ => {}
    }
}

/// Code points of the span where `text` diverges from its NFC form.
///
/// Listing the whole string would bury a single combining mark under the code points of
/// every ASCII character around it, which is the case that actually happens: one accent
/// in a sentence-long label.
fn differing_codepoints(text: &str, normalized: &str) -> String {
    /// Enough to show a base character and the marks that follow it.
    const MAX_SHOWN: usize = 8;

    let original: Vec<char> = text.chars().collect();
    let normal: Vec<char> = normalized.chars().collect();

    let common_prefix = original.iter().zip(&normal).take_while(|(a, b)| a == b).count();
    let common_suffix = original
        .iter()
        .rev()
        .zip(normal.iter().rev())
        .take_while(|(a, b)| a == b)
        .count();

    // The two runs can overlap when a character repeats; clamp to a non-empty span
    // inside the original, since the caller only reaches here for a string that differs.
    let start = common_prefix.min(original.len().saturating_sub(1));
    let end = original.len().saturating_sub(common_suffix).max(start + 1).min(original.len());

    original[start..end]
        .iter()
        .take(MAX_SHOWN)
        .map(|c| format!("U+{:04X}", *c as u32))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Flag a string that is not in Unicode NFC.
///
/// The message cannot show the offending text against its normalised form — that is the
/// point, they look the same — so it names the code points of the part that differs.
fn check_nfc(report: &mut Report, loc: &str, text: &str, what: &str) {
    if unicode_normalization::is_nfc(text) {
        return;
    }
    let normalized: String = unicode_normalization::UnicodeNormalization::nfc(text.chars()).collect();
    let codepoints = differing_codepoints(text, &normalized);
    report.error(
        loc,
        format!(
            "the {what} \"{text}\" is not in Unicode NFC ({codepoints}). It renders \
             exactly like its NFC spelling but hashes to a different manifest id, so a \
             look-alike manifest could show a signer the same screen under another id. \
             Write it as \"{normalized}\"."
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    /// One helper: what does `validate_canonical` say about this raw file?
    fn canonical_messages(raw: &str) -> String {
        validate_canonical(raw)
            .issues
            .iter()
            .map(|i| format!("{} — {}", i.location, i.message))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every way of writing a number that a re-serialiser could change must be caught —
    /// not just the obviously-wrong fraction. `1.0` and `1e2` are the dangerous ones:
    /// they *are* integers to a reader and to JSON Schema, and still round-trip as
    /// `1.0` / `100.0` through one library and `1` / `1e2` through another.
    #[test]
    fn non_integer_numbers_make_the_id_ambiguous() {
        for written in ["1.5", "1.0", "1e2", "-0.0", "18446744073709551616"] {
            let raw = format!(r#"{{ "actions": {{ "A": {{ "outputs": [ {{ "amount_sat": {written} }} ] }} }} }}"#);
            let msg = canonical_messages(&raw);
            assert!(!msg.is_empty(), "`{written}` should be rejected");
            assert!(
                msg.contains("actions.A.outputs[0].amount_sat"),
                "`{written}` should be located precisely: {msg}"
            );
        }

        // Integers — including the largest that fits — are re-serialised identically
        // everywhere, so they are the form the format asks for.
        for written in ["0", "-1", "21000000", "18446744073709551615"] {
            let raw = format!(r#"{{ "actions": {{ "A": {{ "outputs": [ {{ "amount_sat": {written} }} ] }} }} }}"#);
            assert_eq!(canonical_messages(&raw), "", "`{written}` should be accepted");
        }
    }

    /// A string that renders one way and hashes two ways is exactly the hazard clear
    /// signing exists to remove, so it is rejected wherever it appears — including in a
    /// key, which is hashed just like a value.
    #[test]
    fn non_nfc_text_is_rejected_in_values_and_keys() {
        // "café" with a combining acute (U+0065 U+0301) rather than U+00E9.
        let decomposed = "cafe\u{0301}";
        assert_ne!(decomposed, "café", "the two spellings must differ byte-wise");

        let value = format!(r#"{{ "actions": {{ "A": {{ "ui": {{ "label": "{decomposed}" }} }} }} }}"#);
        let msg = canonical_messages(&value);
        assert!(msg.contains("actions.A.ui.label"), "{msg}");
        assert!(msg.contains("U+0301"), "the message must name the code points: {msg}");
        assert!(msg.contains("café"), "the message must show the NFC spelling: {msg}");

        let key = format!(r#"{{ "actions": {{ "{decomposed}": {{}} }} }}"#);
        assert!(canonical_messages(&key).contains("U+0301"), "a key is hashed too");

        // The composed spelling is what the format asks for, and passes.
        assert_eq!(
            canonical_messages(r#"{ "actions": { "A": { "ui": { "label": "café" } } } }"#),
            ""
        );
    }

    /// Unhashed keys are not part of the id, so nothing inside them can make the id
    /// ambiguous. Flagging them would be a false alarm an author cannot act on without
    /// editing prose that provably does not matter.
    #[test]
    fn unhashed_keys_are_exempt() {
        let raw = r#"{ "$comment": 1.5, "$schema": "café", "actions": {} }"#;
        assert_eq!(canonical_messages(raw), "");
    }

    /// The manifests this repo ships are the ones an author copies from.
    #[test]
    fn every_example_manifest_has_an_unambiguous_id() {
        let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples");
        let mut checked = 0;
        for entry in std::fs::read_dir(examples).expect("examples/ should exist") {
            let path = entry.expect("readable entry").path().join("txmanifest.json");
            if !path.is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(&path).expect("readable manifest");
            assert_eq!(canonical_messages(&raw), "", "{}", path.display());
            checked += 1;
        }
        assert!(checked > 0, "no example manifests found");
    }
}
