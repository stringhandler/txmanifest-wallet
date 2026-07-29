//! The published JSON Schema for `txmanifest.json`, derived from the model types.
//!
//! The schema is **generated**, never hand-written: [`crate::manifest::Manifest`] is the
//! source of truth, and `tests/schema.rs` fails if the checked-in file drifts from what
//! the current types produce. That is the whole point — a hand-maintained schema and a
//! serde model diverge within weeks, and then downstream repos validate against a
//! fiction.
//!
//! Regenerate with:
//!
//! ```sh
//! cargo run -p tx-manifest-lib --example gen_schema
//! ```
//!
//! Consumers in other languages point at [`SCHEMA_ID`] for editor completion and CI
//! validation without building this crate.

use schemars::gen::SchemaSettings;
use serde_json::{json, Map, Value};

use crate::manifest::Manifest;

/// Canonical on-disk location, relative to the workspace root.
pub const SCHEMA_PATH: &str = "schema/txmanifest.schema.json";

/// Stable URL authors put in their manifest's `$schema` key.
pub const SCHEMA_ID: &str = "https://raw.githubusercontent.com/stringhandler/manifest-wallet/main/schema/txmanifest.schema.json";

/// Build the schema document for a manifest file.
///
/// Draft-07 rather than a later draft: it has the widest editor support, which is the
/// only reason this artifact exists.
pub fn json_schema() -> Value {
    let settings = SchemaSettings::draft07().with(|s| {
        // Named subschemas under `$defs`/`definitions` keep the output readable and
        // let the recursive Action/Input/Output types reference each other.
        s.inline_subschemas = false;
    });
    let schema = settings.into_generator().into_root_schema_for::<Manifest>();
    let mut value = serde_json::to_value(schema).expect("schema serializes");

    // `$comment` is legal at any depth; admit it everywhere first.
    admit_comment_key(&mut value);

    let root = value.as_object_mut().expect("root schema is an object");
    root.insert("$id".to_string(), json!(SCHEMA_ID));
    root.insert("title".to_string(), json!("Transaction Manifest (txmanifest.json)"));
    // `$schema` is only meaningful on the root document, so admit it only there. The
    // parser strips it at any depth, which makes the schema marginally stricter than
    // the engine — the safe direction: an author can be warned about something that
    // would have parsed, but never left unwarned about something that would not.
    if let Some(Value::Object(props)) = root.get_mut("properties") {
        props.entry("$schema".to_string()).or_insert_with(|| {
            json!({
                "type": "string",
                "description": "Editor hint pointing at this schema; ignored by the engine.",
            })
        });
    }
    value
}

/// Exactly the bytes stored at [`SCHEMA_PATH`]: pretty-printed, trailing newline.
pub fn json_schema_string() -> String {
    let mut out = serde_json::to_string_pretty(&json_schema()).expect("schema serializes");
    out.push('\n');
    out
}

/// Re-admit `$comment` wherever the derive emitted `additionalProperties: false`.
///
/// `deny_unknown_fields` becomes `additionalProperties: false`, which would make an
/// editor flag the `$comment` prose already present in this repo's own examples. The
/// parser strips it, so the schema must permit it, or the two disagree about what a
/// valid file looks like.
fn admit_comment_key(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let closed = map.get("additionalProperties") == Some(&Value::Bool(false));
            if closed {
                if let Some(Value::Object(props)) = map.get_mut("properties") {
                    add_comment_property(props);
                }
            }
            for nested in map.values_mut() {
                admit_comment_key(nested);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(admit_comment_key),
        _ => {}
    }
}

/// Insert the `$comment` property declaration into one `properties` map.
fn add_comment_property(props: &mut Map<String, Value>) {
    props.entry("$comment".to_string()).or_insert_with(|| {
        json!({
            "type": "string",
            "description": "Documentation only; ignored by the engine.",
        })
    });
}
