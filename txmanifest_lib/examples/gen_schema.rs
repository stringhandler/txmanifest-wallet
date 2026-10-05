//! Regenerate the checked-in JSON Schema for `txmanifest.json`.
//!
//! ```sh
//! cargo run -p tx-manifest-lib --example gen_schema
//! ```
//!
//! `tests/schema.rs` fails when the checked-in file differs from what this produces,
//! so run this after any change to the model types in `manifest.rs`.

use std::path::Path;

use tx_manifest_lib::schema::{json_schema_string, SCHEMA_PATH};

fn main() -> anyhow::Result<()> {
    // Examples run with the crate root as CWD; the schema lives at the workspace root.
    let out = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(SCHEMA_PATH);
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let rendered = json_schema_string();
    let unchanged = std::fs::read_to_string(&out).is_ok_and(|existing| existing == rendered);
    std::fs::write(&out, &rendered)?;

    println!(
        "{} {} ({} bytes)",
        if unchanged { "unchanged:" } else { "wrote:" },
        out.display(),
        rendered.len()
    );
    Ok(())
}
