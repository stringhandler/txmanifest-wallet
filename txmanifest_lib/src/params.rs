use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::instance::InstanceFile;

/// Merged parameter defaults from all override sources, in ascending priority:
///
/// 1. Manifest file `default` fields  (lowest — applied per-param at prompt time)
/// 2. Auto-discovered `<stem>.<network>.json` alongside the manifest file
/// 3. Explicit `--params <file>`                               (highest)
///
/// Values from this struct pre-fill prompts; the user can always press Enter to
/// accept or type a new value to override.
pub struct ParamOverrides {
    values: BTreeMap<String, String>,
}

impl ParamOverrides {
    /// Load and merge all override sources.  Sources that don't exist are
    /// silently skipped.  Priority (highest last, wins):
    ///   1. Auto-discovered `<stem>.<network>.json`
    ///   2. Explicit `--params` file
    ///   3. Instance file `compile_params` (locked-in from a prior run)
    pub fn load(
        manifest_file: &Path,
        network: Option<&str>,
        params_file: Option<&Path>,
        instance: Option<&InstanceFile>,
    ) -> Result<Self> {
        let mut values = BTreeMap::new();

        // Auto-discovered network file: <parent>/<stem>.<network>.json
        if let Some(network) = network {
            let path = network_params_path(manifest_file, network);
            if path.exists() {
                eprintln!("Loading network params: {}", path.display());
                values.extend(load_params_file(&path)?);
            } else {
                eprintln!(
                    "Note: no network params file found at {} — skipping.",
                    path.display()
                );
            }
        }

        // Explicit --params file overrides auto-discovered values
        if let Some(path) = params_file {
            eprintln!("Loading params file: {}", path.display());
            values.extend(load_params_file(path)?);
        }

        // Instance fields are authoritative (locked at deploy time from chain data).
        // Legacy flat instance_params loaded first; new instance.fields takes precedence.
        if let Some(inst) = instance {
            values.extend(inst.instance_params.iter().map(|(k, v)| (k.clone(), v.clone())));
            if let Some(idata) = &inst.instance {
                values.extend(idata.fields.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }

        Ok(Self { values })
    }

    /// Return the highest-priority override for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

/// Derive the auto-discovery path `<stem>.<network>.json` alongside the manifest
/// file, e.g. `txmanifest.json` → `txmanifest.<network>.json`.
fn network_params_path(manifest_file: &Path, network: &str) -> PathBuf {
    let stem = manifest_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("manifest");
    let parent = manifest_file.parent().unwrap_or(Path::new("."));
    parent.join(format!("{stem}.{network}.json"))
}

/// Parse a params override file.  Must be a flat JSON object mapping param
/// names (strings) to their values (also strings).
fn load_params_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read params file: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Cannot parse params file (expected flat string→string JSON object): {}", path.display()))
}
