use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::context::ResolvedInput;

// ---------------------------------------------------------------------------
// Instance file
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceFile {
    /// Class instance state — class name + field values.
    /// Written by a constructor (`is_constructor: true`) after broadcast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceData>,

    /// Legacy flat param map. Read-only for backward compatibility;
    /// new constructors write `instance` instead.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub instance_params: HashMap<String, String>,

    /// Pre-resolved covenant input outpoints, keyed by action input id.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub provided_inputs: HashMap<String, ResolvedInput>,
}

/// The instance state stored in the instance file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceData {
    /// Matches a key in `manifest.classes`.
    pub class: String,
    /// Field values set by the constructor (BTreeMap → alphabetical JSON output).
    pub fields: BTreeMap<String, String>,
}

impl InstanceData {
    pub fn get_field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

impl InstanceFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read instance file: {}", path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("Cannot parse instance file: {}", path.display()))?;

        // New format: instance: { class, fields }
        let instance: Option<InstanceData> = v
            .get("instance")
            .and_then(|i| serde_json::from_value(i.clone()).ok());

        // Legacy: instance_params flat map
        let instance_params: HashMap<String, String> = v
            .get("instance_params")
            .and_then(|m| m.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let provided_inputs: HashMap<String, ResolvedInput> = v
            .get("provided_inputs")
            .and_then(|m| m.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(id, entry)| {
                        let txid = entry.get("txid")?.as_str()?.to_string();
                        let vout = entry.get("vout")?.as_u64()? as u32;
                        let amount_sat = entry.get("amount_sat")?.as_u64()?;
                        let asset = entry.get("asset")?.as_str()?.to_string();
                        let issuance_entropy = entry
                            .get("issuance_entropy")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        Some((
                            id.clone(),
                            ResolvedInput { id: id.clone(), txid, vout, amount_sat, asset, issuance_entropy },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self { instance, instance_params, provided_inputs })
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Cannot serialise instance file")?;
        std::fs::write(path, json)
            .with_context(|| format!("Cannot write instance file: {}", path.display()))
    }

    /// Return a field value — checks `instance.fields` first, falls back to
    /// legacy `instance_params`.
    pub fn get_field(&self, name: &str) -> Option<&str> {
        if let Some(inst) = &self.instance {
            if let Some(v) = inst.fields.get(name) {
                return Some(v.as_str());
            }
        }
        self.instance_params.get(name).map(String::as_str)
    }

    /// Class name if an instance is present.
    pub fn class_name(&self) -> Option<&str> {
        self.instance.as_ref().map(|i| i.class.as_str())
    }
}
