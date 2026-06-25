#![allow(dead_code)]

use std::collections::BTreeMap;

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Resolved input
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedInput {
    pub id: String,
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub asset: String,
    /// Issuance entropy (hex, 32 bytes) for reissuance inputs. Computed by instantiate.py
    /// from the original issuance outpoint.
    pub issuance_entropy: Option<String>,
}

// ---------------------------------------------------------------------------
// Runtime context
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ExecutionContext {
    /// compile_params values (both user_provided and derived once resolved)
    compile_params: BTreeMap<String, String>,
    /// Action-level args
    args: BTreeMap<String, String>,
    /// Action-level params
    params: BTreeMap<String, String>,
    /// Resolved inputs keyed by input id
    resolved_inputs: BTreeMap<String, ResolvedInput>,
    /// Per-input derived attributes: (input_id, attr) → value.
    /// Used to store issuance-derived IDs like `yes_issuance.reissuance_token`.
    input_attrs: BTreeMap<(String, String), String>,
    /// Estimated network fee (sats) for the action being built. The `fee` formula
    /// keyword resolves to this. It starts at 0 and is recomputed from the tx vsize
    /// once the output structure is known, before signing.
    fee: u64,
}

impl ExecutionContext {
    pub fn new() -> Self {
        Self::default()
    }

    // -- compile_params ------------------------------------------------------

    pub fn set_compile_param(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.compile_params.insert(name.into(), value.into());
    }

    pub fn get_compile_param(&self, name: &str) -> Option<&str> {
        self.compile_params.get(name).map(|s| s.as_str())
    }

    pub fn require_compile_param(&self, name: &str) -> Result<&str> {
        self.get_compile_param(name)
            .with_context(|| format!("compile_param '{name}' not set in context"))
    }

    // -- args ----------------------------------------------------------------

    pub fn set_arg(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.args.insert(name.into(), value.into());
    }

    pub fn get_arg(&self, name: &str) -> Option<&str> {
        self.args.get(name).map(|s| s.as_str())
    }

    // -- params --------------------------------------------------------------

    pub fn set_param(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.params.insert(name.into(), value.into());
    }

    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }

    // -- fee -----------------------------------------------------------------

    pub fn set_fee(&mut self, fee: u64) {
        self.fee = fee;
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    // -- resolved inputs -----------------------------------------------------

    pub fn set_input(&mut self, input: ResolvedInput) {
        self.resolved_inputs.insert(input.id.clone(), input);
    }

    pub fn get_input(&self, id: &str) -> Option<&ResolvedInput> {
        self.resolved_inputs.get(id)
    }

    pub fn require_input(&self, id: &str) -> Result<&ResolvedInput> {
        self.get_input(id)
            .with_context(|| format!("input '{id}' not resolved in context"))
    }

    // -- input attrs --------------------------------------------------------

    pub fn set_input_attr(
        &mut self,
        input_id: impl Into<String>,
        attr: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.input_attrs.insert((input_id.into(), attr.into()), value.into());
    }

    pub fn get_input_attr(&self, input_id: &str, attr: &str) -> Option<&str> {
        self.input_attrs.get(&(input_id.to_string(), attr.to_string())).map(String::as_str)
    }

    pub fn set_input_entropy(&mut self, id: &str, entropy_hex: String) {
        if let Some(inp) = self.resolved_inputs.get_mut(id) {
            inp.issuance_entropy = Some(entropy_hex);
        }
    }

    // -- display helpers -----------------------------------------------------

    pub fn all_compile_params(&self) -> &BTreeMap<String, String> {
        &self.compile_params
    }

    pub fn all_params(&self) -> &BTreeMap<String, String> {
        &self.params
    }

    pub fn all_args(&self) -> &BTreeMap<String, String> {
        &self.args
    }

    pub fn all_inputs(&self) -> impl Iterator<Item = &ResolvedInput> {
        self.resolved_inputs.values()
    }
}
