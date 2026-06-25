#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::Deserialize;

/// A borrowed list of `(param_name, definition)` pairs.
pub type ParamRefs<'a> = Vec<(&'a str, &'a ParamDef)>;

// ---------------------------------------------------------------------------
// Top-level file
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Manifest {
    /// Manifest schema version. `compose_version` is accepted as a legacy alias.
    #[serde(alias = "compose_version")]
    pub manifest_version: String,
    pub protocol: String,
    pub description: Option<String>,
    pub chain: Option<String>,
    /// Top-level SimplicityHL source file (relative to the manifest file).
    pub source: Option<String>,
    /// File-level default for output confidentiality (blinding). When absent, the chain
    /// default applies: false for "bitcoin", true for "elements". Overridden per output.
    pub confidential_outputs: Option<bool>,
    /// Flat compile-parameter map per spec §5.  Derived params carry `derived: true`.
    /// Kept for backward compatibility; prefer class `fields` in new files.
    pub params: Option<BTreeMap<String, ParamDef>>,
    /// Legacy nested format (prediction_market).  Prefer `params` when present.
    pub compile_params: Option<CompileParams>,
    pub utxo_types: Option<BTreeMap<String, UtxoType>>,
    /// Standalone actions that require no class instance (e.g. Prepare).
    #[serde(default)]
    pub actions: BTreeMap<String, Action>,
    /// Class definitions. Each class has typed fields and methods.
    /// Constructors (`is_constructor: true`) create new instances via `create_instance`.
    pub classes: Option<BTreeMap<String, ClassDef>>,
    /// u16 error code (as string key) -> English description
    pub errors: Option<BTreeMap<String, String>>,
    pub lifecycle: Option<serde_json::Value>,
}

impl Manifest {
    /// Return all compile params as (name, def) pairs split into
    /// (user-provided, derived) regardless of which on-disk format is used.
    pub fn compile_param_sets(&self) -> (ParamRefs<'_>, ParamRefs<'_>) {
        if let Some(flat) = &self.params {
            let user: Vec<_> = flat.iter()
                .filter(|(_, d)| !d.derived.unwrap_or(false))
                .map(|(k, d)| (k.as_str(), d))
                .collect();
            let derived: Vec<_> = flat.iter()
                .filter(|(_, d)| d.derived.unwrap_or(false))
                .map(|(k, d)| (k.as_str(), d))
                .collect();
            return (user, derived);
        }
        if let Some(cp) = &self.compile_params {
            let user: Vec<_> = cp.user_provided.as_ref()
                .map(|m| m.iter().map(|(k, d)| (k.as_str(), d)).collect())
                .unwrap_or_default();
            let derived: Vec<_> = cp.derived.as_ref()
                .map(|m| m.iter().map(|(k, d)| (k.as_str(), d)).collect())
                .unwrap_or_default();
            return (user, derived);
        }
        (vec![], vec![])
    }

    /// Iterate all compile param names regardless of format.
    pub fn all_compile_param_names(&self) -> Vec<&str> {
        let (u, d) = self.compile_param_sets();
        u.into_iter().chain(d).map(|(k, _)| k).collect()
    }

    /// Find a method by name across all classes.
    /// Returns `(class_id, class_def, action)` for the first match.
    /// `MethodDef` is a type alias for `Action`, so the return is `&Action`.
    pub fn find_class_and_method(&self, name: &str) -> Option<(&str, &ClassDef, &Action)> {
        let classes = self.classes.as_ref()?;
        for (class_id, class_def) in classes {
            if let Some(method) = class_def.methods.get(name) {
                return Some((class_id.as_str(), class_def, method));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Compile params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CompileParams {
    pub user_provided: Option<BTreeMap<String, ParamDef>>,
    pub derived: Option<BTreeMap<String, ParamDef>>,
}

#[derive(Debug, Deserialize)]
pub struct ParamDef {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: Option<String>,
    /// Formula (informational only for display)
    pub formula: Option<String>,
    /// Default value shown as a pre-fill in the prompt.
    pub default: Option<String>,
    /// True for params computed from other params (spec §5).  Omitting equals false.
    #[serde(default)]
    pub derived: Option<bool>,
    /// Optional source for auto-populating the value (e.g. from the wallet).
    pub source: Option<ParamSource>,
    /// Auto-compute expression for derived params not loaded from an instance file.
    pub compute: Option<ParamCompute>,
}

/// Auto-computation spec for a derived compile param or action param.
///
/// Dispatched by `lang`:
/// - `"expr"`: arithmetic expression over other compile params (`pow(base, exp)` supported)
/// - `"tapleaf"`: compile a `.simf` file and return its Simplicity tapleaf hash (32 bytes hex)
/// - `"simf_fn"`: call a named function in a `.simf` file and use its return value
#[derive(Debug, Deserialize)]
#[serde(tag = "lang", rename_all = "snake_case")]
pub enum ParamCompute {
    Expr { expr: String },
    Tapleaf {
        simf: String,
        /// Explicit param map for the simf. Each entry combines the value (a compile-param
        /// reference or string literal) with an optional manifest type hint.
        /// Omit entirely to pass ALL current compile params (auto-populate mode).
        #[serde(default)]
        params: std::collections::HashMap<String, TapleafParam>,
        /// Subset of compile-param names this simf actually consumes (auto-populate only).
        /// When set, the tapleaf is computed as soon as exactly these params are resolved,
        /// instead of waiting for ALL compile params. Use this to break apparent circular
        /// dependencies when the simf does not use every manifest-level compile param.
        #[serde(default)]
        depends_on: Option<Vec<String>>,
    },
    /// Call a named function in a `.simf` file after inputs are resolved.
    /// The function is compiled with `compile_params` as param:: constants.
    /// Its runtime input is read from `input` (a dot-path into ctx, e.g. `"params.STATE_BYTES"`).
    /// The return value is stored as the param value.
    SimfFn {
        simf: String,
        /// Name of the function to call. If omitted the file must define exactly one function.
        #[serde(rename = "fn", default)]
        fn_name: Option<String>,
        /// Compile-time param names from ctx to pass as `param::` constants to the function.
        #[serde(default)]
        compile_params: Vec<String>,
        /// Dot-path to the runtime input value, e.g. `"params.STATE_BYTES"`.
        /// Omit for zero-argument functions.
        input: Option<String>,
    },
}

/// A single entry in a `ParamCompute::Tapleaf` params map.
/// Combines the value reference (compile-param name or literal) with an optional type hint.
#[derive(Debug, Deserialize)]
pub struct TapleafParam {
    /// Manifest type, e.g. `"liquid.asset_id"`, `"u64"`, `"bool"`.
    /// When absent, the type is inferred from the compile-param of the same name.
    #[serde(rename = "type")]
    pub type_: Option<String>,
    /// A compile-param name reference OR a string literal like `"1"`, `"true"`.
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ParamSource {
    #[serde(rename = "type")]
    pub type_: String,
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Action {
    pub description: Option<String>,
    /// Legacy deploy flag — writes instance_params on broadcast. Prefer `is_constructor`.
    #[serde(default)]
    pub deploy: bool,
    /// New-style constructor: runs `create_instance` after broadcast.
    #[serde(default)]
    pub is_constructor: bool,
    /// Action-level params (runtime values, often displayed / computed)
    pub params: Option<BTreeMap<String, ParamDef>>,
    /// Action-level args (witness/script arguments)
    pub args: Option<BTreeMap<String, ParamDef>>,
    pub inputs: Option<Vec<Input>>,
    pub outputs: Option<Vec<Output>>,
    pub validations: Option<Vec<Validation>>,
    /// Legacy hook block (input-level on_input_resolved).
    pub hooks: Option<Hooks>,
    /// Method-level hook: runs after inputs are resolved, before PSET is built.
    pub on_pre_broadcast: Option<HookBlock>,
    /// Method-level hook: runs after broadcast (captures txids, asset IDs).
    pub on_post_broadcast: Option<HookBlock>,
    /// Constructor-only: defines the new instance written to the instance file.
    pub create_instance: Option<InstanceCreate>,
    pub witnesses: Option<serde_json::Value>,
}

/// Methods inside a class are structurally identical to standalone actions.
pub type MethodDef = Action;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Input {
    pub id: String,
    pub description: Option<String>,
    /// "wallet" or {"utxo_type": "..."} or conditional object
    pub utxo_source: serde_json::Value,
    pub asset: Option<serde_json::Value>,
    pub amount_sat: Option<serde_json::Value>,
    pub issuance: Option<serde_json::Value>,
    /// Per-input `nSequence`. Drives BIP68 relative timelocks (the `check_lock_distance`
    /// / `check_lock_duration` Simplicity jets). Accepts:
    ///   - `{"relative_blocks": <expr>}`  — block-based relative lock (≤ 65535 blocks)
    ///   - `{"relative_seconds": <expr>}` — time-based relative lock, rounded up to 512s units
    ///   - a bare integer / expression    — raw nSequence value
    ///
    /// Omitted → the input stays at `Sequence::MAX` (relative locktime disabled).
    pub sequence: Option<serde_json::Value>,
    /// Simplicity witnesses for this input: map of witness name → definition.
    pub witnesses: Option<serde_json::Value>,
    /// Inline hook evaluated after this input's UTXO is resolved and its
    /// issuance attrs (asset, reissuance_token) are computed.
    pub on_resolved: Option<InlineHook>,
}

/// Inline hook on an input — evaluated in the standard expression language
/// (not SimplicityHL) once the input is resolved.
///
/// `set` maps target paths (e.g. `"compile_params.BORROWER_NFT_ASSET_ID"`) to
/// expressions.  Within an input's own `on_resolved`, the bare keyword `"asset"`
/// resolves to the input's computed issuance asset ID (or its UTXO asset for
/// non-issuance inputs), and `"reissuance_token"` resolves to the computed
/// reissuance token asset ID.
#[derive(Debug, Deserialize)]
pub struct InlineHook {
    pub set: BTreeMap<String, String>,
}

impl Input {
    /// Returns true when this is a wallet-sourced input.
    pub fn is_wallet_source(&self) -> bool {
        matches!(&self.utxo_source, serde_json::Value::String(s) if s == "wallet")
    }

    /// Returns the utxo_type name if this input comes from a protocol UTXO.
    pub fn utxo_type_name(&self) -> Option<String> {
        match &self.utxo_source {
            serde_json::Value::Object(map) => {
                map.get("utxo_type").and_then(|v| v.as_str()).map(String::from)
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Output {
    pub id: String,
    pub description: Option<String>,
    /// "change" | "params.<name>" | {"utxo_type": "..."} | {"type": "burn"} | conditional
    pub destination: serde_json::Value,
    pub amount_sat: Option<serde_json::Value>,
    pub asset: Option<serde_json::Value>,
    pub optional: Option<bool>,
    pub condition: Option<String>,
    /// When `false`, wallet outputs are built with no blinding key (explicit amount/asset).
    /// Defaults to `true` (confidential) for wallet destinations. Has no effect on
    /// covenant (`utxo_type`) outputs — those are controlled by the `utxo_type.confidential` flag.
    pub confidential: Option<bool>,
}

impl Output {
    /// Human-readable summary of the destination.
    pub fn destination_summary(&self) -> String {
        match &self.destination {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Object(map) => {
                if let Some(ut) = map.get("utxo_type") {
                    format!("utxo_type:{}", json_value_display(ut))
                } else if let Some(t) = map.get("type") {
                    format!("type:{}", json_value_display(t))
                } else if map.contains_key("if") {
                    "[conditional destination]".to_string()
                } else {
                    serde_json::to_string(map).unwrap_or_else(|_| "[object]".to_string())
                }
            }
            other => other.to_string(),
        }
    }
}

fn json_value_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => "[conditional]".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Validations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Validation {
    pub id: String,
    pub description: Option<String>,
    pub rule: ValidationRule,
    pub error_code: Option<u16>,
    /// Legacy / new error format: {"code": "...", "message": "..."} or just a string
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ValidationRule {
    #[serde(rename = "type")]
    pub type_: String,
    pub expr: Option<String>,
    /// For utxo_exists validations
    pub utxo_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Hooks (legacy action-level)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Hooks {
    /// keyed by input id, in declaration order
    pub on_input_resolved: Option<BTreeMap<String, InputHook>>,
    /// Inline SimplicityHL source for on_validate
    pub on_validate: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InputHook {
    pub lang: String,
    /// param path -> SimplicityHL expression
    pub set: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Class / Instance model
// ---------------------------------------------------------------------------

/// A class definition: typed field declarations and named methods.
#[derive(Debug, Deserialize)]
pub struct ClassDef {
    pub description: Option<String>,
    /// Field declarations — names and types only.  Values are set by constructors.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldDef>,
    /// Named methods.  Constructors carry `is_constructor: true`.
    #[serde(default)]
    pub methods: BTreeMap<String, MethodDef>,
}

/// A field declaration inside a class.  Just a name and type; no compute here.
#[derive(Debug, Deserialize)]
pub struct FieldDef {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: Option<String>,
    pub default: Option<String>,
}

/// A method-level hook block: a flat map of setter targets to expressions.
///
/// Targets use dot-path notation:
///   `"params.FOO"` — sets a method param
///   `"args.BAR"`   — sets a method arg
#[derive(Debug, Deserialize)]
pub struct HookBlock {
    pub set: BTreeMap<String, String>,
}

/// Describes the new instance written by a constructor after broadcast.
#[derive(Debug, Deserialize)]
pub struct InstanceCreate {
    /// Must match a key in `manifest.classes`.
    pub class: String,
    /// Maps field names to their initial values.
    /// Each value is either a string expression (`"$params.FOO"`)
    /// or a compute spec (`{ "lang": "tapleaf", ... }`).
    pub fields: BTreeMap<String, FieldValue>,
}

/// A field value in `create_instance.fields`: either a plain expression string
/// or a structured compute spec (tapleaf hash, etc.).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    /// Simple expression: `"$params.COLLATERAL_ASSET_ID"`, `"$inputs.foo.asset"`, etc.
    Expr(String),
    /// Structured compute (e.g. tapleaf hash).
    Compute(ParamCompute),
}

// ---------------------------------------------------------------------------
// UtxoType
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UtxoScript {
    #[serde(rename = "type")]
    pub type_: String,
    pub source: Option<String>,
    pub extra_leaves: Option<Vec<TaprootLeafSpec>>,
    /// Per-utxo-type compile param remappings: simf_param_name → compile_param_reference.
    /// e.g. `{ "SCRIPT_HASH": "LENDING_COV_HASH" }` passes the value of LENDING_COV_HASH
    /// to the simf as SCRIPT_HASH.
    #[serde(default)]
    pub compile_params: std::collections::HashMap<String, String>,
}

/// Describes one additional taproot leaf appended to the Simplicity program leaf.
#[derive(Debug, Deserialize)]
pub struct TaprootLeafSpec {
    #[serde(rename = "type")]
    pub type_: String,
    /// Ordered payload items: each is either a hex literal string ("0x01")
    /// or a state_var reference ({"state_var": "name"}).
    pub payload: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UtxoType {
    pub description: String,
    pub script: Option<UtxoScript>,
    pub asset: Option<String>,
    pub state_vars: Option<serde_json::Value>,
    /// Whether UTXOs of this type are confidential (blinded). Defaults to false — covenant
    /// UTXOs are explicit so the spending Simplicity program can introspect value and asset.
    #[serde(default)]
    pub confidential: bool,
}

impl UtxoType {
    /// Resolve `script.extra_leaves` to concrete byte vectors by substituting
    /// state_var references with their `default_value` as a single u8.
    pub fn resolve_extra_leaf_payloads(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        let extra_leaves = match self.script.as_ref().and_then(|s| s.extra_leaves.as_ref()) {
            Some(l) => l,
            None => return Ok(vec![]),
        };
        let mut result = Vec::new();
        for leaf in extra_leaves {
            let mut bytes: Vec<u8> = Vec::new();
            for item in &leaf.payload {
                match item {
                    serde_json::Value::String(s) => {
                        let hex = s.trim_start_matches("0x").trim_start_matches("0X");
                        anyhow::ensure!(
                            hex.len() % 2 == 0,
                            "Odd-length hex in taproot leaf payload: '{s}'"
                        );
                        for i in (0..hex.len()).step_by(2) {
                            let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| {
                                anyhow::anyhow!("Invalid hex byte '{}' in taproot payload", &hex[i..i + 2])
                            })?;
                            bytes.push(byte);
                        }
                    }
                    serde_json::Value::Object(m) => {
                        let var_name = m
                            .get("state_var")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Unsupported payload object: {}",
                                    serde_json::to_string(m).unwrap_or_default()
                                )
                            })?;
                        let val = self
                            .state_vars
                            .as_ref()
                            .and_then(|sv| sv.get(var_name))
                            .and_then(|v| v.get("default_value"))
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "state_var '{}' not found or missing default_value",
                                    var_name
                                )
                            })?;
                        let byte = val.parse::<u8>().map_err(|_| {
                            anyhow::anyhow!(
                                "state_var '{}' = '{}' is not a valid u8",
                                var_name, val
                            )
                        })?;
                        bytes.push(byte);
                    }
                    other => anyhow::bail!("Unsupported taproot payload item: {other}"),
                }
            }
            result.push(bytes);
        }
        Ok(result)
    }
}

impl Manifest {
    /// Look up a named `utxo_type` entry.
    pub fn utxo_type(&self, name: &str) -> anyhow::Result<&UtxoType> {
        self.utxo_types
            .as_ref()
            .and_then(|m| m.get(name))
            .ok_or_else(|| anyhow::anyhow!("utxo_type '{}' not found in manifest file", name))
    }
}
