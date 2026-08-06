#![allow(dead_code)]

use std::collections::BTreeMap;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::Deserialize;
use simplicityhl::{UnstableFeature, UnstableFeatures};

// ---------------------------------------------------------------------------
// Top-level file
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest schema version.
    pub manifest_version: String,
    pub protocol: String,
    pub description: Option<String>,
    pub chain: Option<String>,
    /// SimplicityHL toolchain settings for this manifest's `.simf` programs.
    pub simplicity_hl: Option<SimplicityHl>,
    pub utxo_types: Option<BTreeMap<String, UtxoType>>,
    /// Standalone actions that require no template instance (e.g. Prepare).
    #[serde(default)]
    pub actions: BTreeMap<String, Action>,
    /// Contract template definitions. Each template has typed fields and actions.
    /// An action carrying a `create_instance` block is a constructor for its template.
    pub contract_templates: Option<BTreeMap<String, ContractTemplate>>,
}

/// SimplicityHL toolchain settings — how the `.simf` programs are compiled, as
/// distinct from what the protocol does.
///
/// Deliberately carries **no** compiler-version field. SimplicityHL has its own
/// `simc "<range>";` source directive, which the compiler enforces fail-fast before
/// lexing, across the entry file and every reachable dependency — none of which a
/// manifest key can do. Tooling that wants the requirement without compiling can read
/// it via `version::SimcDirective::requirement_of`. Declaring it here as well would
/// only create a second place to disagree.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SimplicityHl {
    /// Whether covenant `.simf` programs are compiled with debug symbols included.
    ///
    /// This changes the program's CMR **and therefore every covenant address**, because
    /// `assert!`/`panic!` embed source info into `fail`-node commitments. Set it to match
    /// the toolchain of any protocol this manifest must interoperate with — e.g. `true`
    /// for simplicity-lending / `smplx-sdk`, which compiles with debug symbols on.
    ///
    /// Defaults to `false` (production; debug symbols are a transitional feature).
    #[serde(default)]
    pub debug_symbols: bool,

    /// Unstable SimplicityHL compiler features this manifest's programs are allowed to
    /// use — the manifest form of `simc -Z <name>`, one entry per feature:
    ///
    /// ```json
    /// "simplicity_hl": { "unstable_features": ["enums"] }
    /// ```
    ///
    /// The compiler rejects gated syntax unless the feature is enabled, so a program
    /// using `enum` fails to compile until `"enums"` is listed here. Enabling a feature
    /// the programs don't use is harmless: this only lifts a restriction, it never
    /// changes generated code, and therefore never changes a CMR or covenant address.
    ///
    /// Manifest-wide rather than per-`utxo_type`, mirroring `simc`'s own per-invocation
    /// `-Z` flag — the whole point of a gate is that a reader can see, in one place,
    /// which unstable syntax this protocol depends on.
    ///
    /// Defaults to empty: nothing unstable is enabled.
    #[serde(default)]
    pub unstable_features: Vec<UnstableFeatureName>,
}

/// One entry of [`SimplicityHl::unstable_features`], parsed straight into the compiler's
/// own [`UnstableFeature`] so the manifest and the toolchain cannot disagree about which
/// names exist.
///
/// Both directions of drift are therefore load-time errors, which is the intent: a
/// misspelling (`"enum"`), and a feature that has since *stabilized* upstream — the
/// variant is deleted on stabilization, and the stale `-Z` name it leaves behind in a
/// manifest is no longer meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnstableFeatureName(pub UnstableFeature);

impl<'de> Deserialize<'de> for UnstableFeatureName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        UnstableFeature::from_str(&raw).map(Self).map_err(|_| {
            serde::de::Error::custom(format!(
                "unknown SimplicityHL unstable feature '{raw}'; known features: {}",
                known_unstable_feature_names().join(", ")
            ))
        })
    }
}

impl JsonSchema for UnstableFeatureName {
    fn schema_name() -> String {
        "UnstableFeatureName".to_string()
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        // Enumerated from the compiler's own list rather than hand-copied, so the
        // published schema tracks the toolchain the same way the parser does.
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            enum_values: Some(
                UnstableFeature::ALL
                    .iter()
                    .map(|feature| serde_json::Value::String(feature.to_string()))
                    .collect(),
            ),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(unstable_feature_descriptions()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

/// Every `-Z` name the linked compiler accepts, for error messages.
fn known_unstable_feature_names() -> Vec<String> {
    UnstableFeature::ALL
        .iter()
        .map(UnstableFeature::to_string)
        .collect()
}

/// `name — what it enables` for each feature, as the schema's description.
fn unstable_feature_descriptions() -> String {
    let mut out = String::from("Unstable SimplicityHL compiler feature (`simc -Z <name>`).");
    for feature in UnstableFeature::ALL {
        out.push_str(&format!("\n- {feature} — {}", feature.description()));
    }
    out
}

/// Structural keys an author may place in a manifest that carry no protocol meaning
/// and are stripped before deserialization.
///
/// Every model type is `deny_unknown_fields`, so without this an unremarkable
/// authoring convention would be a hard parse error:
///
/// - `$comment` — JSON has no comment syntax, so manifests carry prose here. Legal in
///   *any* object, at any depth.
/// - `$schema` — the editor hint pointing at the published schema (see
///   [`crate::schema::SCHEMA_ID`]). Conventionally only at the top level, but stripped
///   anywhere so it never becomes a foot-gun.
///
/// The generated schema re-admits both explicitly; see `crate::schema`.
pub const STRIPPED_KEYS: [&str; 2] = ["$comment", "$schema"];

/// Recursively drop [`STRIPPED_KEYS`] entries from a JSON tree.
fn strip_authoring_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for key in STRIPPED_KEYS {
                map.remove(key);
            }
            for nested in map.values_mut() {
                strip_authoring_keys(nested);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_authoring_keys),
        _ => {}
    }
}

impl Manifest {
    /// Parse a manifest from JSON text. **This is the canonical entry point** —
    /// prefer it over `serde_json::from_str` so every caller gets the same
    /// treatment.
    ///
    /// Two things happen here that a bare `from_str` does not do:
    /// 1. [`STRIPPED_KEYS`] (`$comment`, `$schema`) are removed at any depth.
    /// 2. Everything else is parsed with `deny_unknown_fields`, so a key the
    ///    model does not know is a hard error rather than a silent no-op. A
    ///    misspelled `create_instance` used to parse fine and then simply never
    ///    fire; now it fails loudly at load time.
    pub fn from_json_str(raw: &str) -> Result<Self, serde_json::Error> {
        let mut value: serde_json::Value = serde_json::from_str(raw)?;
        strip_authoring_keys(&mut value);
        serde_json::from_value(value)
    }

    /// Find an action by name across all contract templates.
    /// Returns `(template_id, template_def, action)` for the first match.
    pub fn find_template_action(&self, name: &str) -> Option<(&str, &ContractTemplate, &Action)> {
        let contract_templates = self.contract_templates.as_ref()?;
        for (template_id, template_def) in contract_templates {
            if let Some(action) = template_def.actions.get(name) {
                return Some((template_id.as_str(), template_def, action));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Compile params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParamDef {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: Option<String>,
    /// Default value shown as a pre-fill in the prompt.
    pub default: Option<String>,
    /// How this param's value is derived. When present the user is never prompted.
    ///
    /// Either a bare expression string — `"instance.PRINCIPAL_AMOUNT * 2"` — or a
    /// structured spec for the cases an expression cannot express (`tapleaf`,
    /// `simf_fn`). The bare form is what `formula` used to be; they were two ways to
    /// say "this value is computed, do not ask", so they are now one.
    pub compute: Option<ComputeSpec>,
}

impl ComputeSpec {
    /// The bare expression form, if this is one.
    ///
    /// `"a + b"` and `{ "type": "expr", "expr": "a + b" }` mean the same thing, so
    /// both are reported here — callers evaluating an expression need not care which
    /// spelling the author used.
    pub fn as_expr(&self) -> Option<&str> {
        match self {
            ComputeSpec::Expr(e) => Some(e.as_str()),
            ComputeSpec::Compute(ParamCompute::Expr { expr }) => Some(expr.as_str()),
            ComputeSpec::Compute(_) => None,
        }
    }

    /// The structured form, if this is not a bare expression.
    pub fn as_spec(&self) -> Option<&ParamCompute> {
        match self {
            ComputeSpec::Compute(c) => Some(c),
            ComputeSpec::Expr(_) => None,
        }
    }

    /// Which wallet-derived value this resolves to, if it is one.
    pub fn as_wallet(&self) -> Option<WalletValue> {
        match self.as_spec() {
            Some(ParamCompute::Wallet { wallet }) => Some(*wallet),
            _ => None,
        }
    }

    /// True when this is a `simf_fn` spec, which resolves only after inputs do.
    pub fn is_simf_fn(&self) -> bool {
        matches!(self.as_spec(), Some(ParamCompute::SimfFn { .. }))
    }

    /// True when a hook supplies this value later in the run, so the user is never
    /// prompted and there is nothing to evaluate up front.
    pub fn is_hook(&self) -> bool {
        matches!(self.as_spec(), Some(ParamCompute::Hook {}))
    }
}

/// Auto-computation spec for a derived compile param or action param.
///
/// Dispatched by `type`, the same discriminator every other tagged object in the
/// format uses (`script.type`, `destination.type`, a witness's `type`). Note this is
/// the *method* of computation; the value's data type is `ParamDef::type_`, one level
/// up. The legacy key `lang` is still accepted as an alias for the discriminator:
/// - `"expr"`: arithmetic expression over other compile params (`pow(base, exp)` supported)
/// - `"tapleaf"`: compile a `.simf` file and return its Simplicity tapleaf hash (32 bytes hex)
/// - `"simf_fn"`: call a named function in a `.simf` file and use its return value
/// - `"wallet"`: take the value from the executing wallet rather than the manifest,
///   with `wallet` selecting which ([`WalletValue`])
///
/// The `wallet` variant differs from the others in kind: `expr`, `tapleaf` and
/// `simf_fn` are reproducible by anyone holding the manifest, whereas a `wallet_*`
/// value depends on who is running the action. They live here anyway because from an
/// author's point of view they answer the same question — where does this value come
/// from, if not the user? — and having two fields for that (the old `source`) meant
/// two things to check and a name that collided with `script.source`, a file path.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum ParamCompute {
    Expr {
        expr: String,
    },
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
        /// Optional taproot storage leaves to fold into the tap tree BEFORE hashing the
        /// scriptPubKey. When present, the computed value is `sha256(spk WITH these leaves)`
        /// instead of the storage-less script hash — used to key a `script_auth` covenant to
        /// a covenant-with-storage (e.g. the pending lending offer's own script hash, offer
        /// out[3]). Leaf payload item value-refs resolve against the in-progress
        /// create_instance fields (then ctx), so they may reference sibling computed fields
        /// such as `CURRENT_DEBT`.
        #[serde(default)]
        extra_leaves: Option<Vec<TaprootLeafSpec>>,
    },
    /// A value a **hook** supplies later in this run — declared here, set by an
    /// `on_resolved` / `on_pre_broadcast` block targeting `params.<name>`.
    ///
    /// This exists so a hook cannot invent an identifier. Without it, `"set": {
    /// "params.YES_TOKN_ASSET": "asset" }` is accepted, fills a slot nobody reads, and
    /// surfaces as a wrong covenant address much later; with it, `validate` rejects the
    /// typo and the declaration carries the `type` that byte-order handling depends on.
    ///
    /// It lives under `compute` rather than as a separate `deferred: true` flag because
    /// `compute` already means exactly "this value is derived, do not prompt for it" —
    /// the only thing that differs here is *who* derives it. A second flag would need its
    /// own prompt-suppression path and would have to define what it means alongside a
    /// `compute` that is also present.
    Hook {},
    /// A value taken from the executing wallet rather than the manifest.
    ///
    /// Grouped under one tag rather than spread across three so that "is this
    /// wallet-derived?" is a single check on `compute` before dispatching on
    /// `wallet` — and so adding a new wallet-derived value does not grow the
    /// top-level variant list.
    Wallet { wallet: WalletValue },
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

/// Which wallet-derived value a [`ParamCompute::Wallet`] spec resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum WalletValue {
    /// The wallet's x-only BIP340 pubkey. The wallet chooses the derivation path.
    Key,
    /// `sha256(scriptPubKey)` of the wallet's index-0 explicit output — the committed
    /// payout target a covenant checks repayment against.
    ScriptHash,
    /// The explicit address matching [`WalletValue::ScriptHash`]. The two are a pair:
    /// the covenant commits to the hash, the wallet receives at the address, so they
    /// must be derived together.
    Address,
}

/// Normalize a compute spec object so the legacy discriminator key `lang` is
/// accepted as an alias for `compute`. (serde's internal `tag` does not support
/// `#[serde(alias)]`, so we rewrite the key before delegating to the derived impl.)
fn normalize_compute_value<E: serde::de::Error>(
    mut value: serde_json::Value,
) -> Result<ParamCompute, E> {
    if let Some(obj) = value.as_object_mut() {
        // `lang` is always consumed here, never left in place: the variants are
        // `deny_unknown_fields`, so a surviving `lang` would fail to deserialize.
        // When both keys are present `type` wins and `lang` is simply dropped.
        if let Some(lang) = obj.remove("lang") {
            obj.entry("type".to_string()).or_insert(lang);
        }
    }
    ParamCompute::deserialize(value).map_err(E::custom)
}

/// The JSON type of a value, for error messages that say what was actually found.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// A single entry in a `ParamCompute::Tapleaf` params map.
/// Combines the value reference (compile-param name or literal) with an optional type hint.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TapleafParam {
    /// Manifest type, e.g. `"liquid.asset_id"`, `"u64"`, `"bool"`.
    /// When absent, the type is inferred from the compile-param of the same name.
    #[serde(rename = "type")]
    pub type_: Option<String>,
    /// A compile-param name reference OR a string literal like `"1"`, `"true"`.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// Which assets an action lets the engine return a surplus in, via a change output the
/// manifest did not declare. See [`Action::allow_change`].
///
/// Spelled as an enum rather than a boolean because the useful middle case — "return
/// leftover L-BTC, but never move a protocol asset I did not account for" — is the one
/// most funding actions want, and a boolean cannot say it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AllowChange {
    /// No undeclared change. A surplus in any asset fails the build.
    #[default]
    None,
    /// Only the policy asset (L-BTC) may be returned.
    LbtcOnly,
    /// Any asset may be returned.
    Any,
}

impl AllowChange {
    /// Whether a surplus in `asset` may be returned to the wallet.
    pub fn permits(&self, asset: &lwk_wollet::elements::AssetId, policy_asset: &lwk_wollet::elements::AssetId) -> bool {
        match self {
            AllowChange::None => false,
            AllowChange::LbtcOnly => asset == policy_asset,
            AllowChange::Any => true,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub description: Option<String>,
    /// Whether the engine may append a change output this action did not declare.
    ///
    /// **Every output a transaction carries must be written in the manifest. The network
    /// fee is the single exception, because it has no manifest spelling.** A change output
    /// is not an exception: its address and amount are chosen by the engine, so silently
    /// adding one moves value to a destination the manifest never named, in an amount
    /// nobody wrote down. That is how an oversized collateral input once turned 88,735
    /// satoshis into a miner's fee without a word of warning.
    ///
    /// So the default is [`AllowChange::None`]: a surplus in any asset — including L-BTC —
    /// is an error, and the action must size its inputs to what it spends. Relax it only
    /// where the surplus genuinely cannot be predicted:
    ///
    /// - `"none"` (default) — no change may be added; any surplus is an error.
    /// - `"lbtc_only"` — the engine may return an L-BTC surplus to the wallet. Use this
    ///   for ordinary funding actions, where the fee is only known after the size is.
    ///   A surplus in any other asset is still an error.
    /// - `"any"` — the engine may return a surplus in any asset.
    ///
    /// This governs *undeclared* change. An output with `"destination": "change"` is
    /// declared, and permits change for its own asset regardless of this setting.
    #[serde(default)]
    pub allow_change: AllowChange,
    /// Runtime action parameters (Spec §5). Prompted, or set by hooks.
    pub params: Option<BTreeMap<String, ParamDef>>,
    pub inputs: Option<Vec<Input>>,
    pub outputs: Option<Vec<Output>>,
    /// Method-level hook: runs after inputs are resolved, before PSET is built.
    pub on_pre_broadcast: Option<HookBlock>,
    /// Method-level hook: runs after broadcast (captures txids, asset IDs).
    pub on_post_broadcast: Option<HookBlock>,
    /// Constructor-only: defines the new instance written to the instance file.
    pub create_instance: Option<InstanceCreate>,
    /// One-line statement of what this action does, shown as the first clear-signing
    /// screen. Supports `{ref}` and `{ref:symbol}` interpolation against the execution
    /// context (see `preview::interpolate`); asset-typed refs must carry `:symbol` so a
    /// wallet can substitute a friendly name (enforced by `validate::check_ui`).
    ///
    /// Named for the `intent` field in Ethereum's ERC-7730 clear-signing metadata,
    /// which plays the same role. Author-supplied, so only as trustworthy as the
    /// manifest's own signature chain — never a substitute for what a hardware device
    /// verifies. It IS covered by the registry hash (see `crate::canonical`).
    pub intent: Option<String>,
}

// ---------------------------------------------------------------------------
// Clear-signing UI metadata
// ---------------------------------------------------------------------------

/// Per-input / per-output UI hint. Accepts either a bare label string
/// (`"collateral locked"`) or a detailed object for finer control.
///
/// Hand-deserialized rather than `#[serde(untagged)]`: an untagged enum reports only
/// `data did not match any variant of untagged enum UiSpec`, swallowing the real
/// reason. Dispatching on the JSON shape lets `UiDetail`'s own error through, so a
/// misspelled key names itself.
#[derive(Debug, JsonSchema)]
#[serde(untagged)]
pub enum UiSpec {
    /// Shorthand for `{ "label": "..." }`.
    Label(String),
    Detail(UiDetail),
}

impl<'de> Deserialize<'de> for UiSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) => Ok(UiSpec::Label(s)),
            value @ serde_json::Value::Object(_) => UiDetail::deserialize(value)
                .map(UiSpec::Detail)
                .map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "`ui` must be a label string or an object like \
                 {{\"label\": \"...\", \"role\": \"...\"}}, got {}",
                json_type_name(&other)
            ))),
        }
    }
}

#[derive(Debug, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UiDetail {
    /// Human-readable one-line description of this leg — the **only** signer-facing
    /// text for it (`description` is not a fallback; see `preview::input_label`).
    ///
    /// Capped at [`crate::validate::MAX_UI_LABEL`] characters so it fits one net-effect
    /// row alongside the amount and asset symbol. The cap reaches the schema as a
    /// `maxLength` — injected by `crate::schema` from that constant rather than written
    /// here as a literal, so the two cannot drift — and an editor flags an over-long
    /// label while typing rather than at validate time.
    pub label: Option<String>,
    /// Optional semantic tag (e.g. "collateral", "auth_nft").
    pub role: Option<String>,
    /// Override the net-effect account/bucket heading (else derived from source/destination).
    pub group: Option<String>,
    /// Suppress this leg from the net-effect diff (e.g. pure protocol data).
    #[serde(default)]
    pub hide: bool,
}

impl UiSpec {
    /// The display label, if any.
    pub fn label(&self) -> Option<&str> {
        match self {
            UiSpec::Label(s) => Some(s.as_str()),
            UiSpec::Detail(d) => d.label.as_deref(),
        }
    }

    /// An explicit bucket-heading override, if the detailed form set one.
    pub fn group(&self) -> Option<&str> {
        match self {
            UiSpec::Detail(d) => d.group.as_deref(),
            UiSpec::Label(_) => None,
        }
    }

    /// The semantic role tag (e.g. "collateral", "auth_nft"), if the detailed form set one.
    /// The bare-label form carries no role.
    pub fn role(&self) -> Option<&str> {
        match self {
            UiSpec::Detail(d) => d.role.as_deref(),
            UiSpec::Label(_) => None,
        }
    }

    /// Whether this leg should be omitted from the net-effect diff.
    pub fn hidden(&self) -> bool {
        matches!(self, UiSpec::Detail(d) if d.hide)
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub id: String,
    pub description: Option<String>,
    /// "wallet" or {"utxo_type": "..."} or conditional object
    pub utxo_source: serde_json::Value,
    pub asset: Option<serde_json::Value>,
    /// When `true`, the transaction proceeds even if this UTXO is not found. Spec §6.
    ///
    /// ⚠️ **Parsed but NOT enforced** — the engine has no optional-input path, so a
    /// missing UTXO fails resolution regardless. `examples/dex` marks its `fee_input`
    /// optional and does not get that behaviour.
    pub optional: Option<bool>,
    /// Required transaction input index: `0`-based absolute, or negative to count from
    /// the end (`-1` = last). Spec §6.
    ///
    /// ⚠️ **Parsed but NOT enforced.** Nothing in the engine reads this field; inputs
    /// land in declaration order and that ordering happens to satisfy the covenants.
    /// Manifests assert an index here 106 times and none of it is checked, so a
    /// reordering that breaks a covenant's introspection would surface only as an
    /// on-chain failure. See `validate.rs` for where a static check belongs.
    pub required_index: Option<i64>,
    /// For `utxo_source: "wallet"` inputs: constrain coin selection to UTXOs whose
    /// scriptPubKey equals this address's. A reference (`instance.X` / `params.X`) or a
    /// literal address string. Use this to pin an input to a committed address — e.g. so a
    /// covenant's collateral is spent from the exact address whose hash it commits to.
    pub from_address: Option<String>,
    pub amount_sat: Option<serde_json::Value>,
    /// An Elements asset issuance carried by this input.
    ///
    /// - `{"kind": "new", "asset_amount_sat": <expr>, "inflation_amount_sat": <expr>}` —
    ///   mint a brand-new asset, whose id is derived from this input's outpoint. Either
    ///   amount may be `0` (reissuance tokens only, or a fixed supply with no reissuance
    ///   rights).
    /// - `{"kind": "reissue", "asset_amount_sat": <expr>, "entropy": <ref>}` — mint more of
    ///   an existing asset by spending its reissuance token.
    ///
    /// A reissuance needs the **issuance entropy** of the original mint —
    /// `fast_merkle_root([sha256d(defining outpoint), contract_hash])`, the value the asset
    /// id itself is derived from. It cannot be recovered from anything on chain: the
    /// reissuance token UTXO carries no trace of the outpoint that created it. So a
    /// constructor has to capture it at the one moment it exists, and hand it back later:
    ///
    /// ```json
    /// // in the minting action's create_instance:
    /// "YES_ISSUANCE_ENTROPY": "$inputs.yes_defining_in.issuance_entropy"
    /// // in the reissuing action's input:
    /// "issuance": { "kind": "reissue", "asset_amount_sat": "params.PAIRS",
    ///               "entropy": "instance.YES_ISSUANCE_ENTROPY",
    ///               "issued_asset": "instance.YES_TOKEN_ASSET" }
    /// ```
    ///
    /// `issued_asset` is optional and is a **check**, not an input: the engine re-derives
    /// the asset id from the entropy and refuses to build if the two disagree. An entropy
    /// is opaque, and the byte order block explorers print is the reverse of the one used
    /// here — without the check a transposed value still builds a broadcastable transaction
    /// that reissues the wrong asset.
    ///
    /// Failing that, the entropy may come from `provided_inputs.<input_id>.issuance_entropy`
    /// in the instance file. That works, but it travels with an outpoint override which
    /// pins the input for *every* action sharing its id — long after the pin is correct.
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
    pub on_resolved: Option<HookBlock>,
    /// Clear-signing UI hint for this input (net-effect debit line).
    pub ui: Option<UiSpec>,
}


impl Input {
    /// This input's short human-readable label, if it declares one.
    ///
    /// Deliberately does NOT fall back to `description`: descriptions are multi-sentence
    /// prose meant for readers of the manifest, so they would wreck a one-line terminal
    /// display. Callers that want a guaranteed-present string (the net-effect preview)
    /// apply their own `description` → `id` fallback.
    pub fn ui_label(&self) -> Option<&str> {
        self.ui.as_ref().and_then(|u| u.label())
    }

    /// This input's semantic role tag (e.g. "collateral", "covenant"), if declared.
    pub fn ui_role(&self) -> Option<&str> {
        self.ui.as_ref().and_then(|u| u.role())
    }

    /// Returns true when this is a wallet-sourced input.
    pub fn is_wallet_source(&self) -> bool {
        matches!(&self.utxo_source, serde_json::Value::String(s) if s == "wallet")
    }

    /// Returns the utxo_type name if this input comes from a protocol UTXO.
    pub fn utxo_type_name(&self) -> Option<String> {
        match &self.utxo_source {
            serde_json::Value::Object(map) => map
                .get("utxo_type")
                .and_then(|v| v.as_str())
                .map(String::from),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub id: String,
    pub description: Option<String>,
    /// "change" | "params.<name>" | {"utxo_type": "..."} | {"type": "burn"} | conditional
    pub destination: serde_json::Value,
    pub amount_sat: Option<serde_json::Value>,
    pub asset: Option<serde_json::Value>,
    pub optional: Option<bool>,
    /// Required transaction output index; same semantics and same caveat as
    /// [`Input::required_index`] (Spec §7) — parsed, never enforced.
    pub required_index: Option<i64>,
    pub condition: Option<String>,
    /// OP_RETURN payload, for `destination: {"type":"op_return"}` outputs. Either a
    /// `concat(ref, …)` string, or an object `{"parts": [ … ]}` of typed fields (for exact
    /// binary layouts — LE integers, `program_id`, asset-internal bytes). Evaluated to raw
    /// bytes and embedded after `OP_RETURN`. Omit for a bare data-less OP_RETURN (NFT burns).
    pub data: Option<serde_json::Value>,
    /// When `false`, wallet outputs are built with no blinding key (explicit amount/asset).
    /// Defaults to `true` (confidential) for wallet destinations. Has no effect on
    /// covenant (`utxo_type`) outputs — those are controlled by the `utxo_type.confidential` flag.
    pub confidential: Option<bool>,
    /// Clear-signing UI hint for this output (net-effect credit line).
    pub ui: Option<UiSpec>,
}

impl Output {
    /// This output's short human-readable label, if it declares one.
    /// See [`Input::ui_label`] for why `description` is not a fallback here.
    pub fn ui_label(&self) -> Option<&str> {
        self.ui.as_ref().and_then(|u| u.label())
    }

    /// This output's semantic role tag (e.g. "change", "vault"), if declared.
    pub fn ui_role(&self) -> Option<&str> {
        self.ui.as_ref().and_then(|u| u.role())
    }

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
// Class / Instance model
// ---------------------------------------------------------------------------

/// A contract template: typed field declarations and named methods.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContractTemplate {
    pub description: Option<String>,
    /// Field declarations — names and types only.  Values are set by constructors.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldDef>,
    /// Actions callable on an instance of this template. Structurally identical to
    /// the top-level `actions` — the only difference is that these run against an
    /// instance, so their formulas may reference `instance.*`. An action carrying a
    /// `create_instance` block constructs a new instance of this template.
    #[serde(default)]
    pub actions: BTreeMap<String, Action>,
}

/// A field declaration inside a contract template.  Just a name and type; no compute here.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldDef {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: Option<String>,
    pub default: Option<String>,
}

/// A hook: a flat map of setter targets to the values they take.
///
/// One type serves every hook position — an action's `on_pre_broadcast` /
/// `on_post_broadcast` and an input's `on_resolved` — because they only ever
/// differed in when they run, never in shape.
///
/// Targets use dot-path notation:
///   `"instance.FOO"` — sets a contract-template field (`compile_params.` is a
///                      deprecated alias)
///   `"params.FOO"`   — sets an action param
///
/// Values are [`ComputeSpec`], the same type `create_instance.fields` uses, so all
/// three "name → how to produce a value" maps in the format read alike. In hook
/// position only the expression forms are meaningful; `validate` rejects the rest
/// (see `validate::check_hook`).
///
/// Within an input's own `on_resolved`, two bare keywords are self-referential:
/// `"asset"` resolves to that input's computed issuance asset ID (or its UTXO asset
/// for non-issuance inputs), and `"reissuance_token"` to the computed reissuance
/// token asset ID.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookBlock {
    pub set: BTreeMap<String, ComputeSpec>,
}

/// Describes the new instance written after broadcast.
///
/// An action carrying this block **is** a constructor — there is no separate flag.
/// The instance is always of the contract template the action is declared in, so the
/// template is not named here: `create_instance` is only legal inside
/// `contract_templates.<T>.actions.*`, and always creates a `<T>`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstanceCreate {
    /// Maps field names to their initial values.
    /// Each value is either a string expression (`"$params.FOO"`)
    /// or a compute spec (`{ "compute": "tapleaf", ... }`).
    pub fields: BTreeMap<String, ComputeSpec>,
}

/// How a value is computed: either a plain expression string or a structured spec.
///
/// Used in two places, deliberately the same shape: `create_instance.fields` values
/// and [`ParamDef::compute`].
///
/// Hand-deserialized rather than `#[serde(untagged)]`, for the same reason as
/// [`UiSpec`]: untagged collapses every inner failure into `data did not match any
/// variant of untagged enum ComputeSpec`, which hides the one thing the author needs
/// to know. Dispatching on the JSON shape lets [`ParamCompute`]'s error — naming the
/// offending key or the unknown `type` — reach the surface.
#[derive(Debug, JsonSchema)]
#[serde(untagged)]
pub enum ComputeSpec {
    /// Simple expression: `"$params.COLLATERAL_ASSET_ID"`, `"instance.DEBT - 1"`.
    Expr(String),
    /// Structured compute — `tapleaf`, `simf_fn`, or an explicit `expr`.
    Compute(ParamCompute),
}

impl<'de> Deserialize<'de> for ComputeSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) => Ok(ComputeSpec::Expr(s)),
            value @ serde_json::Value::Object(_) => {
                normalize_compute_value(value).map(ComputeSpec::Compute)
            }
            other => Err(D::Error::custom(format!(
                "a compute spec must be an expression string or an object like \
                 {{\"type\": \"tapleaf\", ...}}, got {}",
                json_type_name(&other)
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// UtxoType
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaprootLeafSpec {
    #[serde(rename = "type")]
    pub type_: String,
    /// Ordered payload items: each is either a hex literal string ("0x01")
    /// or a state_var reference ({"state_var": "name"}).
    pub payload: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Resolve `script.extra_leaves` to concrete byte vectors.
    ///
    /// Each payload item is one of:
    /// - a hex-literal string (`"0x01"`),
    /// - `{ "state_var": "name" }` → the state var's `default_value` as a single u8, or
    /// - a typed/computed value `{ "value": <ref>, "type": ..., "pad_to": ..., ... }`
    ///   resolved against `ctx` (see [`crate::eval::encode_leaf_value`]) — used for
    ///   dynamic slots such as the lending covenant's `current_debt` leaf.
    pub fn resolve_extra_leaf_payloads(
        &self,
        ctx: &crate::context::ExecutionContext,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
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
                                anyhow::anyhow!(
                                    "Invalid hex byte '{}' in taproot payload",
                                    &hex[i..i + 2]
                                )
                            })?;
                            bytes.push(byte);
                        }
                    }
                    // Typed/computed value item, e.g. the dynamic `current_debt` slot:
                    // { "value": "instance.CURRENT_DEBT", "type": "u64", "pad_to": 32, "endian": "be" }.
                    serde_json::Value::Object(m) if m.contains_key("value") => {
                        bytes.extend_from_slice(&crate::eval::encode_leaf_value(item, ctx)?);
                    }
                    serde_json::Value::Object(m) => {
                        let var_name =
                            m.get("state_var").and_then(|v| v.as_str()).ok_or_else(|| {
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
                                var_name,
                                val
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
    /// Whether covenants should be compiled with SimplicityHL debug symbols included.
    /// Defaults to `false`; see [`SimplicityHl::debug_symbols`].
    pub fn include_debug_symbols(&self) -> bool {
        self.simplicity_hl.as_ref().is_some_and(|s| s.debug_symbols)
    }

    /// The unstable SimplicityHL features this manifest enables for its `.simf` programs.
    /// Empty by default; see [`SimplicityHl::unstable_features`].
    pub fn unstable_features(&self) -> UnstableFeatures {
        UnstableFeatures::new(
            self.simplicity_hl
                .iter()
                .flat_map(|hl| hl.unstable_features.iter().map(|name| name.0)),
        )
    }

    /// Everything the SimplicityHL compiler needs from this manifest, in the shape the
    /// [`crate::covenant`] helpers take. Build this once per run and pass it down —
    /// deriving it per call site is how the two settings drift apart.
    pub fn compile_opts(&self) -> crate::covenant::CompileOpts {
        crate::covenant::CompileOpts {
            debug_symbols: self.include_debug_symbols(),
            unstable_features: self.unstable_features(),
        }
    }

    /// Look up a named `utxo_type` entry.
    pub fn utxo_type(&self, name: &str) -> anyhow::Result<&UtxoType> {
        self.utxo_types
            .as_ref()
            .and_then(|m| m.get(name))
            .ok_or_else(|| anyhow::anyhow!("utxo_type '{}' not found in manifest file", name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_field_value(json: &str) -> ComputeSpec {
        serde_json::from_str(json).expect("ComputeSpec should deserialize")
    }

    /// A minimal well-formed manifest, with `extra` splatted into the single input.
    fn manifest_json(extra: &str) -> String {
        format!(
            r#"{{
                "manifest_version": "1",
                "protocol": "test",
                "actions": {{ "A": {{ "inputs": [
                    {{ "id": "in0", "utxo_source": "wallet"{extra} }}
                ] }} }}
            }}"#
        )
    }

    #[test]
    fn baseline_manifest_parses() {
        Manifest::from_json_str(&manifest_json("")).expect("baseline manifest should parse");
    }

    #[test]
    fn misspelled_field_is_rejected() {
        // The whole point of `deny_unknown_fields`: `from_addres` (one 's') used to
        // parse fine and then silently never constrain coin selection.
        let err = Manifest::from_json_str(&manifest_json(r#", "from_addres": "abc""#))
            .expect_err("a misspelled field must not parse");
        assert!(
            err.to_string().contains("from_addres"),
            "error should name the offending key, got: {err}"
        );
    }

    /// Legacy keys that were deliberately dropped from the model. Each must now be a
    /// hard parse error — the point of removing them is that a file still carrying one
    /// gets told, rather than having it silently ignored as before.
    #[test]
    fn removed_legacy_fields_are_rejected() {
        // `deploy` — superseded by `create_instance`.
        let deploy = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "deploy": true } }
        }"#;
        // Top-level `compile_params` — superseded by the flat `params` map.
        let compile_params = r#"{
            "manifest_version": "1", "protocol": "test",
            "compile_params": { "user_provided": {}, "derived": {} }
        }"#;
        // `attestation_version` — never read by anything.
        let attestation = r#"{
            "manifest_version": "1", "protocol": "test",
            "attestation_version": "1"
        }"#;
        // `confidential_outputs` — a file-level default no manifest ever set, so it
        // only ever passed through to the chain default. Set it per output instead.
        let confidential = r#"{
            "manifest_version": "1", "protocol": "test",
            "confidential_outputs": true
        }"#;

        // `lifecycle` — a free-form state/transition block nothing enforced; removed
        // for now, so it must not silently reappear as an ignored key.
        let lifecycle = r#"{
            "manifest_version": "1", "protocol": "test",
            "lifecycle": { "states": ["a"], "transitions": {} }
        }"#;

        // Both folded into the `simplicity_hl` object.
        let hl_version = r#"{
            "manifest_version": "1", "protocol": "test",
            "simplicity_hl_version": "0.6.0"
        }"#;
        let debug_symbols = r#"{
            "manifest_version": "1", "protocol": "test",
            "compile_debug_symbols": true
        }"#;

        // `errors` — a code→description lookup table nothing ever read.
        let errors = r#"{
            "manifest_version": "1", "protocol": "test",
            "errors": { "1": "something went wrong" }
        }"#;
        // `validations` — deferred to a future addition. Of the 11 entries the
        // examples carried, only 3 were enforced (all `!=` asset-distinctness); the
        // rest printed [TODO] and passed.
        //
        // Those 3 were real protection, and nothing replaces them yet: `dex` can now
        // publish an offer swapping an asset for itself, and `lending` can open a loan
        // whose collateral and principal are the same asset. Restoring the block
        // as-is would also re-admit the 8 no-op rules, which is the
        // parses-but-never-fires pattern this pass exists to remove — so the
        // replacement needs a comparison evaluator and its own design. Until then
        // `eval::eval_inequality_validation` is retained but unreferenced; it is the
        // starting point for that work, and the thing to delete if the decision is
        // that covenant-level enforcement is sufficient.
        let validations = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "validations": [
                { "id": "v", "rule": { "type": "arithmetic", "expr": "1 != 2" } }
            ] } }
        }"#;

        // Top-level `params` — no example ever used it; template `fields` is the live
        // path. Action-level `params` is a different field and still exists.
        let params = r#"{
            "manifest_version": "1", "protocol": "test",
            "params": { "P": { "type": "u64" } }
        }"#;
        // Top-level `source` — never set by any manifest; the engine now always
        // falls back to "covenant.simf". Per-utxo_type `script.source` is unaffected.
        let source = r#"{
            "manifest_version": "1", "protocol": "test",
            "source": "./covenant.simf"
        }"#;

        // `classes` — renamed to `contract_templates` to match tx_manifest_spec
        // (2026-07-06). `create_instance.class` became `template` in the same pass.
        let classes = r#"{
            "manifest_version": "1", "protocol": "test",
            "classes": { "C": { "fields": {}, "methods": {} } }
        }"#;

        // `hooks` — the legacy action-level block. Both members were unused by every
        // example: `on_input_resolved` is superseded by per-input `on_resolved` (and
        // executed hooks in alphabetical rather than declaration order), and
        // `on_validate` was never executed at all.
        let hooks = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "hooks": { "on_validate": "assert!(true)" } } }
        }"#;

        // `args` — never declared by any example, never referenced by one, and not an
        // action field in Spec.md §5. The `args.NAME` namespace went with it: the
        // whole parallel namespace (ctx storage, formula resolution, hook write
        // target) is gone, so `params` is now the only runtime value namespace.
        // NOTE: this puts the repo *ahead* of tx_manifest_spec, whose Hooks extension
        // still lists `args.NAME` as an assignment target.
        let args = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "args": { "SIG": { "type": "bytes32" } } } }
        }"#;

        // Action-level `ui` — flattened to a bare `intent` string (the wrapper held
        // exactly one field). Per-leg `ui` is a different field and still exists.
        let action_ui = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "ui": { "action": "do the thing" } } }
        }"#;

        // `methods` on a contract template — renamed to `actions`. They were always
        // the same type (`MethodDef` was a type alias for `Action`), and "methods" is
        // the OOP jargon `contract_templates` was chosen to avoid.
        let methods = r#"{
            "manifest_version": "1", "protocol": "test",
            "contract_templates": { "T": { "fields": {}, "methods": {} } }
        }"#;

        // `is_constructor` — an action carrying `create_instance` *is* a constructor;
        // the flag was a second way of saying the same thing, and could disagree.
        let is_constructor = r#"{
            "manifest_version": "1", "protocol": "test",
            "contract_templates": { "T": { "fields": {},
                "actions": { "A": { "is_constructor": true } } } }
        }"#;
        // `create_instance.template` — the instance is always of the enclosing
        // template, so naming it invited creating an instance of a different one.
        let ci_template = r#"{
            "manifest_version": "1", "protocol": "test",
            "contract_templates": { "T": { "fields": {},
                "actions": { "A": { "create_instance": { "template": "T", "fields": {} } } } } }
        }"#;

        // Action-level `witnesses` — witnesses satisfy a specific input's script, so
        // they belong on the input. No manifest ever set the action-level map, and
        // Spec.md §8 places witnesses on an input descriptor only.
        let action_witnesses = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "witnesses": { "SIG": { "type": "Signature" } } } }
        }"#;

        // `derived` — a boolean saying "this is computed", alongside `compute`, which
        // says the same thing and also says how. Only the second is load-bearing.
        let derived = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "params": { "P": { "type": "u64", "derived": true } } } }
        }"#;
        // `formula` — merged into `compute`, whose bare-string form it now is.
        let formula = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "params": { "P": { "type": "u64", "formula": "1 + 1" } } } }
        }"#;

        // `source` — folded into `compute` as its `wallet_*` variants. It answered the
        // same question ("where does this value come from, if not the user?") and its
        // name collided with `script.source`, which is a file path.
        let source = r#"{
            "manifest_version": "1", "protocol": "test",
            "actions": { "A": { "params": { "P": {
                "type": "pubkey", "source": { "type": "wallet_key" } } } } }
        }"#;

        for (name, json) in [
            ("source", source),
            ("derived", derived),
            ("formula", formula),
            ("witnesses", action_witnesses),
            ("is_constructor", is_constructor),
            ("template", ci_template),
            ("methods", methods),
            ("ui", action_ui),
            ("args", args),
            ("hooks", hooks),
            ("classes", classes),
            ("params", params),
            ("source", source),
            ("deploy", deploy),
            ("compile_params", compile_params),
            ("attestation_version", attestation),
            ("confidential_outputs", confidential),
            ("lifecycle", lifecycle),
            ("simplicity_hl_version", hl_version),
            ("compile_debug_symbols", debug_symbols),
            ("errors", errors),
            ("validations", validations),
        ] {
            let err =
                Manifest::from_json_str(json).expect_err("removed field '{name}' must not parse");
            assert!(
                err.to_string().contains(name),
                "error for '{name}' should name the key, got: {err}"
            );
        }
    }

    #[test]
    fn simplicity_hl_block_drives_debug_symbols() {
        // `debug_symbols` changes every covenant address, so pin both the plumbing
        // and the default rather than trusting the field is wired up.
        let with_debug = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t",
                 "simplicity_hl": { "debug_symbols": true } }"#,
        )
        .expect("simplicity_hl should parse");
        assert!(with_debug.include_debug_symbols());

        // An empty block defaults to false...
        let empty = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t", "simplicity_hl": {} }"#,
        )
        .expect("empty simplicity_hl should parse");
        assert!(!empty.include_debug_symbols());

        // ...and a compiler version does NOT belong here: that is the `.simf`
        // `simc "<range>";` directive's job, so the key must be rejected.
        for key in ["version", "min_version", "simc"] {
            let json = format!(
                r#"{{ "manifest_version": "1", "protocol": "t",
                      "simplicity_hl": {{ "{key}": "0.6.0" }} }}"#
            );
            assert!(
                Manifest::from_json_str(&json).is_err(),
                "simplicity_hl.{key} must not be accepted"
            );
        }

        // ...as does an absent block entirely.
        let absent =
            Manifest::from_json_str(r#"{ "manifest_version": "1", "protocol": "t" }"#).unwrap();
        assert!(!absent.include_debug_symbols());
    }

    #[test]
    fn unstable_features_reach_the_compiler_and_default_to_none() {
        // The point of the field is that the set handed to the compiler is exactly what
        // the manifest listed — an entry that silently doesn't arrive shows up much later
        // as an "unstable feature not enabled" compile error.
        let enabled = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t",
                 "simplicity_hl": { "unstable_features": ["enums"] } }"#,
        )
        .expect("unstable_features should parse");
        assert_eq!(
            enabled.unstable_features(),
            UnstableFeatures::new([UnstableFeature::Enums])
        );
        // Purely a gate: it must not drag debug symbols (which move every address) along.
        assert!(!enabled.include_debug_symbols());

        // Absent block, empty block and empty list all mean "nothing unstable".
        for json in [
            r#"{ "manifest_version": "1", "protocol": "t" }"#,
            r#"{ "manifest_version": "1", "protocol": "t", "simplicity_hl": {} }"#,
            r#"{ "manifest_version": "1", "protocol": "t",
                 "simplicity_hl": { "unstable_features": [] } }"#,
        ] {
            let m = Manifest::from_json_str(json).expect("should parse");
            assert_eq!(m.unstable_features(), UnstableFeatures::none(), "{json}");
        }

        // A name the compiler doesn't know is a load-time error, not a mystery compile
        // failure later — and the message says which names exist.
        let err = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t",
                 "simplicity_hl": { "unstable_features": ["enum"] } }"#,
        )
        .expect_err("a misspelled feature must not parse");
        let msg = err.to_string();
        assert!(msg.contains("enum"), "{msg}");
        assert!(msg.contains("enums"), "message should list known features: {msg}");

        // Both settings travel together to the compile sites.
        let both = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t",
                 "simplicity_hl": { "debug_symbols": true, "unstable_features": ["enums", "enums"] } }"#,
        )
        .expect("both settings should parse");
        let opts = both.compile_opts();
        assert!(opts.debug_symbols);
        // Duplicates collapse rather than being passed through twice.
        assert_eq!(
            opts.unstable_features,
            UnstableFeatures::new([UnstableFeature::Enums])
        );
    }

    #[test]
    fn wallet_computes_are_recognised_and_are_not_expressions() {
        let m = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t", "actions": { "A": { "params": {
                 "K": { "type": "pubkey",  "compute": { "type": "wallet", "wallet": "key" } },
                 "H": { "type": "bytes32", "compute": { "type": "wallet", "wallet": "script_hash" } },
                 "A": { "type": "string",  "compute": { "type": "wallet", "wallet": "address" } },
                 "E": { "type": "u64",     "compute": "1 + 1" } } } } }"#,
        )
        .expect("wallet computes should parse");
        let params = m.actions["A"].params.as_ref().unwrap();
        let spec = |n: &str| params[n].compute.as_ref().unwrap();

        use crate::manifest::WalletValue as WV;
        assert_eq!(spec("K").as_wallet(), Some(WV::Key));
        assert_eq!(spec("H").as_wallet(), Some(WV::ScriptHash));
        assert_eq!(spec("A").as_wallet(), Some(WV::Address));
        for n in ["K", "H", "A"] {
            // A wallet value is not reproducible from the manifest, so it must never
            // be mistaken for an expression the engine could evaluate itself.
            assert_eq!(spec(n).as_expr(), None, "{n} must not read as an expression");
        }
        assert!(spec("E").as_wallet().is_none());
        assert_eq!(spec("E").as_expr(), Some("1 + 1"));
    }

    #[test]
    fn compute_accepts_both_spellings_equivalently() {
        // `"compute": "a + b"` is shorthand for `{"type":"expr","expr":"a + b"}`.
        // Callers read through `as_expr()`, so neither spelling is privileged.
        let bare = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t", "actions": { "A": {
                 "params": { "P": { "type": "u64", "compute": "1 + 1" } } } } }"#,
        )
        .expect("bare expression should parse");
        let spelled = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t", "actions": { "A": {
                 "params": { "P": { "type": "u64",
                   "compute": { "type": "expr", "expr": "1 + 1" } } } } } }"#,
        )
        .expect("structured expr should parse");

        let expr_of = |m: &Manifest| {
            m.actions["A"].params.as_ref().unwrap()["P"]
                .compute
                .as_ref()
                .unwrap()
                .as_expr()
                .map(str::to_string)
        };
        assert_eq!(expr_of(&bare), Some("1 + 1".to_string()));
        assert_eq!(expr_of(&bare), expr_of(&spelled));

        // A tapleaf spec is not an expression, and must not masquerade as one.
        let tapleaf = Manifest::from_json_str(
            r#"{ "manifest_version": "1", "protocol": "t", "actions": { "A": {
                 "params": { "P": { "type": "u64",
                   "compute": { "type": "tapleaf", "simf": "./a.simf" } } } } } }"#,
        )
        .expect("tapleaf spec should parse");
        assert_eq!(expr_of(&tapleaf), None);
    }

    #[test]
    fn sibling_compile_params_still_parse() {
        // Two *other* fields share the name and must be unaffected by the removal of
        // the top-level one: the per-utxo-type simf wiring, and the simf_fn list.
        let json = r#"{
            "manifest_version": "1",
            "protocol": "test",
            "actions": {
                "A": {
                    "params": {
                        "P": {
                            "type": "u64",
                            "compute": {
                                "type": "simf_fn", "simf": "./a.simf", "compile_params": ["X"]
                            }
                        }
                    }
                }
            },
            "utxo_types": {
                "t": {
                    "description": "d",
                    "script": {
                        "type": "simplicity", "source": "./a.simf",
                        "compile_params": { "SCRIPT_HASH": "LENDING_COV_HASH" }
                    }
                }
            }
        }"#;
        let manifest = Manifest::from_json_str(json).expect("sibling compile_params should parse");
        let script = manifest.utxo_types.as_ref().unwrap()["t"]
            .script
            .as_ref()
            .unwrap();
        assert_eq!(script.compile_params["SCRIPT_HASH"], "LENDING_COV_HASH");
    }

    #[test]
    fn comment_key_is_allowed_at_any_depth() {
        // `$comment` is the one key authors may put in any object; it is stripped
        // before deserialization rather than modelled on every struct.
        let json = manifest_json(r#", "$comment": "why this input exists""#);
        let manifest = Manifest::from_json_str(&json).expect("$comment should be stripped");
        assert_eq!(manifest.actions["A"].inputs.as_ref().unwrap()[0].id, "in0");
    }

    #[test]
    fn comment_key_is_allowed_at_top_level() {
        let json = r#"{
            "$comment": "file-level note",
            "manifest_version": "1",
            "protocol": "test"
        }"#;
        Manifest::from_json_str(json).expect("top-level $comment should be stripped");
    }

    /// A bad `compute` spec must say what is wrong with it.
    ///
    /// Under `#[serde(untagged)]` every one of these collapsed to `data did not match
    /// any variant of untagged enum ComputeSpec`, which tells an author nothing — the
    /// opposite of what `deny_unknown_fields` is here to achieve.
    #[test]
    fn a_bad_compute_spec_names_the_problem() {
        let manifest_with = |compute: &str| {
            format!(
                r#"{{ "manifest_version": "1", "protocol": "t", "actions": {{ "A": {{
                     "params": {{ "P": {{ "type": "u64", "compute": {compute} }} }} }} }} }}"#
            )
        };
        // (compute spec, the substring the error must contain)
        for (compute, needle) in [
            // An unknown key inside an otherwise well-formed spec.
            (r#"{ "type": "tapleaf", "simf": "./a.simf", "bogus": 1 }"#, "bogus"),
            // An unknown discriminator.
            (r#"{ "type": "no_such_kind" }"#, "no_such_kind"),
            // A required field missing from a known variant.
            (r#"{ "type": "tapleaf" }"#, "simf"),
            // Not a string and not an object.
            ("42", "a number"),
        ] {
            let err = Manifest::from_json_str(&manifest_with(compute))
                .expect_err("a bad compute spec must not parse");
            assert!(
                err.to_string().contains(needle),
                "error for {compute} should mention '{needle}', got: {err}"
            );
            assert!(
                !err.to_string().contains("did not match any variant"),
                "error for {compute} should not be the untagged catch-all, got: {err}"
            );
        }
    }

    /// Same for `ui`, which has the same two-spellings shape.
    #[test]
    fn a_bad_ui_spec_names_the_problem() {
        let manifest_with = |ui: &str| {
            format!(
                r#"{{ "manifest_version": "1", "protocol": "t", "actions": {{ "A": {{
                     "outputs": [ {{ "id": "o0", "destination": "change", "ui": {ui} }} ] }} }} }}"#
            )
        };
        for (ui, needle) in [
            (r#"{ "label": "ok", "rol": "typo" }"#, "rol"),
            ("42", "a number"),
        ] {
            let err = Manifest::from_json_str(&manifest_with(ui))
                .expect_err("a bad ui spec must not parse");
            assert!(
                err.to_string().contains(needle),
                "error for {ui} should mention '{needle}', got: {err}"
            );
            assert!(
                !err.to_string().contains("did not match any variant"),
                "error for {ui} should not be the untagged catch-all, got: {err}"
            );
        }
    }

    #[test]
    fn both_ui_spellings_still_parse() {
        // The manual impl must not have narrowed what is accepted.
        let json = r#"{ "manifest_version": "1", "protocol": "t", "actions": { "A": {
             "outputs": [
               { "id": "o0", "destination": "change", "ui": "bare label" },
               { "id": "o1", "destination": "change",
                 "ui": { "label": "detailed", "role": "change", "hide": true } } ] } } }"#;
        let m = Manifest::from_json_str(json).expect("both ui spellings should parse");
        let outputs = m.actions["A"].outputs.as_ref().unwrap();
        assert_eq!(outputs[0].ui_label(), Some("bare label"));
        assert_eq!(outputs[0].ui_role(), None);
        assert_eq!(outputs[1].ui_label(), Some("detailed"));
        assert_eq!(outputs[1].ui_role(), Some("change"));
        assert!(outputs[1].ui.as_ref().unwrap().hidden());
    }

    #[test]
    fn type_key_dispatches_tapleaf() {
        let fv = parse_field_value(r#"{ "type": "tapleaf", "simf": "./a.simf" }"#);
        assert!(matches!(
            fv,
            ComputeSpec::Compute(ParamCompute::Tapleaf { .. })
        ));
    }

    #[test]
    fn legacy_lang_key_is_accepted_as_alias() {
        let fv = parse_field_value(r#"{ "lang": "tapleaf", "simf": "./a.simf" }"#);
        assert!(matches!(
            fv,
            ComputeSpec::Compute(ParamCompute::Tapleaf { .. })
        ));
    }

    #[test]
    fn type_wins_when_both_keys_present() {
        // `type` is canonical; a stray `lang` must not override it.
        let fv = parse_field_value(r#"{ "type": "expr", "lang": "tapleaf", "expr": "1 + 1" }"#);
        assert!(matches!(fv, ComputeSpec::Compute(ParamCompute::Expr { .. })));
    }
}
