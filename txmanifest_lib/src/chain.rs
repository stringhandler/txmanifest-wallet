//! Which ledger a manifest targets, and what that ledger can do.
//!
//! Everything in this engine was written against Liquid/Elements, where a great deal is
//! simply assumed: outputs carry an asset id, amounts may be blinded, the fee is its own
//! `TxOut`, taproot tagged hashes are domain-separated with an `/elements` suffix, and a
//! Simplicity tapleaf will be executed by the validator. None of those hold on Bitcoin.
//!
//! This module is the seam. It splits the assumptions into three kinds, because they are
//! settled by different parties at different times:
//!
//! - **[`ChainFamily`] properties** — what follows from the ledger itself. Whether outputs
//!   carry an asset id, whether amounts can be blinded, whether the fee is its own output,
//!   which taproot tag domain applies. Nobody declares these: `chain: "bitcoin"` already
//!   says there are no native assets, and a manifest repeating that in a feature list
//!   would only create a second place to disagree.
//! - **[`Capability`]** — what a *manifest* must state because the chain alone does not
//!   settle it. Today that is exactly one thing, [`Capability::SIMPLICITY`], because
//!   Simplicity is a soft fork on Bitcoin rather than a property of it. Plus whatever
//!   third parties define under their own namespace.
//! - **[`Activation`]** — what the specific node being talked to actually provides. This
//!   is configuration, not discovery.
//!
//! # Why the core capability set is so small
//!
//! An earlier cut of this module also had `multi-asset`, `asset-issuance` and
//! `confidential-amounts` as declarable capabilities. They came out: every one of them is
//! implied by `chain`, so declaring them was redundant, and a redundant declaration is a
//! declaration that can be wrong. The checks they powered did not go away — a manifest
//! using issuance on Bitcoin is still an error — they just read the chain instead of a
//! restatement of it. See [`ChainFamily::has_native_assets`] and its neighbours.
//!
//! What is left in [`Capability`] is the residue that genuinely cannot be inferred: a soft
//! fork's activation state, and features this crate has never heard of.
//!
//! # Namespaces
//!
//! A bare name (`simplicity`) is defined by this format and comes from a closed set — an
//! unrecognized bare name is an error, because it is almost always a typo, and silently
//! ignoring it would mean a manifest requesting nothing while appearing to request
//! something. A name containing `::` (`custom::my-feature`, `mosaik::tessera`) belongs to
//! whoever owns that namespace. This crate cannot check those, so it carries them through:
//! they parse, they round-trip, and a target satisfies them only by declaring them in
//! [`Activation::extensions`]. That is what lets a downstream tool extend the vocabulary
//! without patching this crate or colliding with a future core name.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use schemars::gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

// ---------------------------------------------------------------------------
// Chain family
// ---------------------------------------------------------------------------

/// The ledger a manifest is written for, independent of which network of it is in use.
///
/// This is the manifest-facing granularity: a protocol works on Liquid and Liquid testnet
/// alike, so pinning the network in the file would be wrong. The wallet's config picks the
/// [`Network`]; the manifest picks the family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainFamily {
    /// Liquid and any other Elements-based sidechain: confidential, multi-asset,
    /// explicit fee outputs, Simplicity already live.
    Elements,
    /// Bitcoin: single asset, transparent amounts, implicit fee.
    Bitcoin,
}

impl ChainFamily {
    /// The family assumed when a manifest declares no `chain`.
    ///
    /// Elements, because every manifest written before the field existed was an Elements
    /// manifest. A new default would silently reinterpret them.
    pub const DEFAULT: ChainFamily = ChainFamily::Elements;

    /// Whether outputs carry an asset id other than the chain's own unit of account.
    ///
    /// False on Bitcoin, which has exactly one asset. This is the fact that makes a
    /// per-output `asset` field, an issuance input, or `allow_change: "any"` meaningless
    /// there — see `Manifest::elements_only_uses`.
    pub fn has_native_assets(self) -> bool {
        matches!(self, ChainFamily::Elements)
    }

    /// Whether an issuance or reissuance input can mint an asset.
    ///
    /// Separate from [`Self::has_native_assets`] even though the two agree today: a chain
    /// could carry assets it cannot mint, and the error messages differ — a manifest that
    /// merely *moves* a second asset has a smaller problem than one that creates it.
    pub fn has_asset_issuance(self) -> bool {
        matches!(self, ChainFamily::Elements)
    }

    /// Whether amounts and assets can be blinded — rangeproofs, surjection proofs,
    /// blinding factors. False on Bitcoin, where amounts are always explicit.
    pub fn has_confidential_amounts(self) -> bool {
        matches!(self, ChainFamily::Elements)
    }

    /// Whether the fee is carried by an explicit `TxOut`.
    ///
    /// Elements makes the fee a real output with the policy asset and no scriptPubKey, so
    /// a Simplicity program can introspect it (`jet::output_is_fee`). Bitcoin leaves it
    /// implicit as inputs minus outputs, and a covenant reads it via `jet::fee`.
    pub fn has_explicit_fee_output(self) -> bool {
        matches!(self, ChainFamily::Elements)
    }

    /// Tag suffix for taproot tagged hashes on this family.
    ///
    /// Elements domain-separates its taproot hashes (`TapLeaf/elements`) so that a tree
    /// built for one chain cannot be replayed on the other. The consequence for this
    /// engine is blunt: the same covenant program yields a **different address** on
    /// Bitcoin than on Liquid.
    pub fn taproot_tag_suffix(self) -> &'static str {
        match self {
            ChainFamily::Elements => "/elements",
            ChainFamily::Bitcoin => "",
        }
    }

    /// Full tag string for a taproot tagged hash, e.g. `TapBranch/elements`.
    pub fn taproot_tag(self, base: TaprootTag) -> String {
        format!("{}{}", base.base_name(), self.taproot_tag_suffix())
    }

    /// Canonical lowercase name, as written in a manifest's `chain` field.
    pub fn as_str(self) -> &'static str {
        match self {
            ChainFamily::Elements => "elements",
            ChainFamily::Bitcoin => "bitcoin",
        }
    }
}

impl Default for ChainFamily {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for ChainFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ChainFamily {
    type Err = UnknownChain;

    /// Accepts the spellings already in the wild. `liquid` is the name every example in
    /// this repo uses, and it names a specific Elements network rather than the family —
    /// but rejecting it would break every existing manifest to no purpose.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "elements" | "liquid" => Ok(ChainFamily::Elements),
            "bitcoin" | "btc" => Ok(ChainFamily::Bitcoin),
            other => Err(UnknownChain(other.to_string())),
        }
    }
}

/// A `chain` value this build does not recognize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownChain(pub String);

impl fmt::Display for UnknownChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown chain '{}'; expected one of: elements, liquid, bitcoin",
            self.0
        )
    }
}

impl std::error::Error for UnknownChain {}

impl<'de> Deserialize<'de> for ChainFamily {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        ChainFamily::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// Which of the three taproot tagged hashes a tag string is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaprootTag {
    Leaf,
    Branch,
    Tweak,
}

impl TaprootTag {
    /// The Bitcoin (unsuffixed) tag name.
    pub fn base_name(self) -> &'static str {
        match self {
            TaprootTag::Leaf => "TapLeaf",
            TaprootTag::Branch => "TapBranch",
            TaprootTag::Tweak => "TapTweak",
        }
    }
}

/// Taproot leaf version reserved for Simplicity.
///
/// The same byte on both chains: Elements uses it for its live deployment, and the
/// Bitcoin proposal (BINANA 2026-0003, `TAPROOT_LEAF_TAPSIMPLICITY`) reuses it. The tag
/// *domain* differs, but the leaf version does not — so this is a constant, not a
/// [`ChainFamily`] method, and should stay one unless a chain actually diverges.
pub const SIMPLICITY_LEAF_VERSION: u8 = 0xbe;

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// The separator between a capability's namespace and its name.
pub const NAMESPACE_SEP: &str = "::";

/// A feature a manifest declares in `requires`, because the chain alone does not settle it.
///
/// Two shapes:
///
/// - **Core**, written bare (`simplicity`). Defined by this format, drawn from
///   [`Capability::CORE`], and validated on parse.
/// - **Namespaced**, written `namespace::name` (`custom::my-feature`). Owned by whoever
///   owns the namespace. This crate does not know what they mean and does not pretend to;
///   it parses them, keeps them, and reports them unsatisfied unless a target names them
///   in [`Activation::extensions`].
///
/// Anything a chain settles on its own is deliberately *not* here. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// A capability defined by this format, written without a namespace.
    Core(CoreCapability),
    /// A third-party capability, written `namespace::name`.
    ///
    /// Both halves are lowercase, start with an alphanumeric, and otherwise contain only
    /// alphanumerics, `_` and `-`. Held as strings because the set is open by design: the
    /// point is that a downstream tool can define one without touching this crate.
    Namespaced { namespace: String, name: String },
}

/// A capability this format defines itself. Bare names, closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoreCapability {
    /// Covenant `utxo_types` backed by SimplicityHL programs, spent through a Simplicity
    /// tapleaf the validator executes.
    ///
    /// The one core capability, because it is the one thing the `chain` field does not
    /// settle. On Elements it is live. On Bitcoin it is a proposed soft fork (BINANA
    /// 2026-0003) — implemented in the C library, but not activated on mainnet, testnet,
    /// or the default signet — so whether a given Bitcoin node honours it is a property of
    /// that node, not of Bitcoin.
    ///
    /// A manifest that declares no `utxo_types` with a `script` does not need this, and
    /// can target a stock Bitcoin node.
    Simplicity,
}

impl CoreCapability {
    /// Canonical bare name.
    pub fn as_str(self) -> &'static str {
        match self {
            CoreCapability::Simplicity => "simplicity",
        }
    }
}

impl Capability {
    /// The Simplicity capability, spelled out for call sites.
    pub const SIMPLICITY: Capability = Capability::Core(CoreCapability::Simplicity);

    /// Every core capability this build defines.
    pub const CORE: [CoreCapability; 1] = [CoreCapability::Simplicity];

    /// Build a namespaced capability, validating both halves.
    pub fn namespaced(
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Capability, BadCapability> {
        let namespace = namespace.into();
        let name = name.into();
        check_segment(&namespace)?;
        check_segment(&name)?;
        Ok(Capability::Namespaced { namespace, name })
    }

    /// The namespace, or `None` for a core capability.
    pub fn namespace(&self) -> Option<&str> {
        match self {
            Capability::Core(_) => None,
            Capability::Namespaced { namespace, .. } => Some(namespace),
        }
    }

    /// Whether this crate can reason about what the capability means.
    ///
    /// False for every namespaced capability. Callers use it to decide whether an
    /// unsatisfied requirement is worth explaining or merely worth reporting.
    pub fn is_core(&self) -> bool {
        matches!(self, Capability::Core(_))
    }

    /// One line on why a target that lacks this capability cannot run the manifest.
    pub fn unsupported_hint(&self) -> String {
        match self {
            Capability::Core(CoreCapability::Simplicity) => {
                "covenant programs need a validator that executes Simplicity tapleaves; on \
                 Bitcoin that is the BINANA 2026-0003 soft fork, which no public network has \
                 activated"
                    .to_string()
            }
            Capability::Namespaced { namespace, .. } => format!(
                "defined by '{namespace}', not by this format; a target provides it only by \
                 listing it as an extension"
            ),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::Core(c) => f.write_str(c.as_str()),
            Capability::Namespaced { namespace, name } => {
                write!(f, "{namespace}{NAMESPACE_SEP}{name}")
            }
        }
    }
}

/// A `requires` entry that is not a valid capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadCapability {
    /// A bare name that is not in [`Capability::CORE`].
    UnknownCore(String),
    /// A namespace or name that breaks the charset rule.
    MalformedSegment(String),
    /// More than one `::`, or an empty half.
    MalformedName(String),
}

impl fmt::Display for BadCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadCapability::UnknownCore(s) => write!(
                f,
                "unknown capability '{s}'; this format defines {}. \
                 A third-party feature must be namespaced, e.g. 'custom{NAMESPACE_SEP}{s}'",
                Capability::CORE
                    .iter()
                    .map(|c| format!("'{}'", c.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            BadCapability::MalformedSegment(s) => write!(
                f,
                "invalid capability segment '{s}'; each half must be lowercase, start with a \
                 letter or digit, and contain only letters, digits, '_' and '-'"
            ),
            BadCapability::MalformedName(s) => write!(
                f,
                "malformed capability '{s}'; expected a bare name or exactly one \
                 '{NAMESPACE_SEP}' separating a namespace from a name"
            ),
        }
    }
}

impl std::error::Error for BadCapability {}

/// Validate one half of a namespaced capability.
fn check_segment(seg: &str) -> Result<(), BadCapability> {
    let ok = !seg.is_empty()
        && seg.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && seg
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(BadCapability::MalformedSegment(seg.to_string()))
    }
}

impl FromStr for Capability {
    type Err = BadCapability;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Underscores as well as hyphens in a *core* name: the rest of the manifest format
        // is snake_case, so an author reaching for `asset_issuance` has not made a
        // meaningful mistake. Namespaced names are left exactly as written — they belong to
        // someone else, and silently rewriting them would make two spellings of one
        // third-party feature that this crate treats as equal and its owner may not.
        let raw = s.trim();
        match raw.split_once(NAMESPACE_SEP) {
            None => {
                let norm = raw.to_ascii_lowercase().replace('_', "-");
                Capability::CORE
                    .iter()
                    .copied()
                    .find(|c| c.as_str() == norm)
                    .map(Capability::Core)
                    .ok_or_else(|| BadCapability::UnknownCore(raw.to_string()))
            }
            Some((ns, name)) => {
                // A second separator would make the owner ambiguous.
                if name.contains(NAMESPACE_SEP) || ns.is_empty() || name.is_empty() {
                    return Err(BadCapability::MalformedName(raw.to_string()));
                }
                Capability::namespaced(ns, name)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Capability::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// A set of [`Capability`] values.
///
/// A set rather than a bitflags integer both because the space is open — a namespaced
/// capability has no bit to assign — and because it is serialized into a human-edited file
/// and read back in error messages. Ordering is core-first, then namespaced
/// lexicographically, which keeps `validate` output stable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Capabilities(BTreeSet<Capability>);

impl Capabilities {
    /// The empty set — a manifest that needs nothing beyond plain transactions.
    pub fn none() -> Self {
        Self(BTreeSet::new())
    }

    pub fn contains(&self, c: &Capability) -> bool {
        self.0.contains(c)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn insert(&mut self, c: Capability) -> bool {
        self.0.insert(c)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Capability> + '_ {
        self.0.iter()
    }

    /// Members of `self` that `other` does not provide. Empty means `other` can run
    /// whatever needs `self`.
    pub fn missing_from(&self, other: &Capabilities) -> Vec<Capability> {
        self.0
            .iter()
            .filter(|c| !other.contains(c))
            .cloned()
            .collect()
    }

    /// Comma-separated canonical names, or `"none"` when empty.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "none".to_string();
        }
        self.iter().map(Capability::to_string).collect::<Vec<_>>().join(", ")
    }
}

impl FromIterator<Capability> for Capabilities {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

/// A concrete network the wallet can connect to.
///
/// Chosen by the wallet's config, not by the manifest. Exists so that nothing outside
/// this module has to name `lwk_wollet::ElementsNetwork` — that type cannot describe a
/// Bitcoin network, and every call site that takes it today is a place the Bitcoin port
/// would otherwise have to fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    Liquid,
    LiquidTestnet,
    ElementsRegtest,
    Bitcoin,
    BitcoinTestnet,
    BitcoinSignet,
    BitcoinRegtest,
}

impl Network {
    pub fn family(self) -> ChainFamily {
        match self {
            Network::Liquid | Network::LiquidTestnet | Network::ElementsRegtest => {
                ChainFamily::Elements
            }
            Network::Bitcoin
            | Network::BitcoinTestnet
            | Network::BitcoinSignet
            | Network::BitcoinRegtest => ChainFamily::Bitcoin,
        }
    }

    /// Whether this is a production network carrying real value.
    ///
    /// Drives confirmation prompts, so it errs toward `true`: a network this build does
    /// not recognize as a testnet is treated as mainnet.
    pub fn is_mainnet(self) -> bool {
        matches!(self, Network::Liquid | Network::Bitcoin)
    }

    /// What this network, running the node described by `activation`, actually provides.
    ///
    /// Simplicity is unconditional on Elements and configuration-dependent on Bitcoin.
    /// Everything else comes from `activation.extensions` verbatim: this crate cannot
    /// verify a namespaced capability, so it takes the operator's word and reports the
    /// requirement as satisfied.
    pub fn capabilities(self, activation: &Activation) -> Capabilities {
        let mut caps = activation.extensions.clone();
        let simplicity_live = match self.family() {
            ChainFamily::Elements => true,
            ChainFamily::Bitcoin => activation.simplicity,
        };
        if simplicity_live {
            caps.insert(Capability::SIMPLICITY);
        }
        caps
    }

    /// Canonical lowercase name, as written in the wallet config's `default_network`.
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Liquid => "liquid",
            Network::LiquidTestnet => "liquid-testnet",
            Network::ElementsRegtest => "elements-regtest",
            Network::Bitcoin => "bitcoin",
            Network::BitcoinTestnet => "bitcoin-testnet",
            Network::BitcoinSignet => "bitcoin-signet",
            Network::BitcoinRegtest => "bitcoin-regtest",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Network {
    type Err = UnknownNetwork;

    /// Accepts the config spellings this wallet has always written (`mainnet`, `testnet`,
    /// meaning Liquid) alongside the explicit ones. The bare legacy names stay bound to
    /// Elements: a config file written before Bitcoin support existed means Liquid by
    /// `mainnet`, and re-reading it as Bitcoin would point a funded wallet at the wrong
    /// chain.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "liquid" | "mainnet" => Ok(Network::Liquid),
            "liquid-testnet" | "liquidtestnet" | "testnet" => Ok(Network::LiquidTestnet),
            "elements-regtest" | "elementsregtest" | "regtest" => Ok(Network::ElementsRegtest),
            "bitcoin" | "bitcoin-mainnet" => Ok(Network::Bitcoin),
            "bitcoin-testnet" | "bitcoin-testnet4" => Ok(Network::BitcoinTestnet),
            "bitcoin-signet" | "signet" => Ok(Network::BitcoinSignet),
            "bitcoin-regtest" => Ok(Network::BitcoinRegtest),
            other => Err(UnknownNetwork(other.to_string())),
        }
    }
}

/// A `default_network` value this build does not recognize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNetwork(pub String);

impl fmt::Display for UnknownNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown network '{}'; expected one of: liquid, liquid-testnet, elements-regtest, \
             bitcoin, bitcoin-testnet, bitcoin-signet, bitcoin-regtest",
            self.0
        )
    }
}

impl std::error::Error for UnknownNetwork {}

/// What the node the wallet is talking to provides, beyond its network's base rules.
///
/// Configuration, not discovery: nothing here probes the node. A wallet pointed at a
/// patched signet sets `simplicity: true` and takes responsibility for that claim; the
/// failure mode if it is wrong is a rejected broadcast, not a lost coin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activation {
    /// Whether the node executes Simplicity tapleaves. Ignored on Elements networks,
    /// where it is live regardless.
    pub simplicity: bool,
    /// Namespaced capabilities the operator asserts this target provides.
    ///
    /// The escape hatch that makes third-party capabilities usable: this crate has no way
    /// to verify `custom::my-feature`, so the only thing that can satisfy it is somebody
    /// saying so here.
    pub extensions: Capabilities,
}

impl Activation {
    /// Nothing beyond the network's base rules.
    pub fn none() -> Activation {
        Activation::default()
    }

    /// Simplicity live and no extensions.
    pub fn simplicity() -> Activation {
        Activation {
            simplicity: true,
            extensions: Capabilities::none(),
        }
    }

    /// What to assume for `network` when the config says nothing.
    ///
    /// Elements networks have Simplicity live, so assuming it is correct there. Bitcoin
    /// networks do not, on any public network, so the default is off and a user running a
    /// patched node opts in explicitly.
    pub fn default_for(network: Network) -> Activation {
        match network.family() {
            ChainFamily::Elements => Activation::simplicity(),
            ChainFamily::Bitcoin => Activation::none(),
        }
    }
}

// ---------------------------------------------------------------------------
// Interop with lwk / elements types
// ---------------------------------------------------------------------------

impl Network {
    /// The `lwk_wollet` network for an Elements network.
    ///
    /// `None` for a Bitcoin network — `ElementsNetwork` has no variant that could stand in
    /// for one, and inventing a mapping would let Bitcoin flow into Elements-only code
    /// paths and produce addresses on the wrong chain. Callers must handle the `None`.
    pub fn elements_network(self) -> Option<lwk_wollet::ElementsNetwork> {
        match self {
            Network::Liquid => Some(lwk_wollet::ElementsNetwork::Liquid),
            Network::LiquidTestnet => Some(lwk_wollet::ElementsNetwork::LiquidTestnet),
            Network::ElementsRegtest => {
                // The policy asset of a regtest chain is chosen by whoever started it, so
                // there is no single right answer here. This is the value the wallet has
                // always used; it stays until regtest support needs to be configurable.
                Some(lwk_wollet::ElementsNetwork::default_regtest())
            }
            Network::Bitcoin
            | Network::BitcoinTestnet
            | Network::BitcoinSignet
            | Network::BitcoinRegtest => None,
        }
    }
}

impl From<lwk_wollet::ElementsNetwork> for Network {
    fn from(n: lwk_wollet::ElementsNetwork) -> Self {
        match n {
            lwk_wollet::ElementsNetwork::Liquid => Network::Liquid,
            lwk_wollet::ElementsNetwork::LiquidTestnet => Network::LiquidTestnet,
            lwk_wollet::ElementsNetwork::ElementsRegtest { .. } => Network::ElementsRegtest,
        }
    }
}

// ---------------------------------------------------------------------------
// JSON Schema
// ---------------------------------------------------------------------------

impl JsonSchema for ChainFamily {
    fn schema_name() -> String {
        "ChainFamily".to_string()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        // Written by hand rather than derived: the derive emits only the canonical
        // spellings, while `FromStr` accepts aliases. A schema stricter than the parser is
        // not a harmless conservatism here — it makes an editor red-underline
        // `"chain": "liquid"` in files this engine reads happily, including every example
        // in this repo. Whatever the parser accepts, the schema must list.
        let mut schema = SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            ..Default::default()
        };
        schema.metadata().description = Some(
            "Ledger this manifest targets. 'liquid' is an accepted alias for 'elements', and \
             'btc' for 'bitcoin'. Defaults to 'elements' when absent."
                .to_string(),
        );
        schema.enum_values = Some(
            ["elements", "liquid", "bitcoin", "btc"]
                .iter()
                .map(|v| serde_json::json!(v))
                .collect(),
        );
        Schema::Object(schema)
    }
}

impl JsonSchema for Capability {
    fn schema_name() -> String {
        "Capability".to_string()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        // An `enum` cannot express this: core names are a closed list, but namespaced ones
        // are open by design. So the schema is a union of the two — the closed list, so an
        // editor can still complete and typo-check a bare name, and a pattern for anything
        // namespaced.
        let mut core_names: Vec<serde_json::Value> = Vec::new();
        for c in Capability::CORE {
            core_names.push(serde_json::json!(c.as_str()));
            let snake = c.as_str().replace('-', "_");
            if snake != c.as_str() {
                core_names.push(serde_json::json!(snake));
            }
        }

        let core = serde_json::json!({
            "enum": core_names,
            "description": "A capability defined by this format.",
        });
        let seg = "[a-z0-9][a-z0-9_-]*";
        let namespaced = serde_json::json!({
            "type": "string",
            "pattern": format!("^{seg}{NAMESPACE_SEP}{seg}$"),
            "description":
                "A third-party capability, 'namespace::name'. This format does not define \
                 its meaning; a target provides it by listing it as an extension.",
        });

        let mut schema = SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            ..Default::default()
        };
        schema.metadata().description = Some(
            "A ledger feature this manifest depends on that the 'chain' field does not \
             already settle. Bare names are defined by this format; anything containing \
             '::' belongs to the named namespace."
                .to_string(),
        );
        schema.subschemas().any_of = Some(vec![
            Schema::Object(serde_json::from_value(core).expect("core branch is a schema")),
            Schema::Object(
                serde_json::from_value(namespaced).expect("namespaced branch is a schema"),
            ),
        ]);
        Schema::Object(schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_family_accepts_the_spellings_already_in_use() {
        assert_eq!("liquid".parse::<ChainFamily>().unwrap(), ChainFamily::Elements);
        assert_eq!("elements".parse::<ChainFamily>().unwrap(), ChainFamily::Elements);
        assert_eq!("Bitcoin".parse::<ChainFamily>().unwrap(), ChainFamily::Bitcoin);
        assert_eq!("  BTC ".parse::<ChainFamily>().unwrap(), ChainFamily::Bitcoin);
        assert!("cross-chain".parse::<ChainFamily>().is_err());
    }

    #[test]
    fn taproot_tags_are_domain_separated_on_elements_only() {
        assert_eq!(ChainFamily::Elements.taproot_tag(TaprootTag::Branch), "TapBranch/elements");
        assert_eq!(ChainFamily::Bitcoin.taproot_tag(TaprootTag::Branch), "TapBranch");
        assert_eq!(ChainFamily::Elements.taproot_tag(TaprootTag::Leaf), "TapLeaf/elements");
        assert_eq!(ChainFamily::Bitcoin.taproot_tag(TaprootTag::Leaf), "TapLeaf");
    }

    /// The properties that replaced the old declarable capabilities. These are read off
    /// `chain` rather than declared, which is the whole point of removing them.
    #[test]
    fn asset_and_confidentiality_follow_from_the_chain() {
        assert!(ChainFamily::Elements.has_native_assets());
        assert!(ChainFamily::Elements.has_asset_issuance());
        assert!(ChainFamily::Elements.has_confidential_amounts());
        assert!(ChainFamily::Elements.has_explicit_fee_output());

        assert!(!ChainFamily::Bitcoin.has_native_assets());
        assert!(!ChainFamily::Bitcoin.has_asset_issuance());
        assert!(!ChainFamily::Bitcoin.has_confidential_amounts());
        assert!(!ChainFamily::Bitcoin.has_explicit_fee_output());
    }

    #[test]
    fn core_capability_names_round_trip() {
        for c in Capability::CORE {
            let parsed: Capability = c.as_str().parse().unwrap();
            assert_eq!(parsed, Capability::Core(c));
            assert_eq!(parsed.to_string(), c.as_str());
            assert!(parsed.is_core());
        }
    }

    /// An unrecognized bare name is a typo far more often than a deliberate extension, and
    /// silently accepting it would mean a manifest that requests nothing while appearing to
    /// request something. The error points at the namespaced spelling.
    #[test]
    fn an_unknown_bare_name_is_refused_and_suggests_a_namespace() {
        let err = "teleportation".parse::<Capability>().unwrap_err();
        assert!(matches!(err, BadCapability::UnknownCore(_)));
        assert!(err.to_string().contains("custom::teleportation"), "{err}");

        // The capabilities removed in favour of reading `chain` are refused the same way.
        for gone in ["multi-asset", "asset-issuance", "confidential-amounts"] {
            assert!(gone.parse::<Capability>().is_err(), "{gone} should no longer parse");
        }
    }

    #[test]
    fn namespaced_capabilities_round_trip_verbatim() {
        let c: Capability = "custom::my-feature".parse().unwrap();
        assert_eq!(
            c,
            Capability::Namespaced {
                namespace: "custom".into(),
                name: "my-feature".into()
            }
        );
        assert_eq!(c.to_string(), "custom::my-feature");
        assert_eq!(c.namespace(), Some("custom"));
        assert!(!c.is_core());

        // Any namespace, not just `custom` — vendor namespaces are what avoid collisions.
        assert!("mosaik::tessera".parse::<Capability>().is_ok());
    }

    /// A core name normalizes `_` to `-`; a namespaced one must not, because the two
    /// spellings would then be one capability here and possibly two to whoever defined it.
    #[test]
    fn only_core_names_are_normalized() {
        assert_eq!("SIMPLICITY".parse::<Capability>().unwrap(), Capability::SIMPLICITY);
        let a: Capability = "custom::my_feature".parse().unwrap();
        let b: Capability = "custom::my-feature".parse().unwrap();
        assert_ne!(a, b, "namespaced names must be taken verbatim");
    }

    #[test]
    fn malformed_capabilities_are_refused() {
        for bad in [
            "custom::",
            "::feature",
            "a::b::c",
            "Custom::Feature",
            "custom::-leading-dash",
            "custom::has space",
        ] {
            assert!(bad.parse::<Capability>().is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn simplicity_on_bitcoin_depends_on_activation() {
        assert!(!Network::BitcoinSignet
            .capabilities(&Activation::none())
            .contains(&Capability::SIMPLICITY));
        assert!(Network::BitcoinSignet
            .capabilities(&Activation::simplicity())
            .contains(&Capability::SIMPLICITY));

        // Elements has it live regardless of what the config claims.
        assert!(Network::Liquid
            .capabilities(&Activation::none())
            .contains(&Capability::SIMPLICITY));
    }

    /// The only thing that can satisfy a namespaced capability is a target asserting it.
    #[test]
    fn a_namespaced_capability_is_satisfied_only_by_an_extension() {
        let want = Capabilities::from_iter(["custom::my-feature".parse().unwrap()]);

        let plain = Network::Liquid.capabilities(&Activation::simplicity());
        assert_eq!(want.missing_from(&plain).len(), 1);

        let extended = Network::Liquid.capabilities(&Activation {
            simplicity: true,
            extensions: Capabilities::from_iter(["custom::my-feature".parse().unwrap()]),
        });
        assert!(want.missing_from(&extended).is_empty());
    }

    #[test]
    fn a_manifest_needing_nothing_runs_on_stock_bitcoin() {
        let plain = Capabilities::none();
        let stock = Network::Bitcoin.capabilities(&Activation::default_for(Network::Bitcoin));
        assert!(plain.missing_from(&stock).is_empty());
        assert_eq!(plain.describe(), "none");

        // ...and a covenant manifest does not.
        let covenant = Capabilities::from_iter([Capability::SIMPLICITY]);
        assert_eq!(covenant.missing_from(&stock), vec![Capability::SIMPLICITY]);
    }

    #[test]
    fn legacy_network_names_stay_bound_to_elements() {
        // A config written before Bitcoin support existed must not be reinterpreted.
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Liquid);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::LiquidTestnet);
        assert_eq!("signet".parse::<Network>().unwrap(), Network::BitcoinSignet);
        assert!("liquid-signet".parse::<Network>().is_err());
    }

    #[test]
    fn elements_networks_round_trip_through_lwk() {
        for n in [Network::Liquid, Network::LiquidTestnet, Network::ElementsRegtest] {
            let lwk = n.elements_network().expect("elements network maps");
            assert_eq!(Network::from(lwk), n);
        }
        assert!(Network::BitcoinSignet.elements_network().is_none());
    }
}
