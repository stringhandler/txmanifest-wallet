use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::chain::{Activation, Capabilities, Capability, Network};
use crate::wallet::default_data_dir;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// "testnet" or "mainnet"
    pub default_network: String,
    /// Override Esplora URL. If None, a sensible default is chosen from `default_network`.
    pub default_esplora: Option<String>,
    /// Chain backend to use: "esplora" (default) or "electrum".
    /// `#[serde(default)]` keeps config files written before this field was added parseable.
    #[serde(default)]
    pub default_backend: Option<String>,
    /// Electrum server URL (e.g. `ssl://host:50002`). Used only when `default_backend`
    /// is "electrum". If None, a network-appropriate Blockstream default is chosen.
    #[serde(default)]
    pub default_electrum: Option<String>,
    /// Whether the node this wallet talks to executes Simplicity tapleaves.
    ///
    /// Only consulted on Bitcoin networks; Elements has Simplicity live regardless. `None`
    /// means "take the network's default", which is off for Bitcoin — no public Bitcoin
    /// network has activated the BINANA 2026-0003 soft fork, so a user running a patched
    /// node opts in rather than every other user opting out.
    ///
    /// Configuration, not discovery: nothing probes the node. Setting it wrongly costs a
    /// rejected broadcast, not a coin.
    #[serde(default)]
    pub simplicity_activated: Option<bool>,
    /// Namespaced capabilities (`custom::my-feature`) the operator asserts this target
    /// provides. The only thing that can satisfy a third-party `requires` entry, since
    /// this crate has no way to verify one.
    #[serde(default)]
    pub extra_capabilities: Vec<String>,
    /// Which Bitcoin backend to use: `"esplora"` (default) or `"rpc"`.
    ///
    /// Separate from `default_backend`, which selects among the Elements backends. The two
    /// chains have disjoint backend sets, and one field naming both would accept
    /// `"electrum"` for Bitcoin — a value that parses and then cannot connect.
    #[serde(default)]
    pub bitcoin_backend: Option<String>,
    /// JSON-RPC endpoint of a Bitcoin node, e.g. `http://127.0.0.1:18443`.
    #[serde(default)]
    pub bitcoin_rpc_url: Option<String>,
    /// Path to the node's `.cookie` file. Preferred over `bitcoin_rpc_auth`: the cookie is
    /// rewritten on every node start, so it cannot go stale in a config file.
    #[serde(default)]
    pub bitcoin_rpc_cookie: Option<String>,
    /// `user:password` for nodes configured with `rpcauth` instead of a cookie.
    #[serde(default)]
    pub bitcoin_rpc_auth: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_network: "testnet".to_string(),
            default_esplora: None,
            default_backend: None,
            default_electrum: None,
            simplicity_activated: None,
            extra_capabilities: Vec::new(),
            bitcoin_backend: None,
            bitcoin_rpc_url: None,
            bitcoin_rpc_cookie: None,
            bitcoin_rpc_auth: None,
        }
    }
}

impl Config {
    /// Whether the configured network carries real value.
    ///
    /// Asks the network rather than comparing the string to `"mainnet"`, which was true
    /// only while Liquid was the only chain: `default_network: "bitcoin"` *is* mainnet and
    /// compared false, so a wallet created against a Bitcoin mainnet config was recorded
    /// as a testnet wallet. Errs toward `true` for an unparseable value, since treating an
    /// unknown network as a testnet is the dangerous direction.
    pub fn is_mainnet(&self) -> bool {
        match self.network() {
            Ok(n) => n.is_mainnet(),
            Err(_) => self.default_network != "testnet",
        }
    }

    /// Return the Esplora URL: explicit override > network-appropriate default.
    ///
    /// The default follows the configured network across both chains — Esplora serves
    /// Bitcoin and Liquid from the same REST shape at different base paths. A network this
    /// build does not recognize keeps the historical Liquid default rather than erroring,
    /// because this accessor has no way to report one and every config that reaches it
    /// today is an Elements config.
    pub fn esplora_url(&self) -> &str {
        if let Some(explicit) = self.default_esplora.as_deref() {
            return explicit;
        }
        match self.network() {
            Ok(net) => match net {
                Network::Liquid => "https://blockstream.info/liquid/api",
                Network::LiquidTestnet => "https://blockstream.info/liquidtestnet/api",
                // No public Elements or Bitcoin regtest instance exists, so there is
                // nothing honest to default to; the caller gets the testnet URL and will
                // fail loudly against it rather than being pointed somewhere plausible.
                Network::ElementsRegtest => "https://blockstream.info/liquidtestnet/api",
                // Regtest has no public instance, so there is nothing honest to default
                // to. A localhost URL fails to connect, which is the right failure; the
                // public signet that used to stand in here would have silently answered
                // questions about somebody else's chain.
                bitcoin_net => crate::bitcoin_backend::default_esplora_url(bitcoin_net)
                    .unwrap_or("http://127.0.0.1:3002"),
            },
            Err(_) => "https://blockstream.info/liquidtestnet/api",
        }
    }

    /// Resolve the configured backend kind (defaults to Esplora).
    pub fn backend_kind(&self) -> BackendKind {
        match self.default_backend.as_deref() {
            Some(s) => BackendKind::parse(s),
            None => BackendKind::Esplora,
        }
    }

    /// Electrum URL: explicit override > network-appropriate Blockstream default.
    pub fn electrum_url(&self) -> &str {
        self.default_electrum.as_deref().unwrap_or_else(|| {
            if self.is_mainnet() {
                "ssl://blockstream.info:995"
            } else {
                "ssl://blockstream.info:465"
            }
        })
    }

    /// Resolve the server URL for the active backend.
    pub fn backend_url(&self) -> &str {
        match self.backend_kind() {
            BackendKind::Electrum => self.electrum_url(),
            BackendKind::Esplora => self.esplora_url(),
        }
    }
}

impl Config {
    /// The configured network, or an error naming the accepted spellings.
    pub fn network(&self) -> Result<Network> {
        self.default_network
            .parse::<Network>()
            .map_err(|e| anyhow::anyhow!("{e} (in default_network)"))
    }

    /// What the configured target provides, for checking a manifest's `requires` against.
    ///
    /// Unparseable `extra_capabilities` entries are an error rather than a skip: an
    /// operator who misspells one is asserting a capability that then silently fails to
    /// satisfy anything, and the resulting message would blame the manifest.
    pub fn activation(&self, network: Network) -> Result<Activation> {
        let mut extensions = Capabilities::none();
        for raw in &self.extra_capabilities {
            let cap: Capability = raw
                .parse()
                .with_context(|| format!("bad entry in extra_capabilities: {raw:?}"))?;
            extensions.insert(cap);
        }
        Ok(Activation {
            simplicity: self
                .simplicity_activated
                .unwrap_or_else(|| Activation::default_for(network).simplicity),
            extensions,
        })
    }
}

impl Config {
    /// Connect to whichever Bitcoin backend this config selects.
    pub fn bitcoin_chain(&self, network: Network) -> Result<crate::bitcoin_backend::BitcoinChain> {
        use crate::bitcoin_backend::{BitcoinBackendKind, BitcoinChain, EsploraClient};
        use crate::bitcoin_rpc::RpcClient;

        let kind = self
            .bitcoin_backend
            .as_deref()
            .map_or(BitcoinBackendKind::Esplora, BitcoinBackendKind::parse);

        match kind {
            BitcoinBackendKind::Esplora => Ok(BitcoinChain::Esplora(EsploraClient::new(
                self.esplora_url(),
            ))),
            BitcoinBackendKind::Rpc => {
                let url = self.bitcoin_rpc_url.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "bitcoin_backend is \"rpc\" but bitcoin_rpc_url is not set; \
                         a node endpoint has no sensible default"
                    )
                })?;
                let client = match (&self.bitcoin_rpc_cookie, &self.bitcoin_rpc_auth) {
                    (Some(path), _) => RpcClient::with_cookie(url, std::path::Path::new(path))?,
                    (None, Some(auth)) => {
                        let (u, p) = auth.split_once(':').ok_or_else(|| {
                            anyhow::anyhow!("bitcoin_rpc_auth must be \"user:password\"")
                        })?;
                        RpcClient::new(url, Some((u.to_string(), p.to_string())))
                    }
                    // A node with no auth at all is unusual but legal, and refusing it here
                    // would block exactly the throwaway regtest this backend exists for.
                    (None, None) => RpcClient::new(url, None),
                };
                let _ = network;
                Ok(BitcoinChain::Rpc(client))
            }
        }
    }
}

/// An explicit config path, set once at startup by the CLI's `--config`.
///
/// Process-global rather than threaded through every call site: `load` is reached from a
/// dozen places, several of them deep inside the lifecycle, and none of them has anything
/// useful to say about where the config lives. A `OnceLock` also makes the override
/// single-assignment, so nothing can quietly repoint the config mid-run.
static CONFIG_PATH_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Point every later [`load`] and [`save`] at `path`.
///
/// Returns an error if a different path was already set, which can only happen by
/// programming mistake — but a config silently moving after something has read the old one
/// is the kind of mistake worth refusing rather than tolerating.
pub fn set_config_path(path: PathBuf) -> Result<()> {
    match CONFIG_PATH_OVERRIDE.set(path.clone()) {
        Ok(()) => Ok(()),
        Err(_) if CONFIG_PATH_OVERRIDE.get() == Some(&path) => Ok(()),
        Err(_) => anyhow::bail!(
            "config path already set to {}",
            CONFIG_PATH_OVERRIDE.get().map_or_else(String::new, |p| p.display().to_string())
        ),
    }
}

/// Where the config is read from and written to.
///
/// Precedence: an explicit `--config`, then [`crate::wallet::DATA_DIR_ENV`] via
/// [`default_data_dir`], then the platform data directory. Deliberately *not* the current
/// directory: a config that activates based on where you happen to be standing is how a
/// mainnet transaction gets broadcast from the wrong folder.
pub fn config_path() -> PathBuf {
    if let Some(explicit) = CONFIG_PATH_OVERRIDE.get() {
        return explicit.clone();
    }
    default_data_dir().join("config.json")
}

/// Load config from disk. Returns `Config::default()` if the file doesn't exist yet.
pub fn load() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save(config: &Config) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Cannot create config dir: {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, raw)
        .with_context(|| format!("Cannot write config: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(network: &str) -> Config {
        Config { default_network: network.to_string(), ..Config::default() }
    }

    /// A config file written before these fields existed must keep parsing, and must mean
    /// what it meant then: Liquid testnet, Simplicity live.
    #[test]
    fn a_pre_existing_config_keeps_its_meaning() {
        let old = r#"{"default_network": "testnet", "default_esplora": null}"#;
        let parsed: Config = serde_json::from_str(old).expect("old config still parses");
        let net = parsed.network().expect("testnet resolves");
        assert_eq!(net, Network::LiquidTestnet);
        assert!(parsed.activation(net).unwrap().simplicity);
    }

    /// Simplicity defaults off on Bitcoin and on for Elements, and an explicit setting wins
    /// only where it is meaningful.
    #[test]
    fn simplicity_activation_defaults_per_family() {
        let c = cfg("bitcoin-signet");
        let net = c.network().unwrap();
        assert!(!c.activation(net).unwrap().simplicity, "must default off on Bitcoin");

        let opted_in = Config { simplicity_activated: Some(true), ..cfg("bitcoin-signet") };
        assert!(opted_in.activation(net).unwrap().simplicity);

        // Elements has it live regardless, so the capability set carries it either way.
        let c = cfg("liquid");
        let net = c.network().unwrap();
        let off = Config { simplicity_activated: Some(false), ..cfg("liquid") };
        assert!(net
            .capabilities(&off.activation(net).unwrap())
            .contains(&Capability::SIMPLICITY));
        assert!(net.capabilities(&c.activation(net).unwrap()).contains(&Capability::SIMPLICITY));
    }

    #[test]
    fn extra_capabilities_are_parsed_and_asserted() {
        let c = Config {
            extra_capabilities: vec!["custom::my-feature".to_string()],
            ..cfg("bitcoin-signet")
        };
        let net = c.network().unwrap();
        let want = Capabilities::from_iter(["custom::my-feature".parse().unwrap()]);
        assert!(want.missing_from(&net.capabilities(&c.activation(net).unwrap())).is_empty());
    }

    /// A misspelled entry is an error, not a skip: it would otherwise satisfy nothing and
    /// the resulting failure would blame the manifest rather than the config.
    #[test]
    fn a_malformed_extra_capability_is_an_error() {
        let c = Config {
            extra_capabilities: vec!["not a capability".to_string()],
            ..cfg("liquid")
        };
        let err = c.activation(c.network().unwrap()).unwrap_err().to_string();
        assert!(err.contains("extra_capabilities"), "{err}");
    }

    /// The default must be the platform data directory, never the current one.
    ///
    /// A config that activates based on where you happen to be standing is how a mainnet
    /// transaction gets broadcast from the wrong folder, so `./config.json` is deliberately
    /// not consulted.
    #[test]
    fn the_default_config_path_is_not_the_current_directory() {
        // `set_config_path` is process-global and this test must not claim it, so this
        // checks the un-overridden shape rather than calling `config_path`.
        let default = crate::wallet::default_data_dir().join("config.json");
        assert_eq!(default.file_name().unwrap(), "config.json");
        assert!(
            default.parent().is_some_and(|p| p != std::path::Path::new("")),
            "the config must live under a data directory, not at a bare relative path"
        );
    }

    /// The Esplora default must follow the configured network across both chains, and an
    /// explicit override must always win — pointing a Bitcoin wallet at a Liquid instance
    /// would produce confusing decode failures rather than an obvious misconfiguration.
    #[test]
    fn esplora_defaults_follow_the_network() {
        assert_eq!(cfg("liquid").esplora_url(), "https://blockstream.info/liquid/api");
        assert_eq!(cfg("testnet").esplora_url(), "https://blockstream.info/liquidtestnet/api");
        assert_eq!(cfg("bitcoin").esplora_url(), "https://blockstream.info/api");
        assert_eq!(cfg("bitcoin-signet").esplora_url(), "https://blockstream.info/signet/api");
        assert_eq!(
            cfg("bitcoin-testnet").esplora_url(),
            "https://blockstream.info/testnet/api"
        );

        let overridden = Config {
            default_esplora: Some("http://localhost:3000".to_string()),
            ..cfg("bitcoin-signet")
        };
        assert_eq!(overridden.esplora_url(), "http://localhost:3000");
    }

    #[test]
    fn an_unknown_network_names_the_accepted_spellings() {
        let err = cfg("liquid-signet").network().unwrap_err().to_string();
        assert!(err.contains("default_network") && err.contains("bitcoin-signet"), "{err}");
    }
}
