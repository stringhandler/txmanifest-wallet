use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::bitcoin_backend::Checkpoint;
use crate::chain::{Activation, Capabilities, Capability, Network};
use crate::wallet::default_data_dir;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// The network to target when no wallet says otherwise — any name [`Network`] parses.
    ///
    /// A loaded wallet's own network takes precedence (see [`set_wallet_network`]), so this
    /// matters mainly to `create-wallet`. May be omitted, which makes the file purely
    /// backend settings for whichever wallet it sits beside; it then reads as `testnet`.
    #[serde(default = "legacy_default_network")]
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
    /// A block the Bitcoin chain must contain, checked each time a backend connects.
    ///
    /// The only setting that tells one signet from another: they share a genesis block,
    /// a name and an address encoding. Without it a wrong URL is found out — if at all —
    /// when the coins are not there.
    #[serde(default)]
    pub bitcoin_checkpoint: Option<Checkpoint>,
}

fn legacy_default_network() -> String {
    "testnet".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_network: legacy_default_network(),
            default_esplora: None,
            default_backend: None,
            default_electrum: None,
            simplicity_activated: None,
            extra_capabilities: Vec::new(),
            bitcoin_backend: None,
            bitcoin_rpc_url: None,
            bitcoin_rpc_cookie: None,
            bitcoin_rpc_auth: None,
            bitcoin_checkpoint: None,
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
    /// Connect to whichever Bitcoin backend this config selects, and confirm it is on the
    /// chain the config means.
    pub fn bitcoin_chain(&self, network: Network) -> Result<crate::bitcoin_backend::BitcoinChain> {
        use crate::bitcoin_backend::BitcoinBackendKind;

        let kind = self
            .bitcoin_backend
            .as_deref()
            .map_or(BitcoinBackendKind::Esplora, BitcoinBackendKind::parse);

        // A signet with Simplicity is a specific signet, and the Esplora default is not it:
        // it is the default signet, which has not activated the soft fork. So a config that
        // opts in and leaves the URL to the default has forgotten the line naming its chain
        // — and has likely forgotten a checkpoint too, which is why this is checked here
        // rather than left to one.
        if network == Network::BitcoinSignet
            && kind == BitcoinBackendKind::Esplora
            && self.default_esplora.is_none()
            && self.activation(network)?.simplicity
        {
            anyhow::bail!(
                "simplicity_activated is set for bitcoin-signet but default_esplora is not, so \
                 this would use the default signet ({}), which has not activated Simplicity; \
                 set default_esplora to the signet that has",
                self.esplora_url()
            );
        }

        let chain = self.connect_bitcoin(kind, network)?;
        if let Some(checkpoint) = &self.bitcoin_checkpoint {
            chain
                .verify_checkpoint(checkpoint)
                .with_context(|| format!("bitcoin_checkpoint does not hold on {chain:?}"))?;
        }
        Ok(chain)
    }

    fn connect_bitcoin(
        &self,
        kind: crate::bitcoin_backend::BitcoinBackendKind,
        network: Network,
    ) -> Result<crate::bitcoin_backend::BitcoinChain> {
        use crate::bitcoin_backend::{BitcoinBackendKind, BitcoinChain, EsploraClient};
        use crate::bitcoin_rpc::RpcClient;

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
                        RpcClient::new(url, Some((u.to_string(), p.to_string())))?
                    }
                    // A node with no auth at all is unusual but legal, and refusing it here
                    // would block exactly the throwaway regtest this backend exists for.
                    (None, None) => RpcClient::new(url, None)?,
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

/// The `config.json` beside a wallet file, if there is one.
///
/// Beside the *wallet*, not in the current directory. The objection to reading a config from
/// wherever you happen to stand is that the chain then depends on your shell; a config
/// that travels with one wallet file is bound to that wallet instead, and the wallet's
/// network is checked against it regardless (see [`declared_network`]). Only offered for
/// a wallet that exists, so a mistyped `--wallet` cannot pick up a stray config.
pub fn config_beside(wallet_path: &std::path::Path) -> Option<PathBuf> {
    if !wallet_path.is_file() {
        return None;
    }
    config_in_dir_of(wallet_path)
}

/// The `config.json` in the directory a wallet file is, or is about to be, written to.
///
/// [`config_beside`] without the existence check, for `create-wallet`: writing a config
/// into a fresh directory and then creating the wallet there is how a wallet gets made for
/// the chain that config names.
pub fn config_in_dir_of(wallet_path: &std::path::Path) -> Option<PathBuf> {
    let dir = match wallet_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let candidate = dir.join("config.json");
    (candidate.is_file() && candidate != wallet_path).then_some(candidate)
}

/// The network the config file names explicitly, if any.
///
/// Read from the raw file, because [`Config`] fills an absent `default_network` with a
/// legacy default, and a config that never mentioned a network must not be reported as
/// disagreeing with the wallet. Unlike [`load`], a file that is present but malformed is an
/// error: this runs once at startup, and it is the one chance to say so before every later
/// load quietly substitutes the defaults.
pub fn declared_network() -> Result<Option<Network>> {
    declared_network_at(&config_path())
}

fn declared_network_at(path: &std::path::Path) -> Result<Option<Network>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read config: {}", path.display()))?;
    serde_json::from_str::<Config>(&raw)
        .with_context(|| format!("Cannot parse config: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    match value.get("default_network").and_then(serde_json::Value::as_str) {
        None => Ok(None),
        Some(name) => name
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("{e} (in default_network of {})", path.display())),
    }
}

/// The network of the wallet this process is operating, set once at startup.
///
/// Process-global for the same reason [`CONFIG_PATH_OVERRIDE`] is: `load` has a dozen
/// callers and no arguments. The wallet decides the chain because it is the one thing that
/// cannot be wrong about it — its keys and addresses were made for that network — while a
/// config is just settings, and may have been written for another wallet entirely.
static WALLET_NETWORK: std::sync::OnceLock<Network> = std::sync::OnceLock::new();

/// Make `network` the target of every later [`load`], whatever the file's `default_network`.
///
/// Callers check first that the config does not name a *different* network
/// ([`declared_network`]): its URLs, checkpoint and activation were written for that one,
/// and carrying them onto this network would be wrong in ways nothing downstream detects.
pub fn set_wallet_network(network: Network) -> Result<()> {
    match WALLET_NETWORK.set(network) {
        Ok(()) => Ok(()),
        Err(_) if WALLET_NETWORK.get() == Some(&network) => Ok(()),
        Err(_) => anyhow::bail!(
            "wallet network already set to {}",
            WALLET_NETWORK.get().map_or_else(String::new, ToString::to_string)
        ),
    }
}

/// Load config from disk. Returns `Config::default()` if the file doesn't exist yet.
///
/// When a wallet has been bound with [`set_wallet_network`], its network replaces
/// `default_network`.
pub fn load() -> Config {
    let path = config_path();
    let mut cfg = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    } else {
        Config::default()
    };
    if let Some(net) = WALLET_NETWORK.get() {
        cfg.default_network = net.to_string();
    }
    cfg
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

    /// Opting into Simplicity on signet while leaving the URL to the default would aim the
    /// wallet at a chain that cannot run its covenants. Every case here is refused or passed
    /// before any connection is made, so none of them touches the network.
    #[test]
    fn simplicity_on_the_default_signet_is_refused() {
        let opted_in = Config { simplicity_activated: Some(true), ..cfg("bitcoin-signet") };
        let err = opted_in.bitcoin_chain(Network::BitcoinSignet).unwrap_err().to_string();
        assert!(err.contains("default_esplora") && err.contains("blockstream.info/signet"), "{err}");

        // Naming the chain, or not claiming Simplicity, or using a node: all fine.
        let named = Config {
            default_esplora: Some("https://signet.example.invalid/api".to_string()),
            ..opted_in
        };
        assert!(named.bitcoin_chain(Network::BitcoinSignet).is_ok());
        assert!(cfg("bitcoin-signet").bitcoin_chain(Network::BitcoinSignet).is_ok());
        let node = Config {
            simplicity_activated: Some(true),
            bitcoin_backend: Some("rpc".to_string()),
            bitcoin_rpc_url: Some("http://127.0.0.1:38332".to_string()),
            ..cfg("bitcoin-signet")
        };
        assert!(node.bitcoin_chain(Network::BitcoinSignet).is_ok());
    }

    #[test]
    fn a_checkpoint_is_read_from_the_config_file() {
        let raw = r#"{"default_network": "bitcoin-signet", "default_esplora": null,
                      "bitcoin_checkpoint": {"height": 1296, "hash": "00ab"}}"#;
        let parsed: Config = serde_json::from_str(raw).expect("parses");
        let cp = parsed.bitcoin_checkpoint.expect("present");
        assert_eq!((cp.height, cp.hash.as_str()), (1296, "00ab"));
    }

    /// A fresh directory under the system temp dir, unique to one test.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("txm-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_config_is_found_beside_an_existing_wallet_only() {
        let dir = scratch_dir("beside");
        let wallet = dir.join("wallet.json");
        let config = dir.join("config.json");
        std::fs::write(&config, "{}").unwrap();

        // No wallet yet: `config_beside` declines, `config_in_dir_of` (create-wallet) does not.
        assert_eq!(config_beside(&wallet), None);
        assert_eq!(config_in_dir_of(&wallet), Some(config.clone()));

        std::fs::write(&wallet, "{}").unwrap();
        assert_eq!(config_beside(&wallet), Some(config.clone()));

        std::fs::remove_file(&config).unwrap();
        assert_eq!(config_beside(&wallet), None);
    }

    /// Only an explicit `default_network` is a declaration. The legacy default that fills
    /// an absent one would otherwise read as "testnet" and refuse every non-Liquid wallet.
    #[test]
    fn only_an_explicit_network_is_declared() {
        let dir = scratch_dir("declared");
        let path = dir.join("config.json");

        assert_eq!(declared_network_at(&path).unwrap(), None, "no file");

        std::fs::write(&path, r#"{"default_esplora": "https://example.invalid/api"}"#).unwrap();
        assert_eq!(declared_network_at(&path).unwrap(), None, "backend settings only");

        std::fs::write(&path, r#"{"default_network": "signet"}"#).unwrap();
        assert_eq!(declared_network_at(&path).unwrap(), Some(Network::BitcoinSignet));

        std::fs::write(&path, r#"{"default_network": "liquid-signet"}"#).unwrap();
        let err = declared_network_at(&path).unwrap_err().to_string();
        assert!(err.contains("default_network"), "{err}");
    }

    /// `load` substitutes defaults for a file it cannot parse; this is where that is caught.
    #[test]
    fn a_malformed_config_is_an_error_not_the_defaults() {
        let dir = scratch_dir("malformed");
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"default_network": "bitcoin-signet",
                "bitcoin_checkpoint": {"height": "1296", "hash": "00"}}"#,
        )
        .unwrap();
        let err = format!("{:#}", declared_network_at(&path).unwrap_err());
        assert!(err.contains("Cannot parse config"), "{err}");
    }

    #[test]
    fn an_unknown_network_names_the_accepted_spellings() {
        let err = cfg("liquid-signet").network().unwrap_err().to_string();
        assert!(err.contains("default_network") && err.contains("bitcoin-signet"), "{err}");
    }
}
