//! What a run targets — the network, and the config that reaches it — resolved once, and
//! checked for agreement, before anything reads either.
//!
//! This used to live in the CLI, behind two process-global `OnceLock`s that changed what a
//! no-argument `config::load()` returned. The checks therefore held only for code reached
//! through `main`: a library caller of `lifecycle::run` got no wallet/config agreement
//! check at all, the network came from `network.unwrap_or(cfg.default_network)` rather
//! than from the wallet, and one process could not serve two wallets. A `Target` is a value
//! instead, made by [`Target::bind`] and passed to whatever needs it.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::chain::Network;
use crate::config::{Config, LoadedConfig};
use crate::wallet::WalletFile;

/// The network a run targets and the config that reaches it, already checked against each
/// other and against the wallet.
#[derive(Debug)]
pub struct Target {
    pub network: Network,
    /// The network as the user wrote it, for `<stem>.<network>.json` params discovery.
    ///
    /// Not the canonical name: a wallet or flag saying `testnet` keeps looking for
    /// `txmanifest.testnet.json`, as it did before canonical names existed, rather than
    /// silently switching to `txmanifest.liquid-testnet.json` and finding nothing.
    pub network_label: String,
    /// The config, with `default_network` set to [`Target::network`].
    pub config: Config,
    /// The file the config came from; `None` when there was none.
    pub config_path: Option<PathBuf>,
}

impl Target {
    /// Bind a run to its network.
    ///
    /// The wallet decides, when there is one: its keys and addresses were made for one
    /// network, and it is the only input that cannot be wrong about it. A config or a
    /// `--network` naming a *different* network is then an error rather than an override —
    /// a config's URLs, checkpoint and activation claim were written for the network it
    /// names, and carrying them onto another would be wrong in ways nothing downstream
    /// detects. Without a wallet, `--network` wins, then the config's own network, then the
    /// legacy default.
    ///
    /// `wallet` pairs the file with its path, for messages.
    pub fn bind(
        loaded: LoadedConfig,
        wallet: Option<(&Path, &WalletFile)>,
        network_flag: Option<&str>,
    ) -> Result<Target> {
        let LoadedConfig { mut config, declared_network, path } = loaded;
        let flag_network: Option<Network> = network_flag
            .map(|f| f.parse().map_err(|e| anyhow::anyhow!("{e} (in --network)")))
            .transpose()?;

        let (network, network_label) = match wallet.and_then(|(p, w)| w.network().map(|n| (p, w, n)))
        {
            Some((wallet_path, wallet_file, wallet_net)) => {
                if let Some(config_net) = declared_network.filter(|n| *n != wallet_net) {
                    anyhow::bail!(
                        "{} is a {wallet_net} wallet, but the config at {} is for {config_net}; \
                         pass --config with a {wallet_net} config, or put one beside the wallet",
                        wallet_path.display(),
                        path.as_deref().map_or_else(|| "(defaults)".into(), |p| p.display().to_string()),
                    );
                }
                if let (Some(flag), Some(flag_net)) = (network_flag, flag_network) {
                    if flag_net != wallet_net {
                        anyhow::bail!(
                            "--network {flag} does not match {}, which is a {wallet_net} wallet",
                            wallet_path.display()
                        );
                    }
                }
                let label = network_flag.unwrap_or(&wallet_file.network).to_string();
                (wallet_net, label)
            }
            // No wallet, or one naming a network this build does not know — which gives
            // nothing to bind to; `WalletFile::is_mainnet` already treats such a wallet as the
            // dangerous case.
            None => {
                let network = match flag_network.or(declared_network) {
                    Some(n) => n,
                    None => config.network()?,
                };
                let label = network_flag.unwrap_or(&config.default_network).to_string();
                (network, label)
            }
        };

        config.default_network = network.to_string();
        Ok(Target { network, network_label, config, config_path: path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(network: &str) -> WalletFile {
        WalletFile { network: network.to_string(), mnemonic: String::new() }
    }

    fn loaded(declared: Option<Network>) -> LoadedConfig {
        LoadedConfig {
            config: Config::default(),
            declared_network: declared,
            path: Some(PathBuf::from("/cfg/config.json")),
        }
    }

    fn path() -> &'static Path {
        Path::new("/w/wallet.json")
    }

    /// A config that says nothing about networks takes the wallet's.
    #[test]
    fn the_wallet_decides_the_network() {
        let w = wallet("bitcoin-signet");
        let t = Target::bind(loaded(None), Some((path(), &w)), None).unwrap();
        assert_eq!(t.network, Network::BitcoinSignet);
        assert_eq!(t.config.default_network, "bitcoin-signet");
    }

    /// The bug this exists for: a signet wallet beside a Liquid testnet config.
    #[test]
    fn a_config_for_another_network_is_refused() {
        let w = wallet("bitcoin-signet");
        let err = Target::bind(loaded(Some(Network::LiquidTestnet)), Some((path(), &w)), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bitcoin-signet wallet") && err.contains("liquid-testnet"), "{err}");
    }

    #[test]
    fn a_network_flag_for_another_network_is_refused() {
        let w = wallet("bitcoin-signet");
        let err = Target::bind(loaded(None), Some((path(), &w)), Some("bitcoin-regtest"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--network bitcoin-regtest"), "{err}");
        // The same network under another spelling agrees.
        assert!(Target::bind(loaded(None), Some((path(), &w)), Some("signet")).is_ok());
    }

    /// Params discovery keeps the spelling it was given, so `txmanifest.testnet.json`
    /// still loads for a wallet that says `testnet`.
    #[test]
    fn the_network_label_keeps_the_given_spelling() {
        let w = wallet("testnet");
        let t = Target::bind(loaded(Some(Network::LiquidTestnet)), Some((path(), &w)), None)
            .unwrap();
        assert_eq!(t.network, Network::LiquidTestnet);
        assert_eq!(t.network_label, "testnet");
    }

    /// Without a wallet: the flag, then the config, then the legacy default.
    #[test]
    fn without_a_wallet_the_flag_then_the_config_decide() {
        let t = Target::bind(loaded(Some(Network::BitcoinRegtest)), None, Some("signet")).unwrap();
        assert_eq!(t.network, Network::BitcoinSignet);
        let t = Target::bind(loaded(Some(Network::BitcoinRegtest)), None, None).unwrap();
        assert_eq!(t.network, Network::BitcoinRegtest);
        let t = Target::bind(loaded(None), None, None).unwrap();
        assert_eq!(t.network, Network::LiquidTestnet);
    }

    /// Two targets in one process — impossible with the old process-global binding.
    #[test]
    fn two_wallets_can_be_bound_in_one_process() {
        let a = wallet("bitcoin-signet");
        let b = wallet("liquid");
        let ta = Target::bind(loaded(None), Some((path(), &a)), None).unwrap();
        let tb = Target::bind(loaded(None), Some((path(), &b)), None).unwrap();
        assert_eq!((ta.network, tb.network), (Network::BitcoinSignet, Network::Liquid));
    }
}
