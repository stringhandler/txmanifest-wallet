use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_network: "testnet".to_string(),
            default_esplora: None,
            default_backend: None,
            default_electrum: None,
        }
    }
}

impl Config {
    pub fn is_mainnet(&self) -> bool {
        self.default_network == "mainnet"
    }

    /// Return the Esplora URL: explicit override > network-appropriate default.
    pub fn esplora_url(&self) -> &str {
        self.default_esplora.as_deref().unwrap_or_else(|| {
            if self.is_mainnet() {
                "https://blockstream.info/liquid/api"
            } else {
                "https://blockstream.info/liquidtestnet/api"
            }
        })
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

pub fn config_path() -> PathBuf {
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
