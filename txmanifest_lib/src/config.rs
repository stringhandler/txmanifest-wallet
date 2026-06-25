use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::wallet::default_data_dir;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// "testnet" or "mainnet"
    pub default_network: String,
    /// Override Esplora URL. If None, a sensible default is chosen from `default_network`.
    pub default_esplora: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_network: "testnet".to_string(),
            default_esplora: None,
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
