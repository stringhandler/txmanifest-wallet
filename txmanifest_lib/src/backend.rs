//! Blockchain backend abstraction.
//!
//! The wallet can talk to the chain through either an Esplora HTTP server or an
//! Electrum server. `lwk_wollet`'s `BlockchainBackend` trait has generic methods
//! (`full_scan<S: WolletState>`), so it is **not** object-safe and cannot be used
//! as `Box<dyn BlockchainBackend>`. Instead we wrap the two concrete clients in an
//! enum and delegate, which keeps a single connection type at every call site.

use anyhow::{anyhow, Result};
use lwk_wollet::blocking::BlockchainBackend;
use lwk_wollet::elements::{Transaction, Txid};
use lwk_wollet::{blocking, ElectrumClient, ElectrumUrl, ElementsNetwork, Update, Wollet};

/// Which chain backend to connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Esplora,
    Electrum,
}

impl BackendKind {
    /// Parse a config string. Anything other than `electrum` resolves to Esplora,
    /// so the default (and any legacy/empty value) stays on the existing backend.
    pub fn parse(s: &str) -> BackendKind {
        match s.trim().to_ascii_lowercase().as_str() {
            "electrum" => BackendKind::Electrum,
            _ => BackendKind::Esplora,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Esplora => "esplora",
            BackendKind::Electrum => "electrum",
        }
    }
}

/// A connected blockchain backend — either Esplora (HTTP) or Electrum (TCP/TLS).
pub enum Backend {
    Esplora(blocking::EsploraClient),
    Electrum(ElectrumClient),
}

impl Backend {
    /// Connect to `url` using the requested backend kind.
    ///
    /// Esplora URLs are plain HTTP(S) endpoints (`https://host/api`). Electrum URLs
    /// use a scheme prefix understood by [`ElectrumUrl`]: `ssl://host:port` (TLS),
    /// `tcp://host:port` (plaintext), or a bare `host:port` (TLS assumed).
    pub fn connect(kind: BackendKind, url: &str, network: ElementsNetwork) -> Result<Self> {
        match kind {
            BackendKind::Esplora => {
                let client = blocking::EsploraClient::new(url, network)
                    .map_err(|e| anyhow!("Failed to connect to Esplora at '{url}': {e}"))?;
                Ok(Backend::Esplora(client))
            }
            BackendKind::Electrum => {
                let electrum_url: ElectrumUrl = url
                    .parse()
                    .map_err(|e| anyhow!("Invalid Electrum URL '{url}': {e}"))?;
                let client = ElectrumClient::new(&electrum_url)
                    .map_err(|e| anyhow!("Failed to connect to Electrum at '{url}': {e}"))?;
                Ok(Backend::Electrum(client))
            }
        }
    }

    /// Full chain scan for the given wallet.
    pub fn full_scan(&mut self, wollet: &Wollet) -> Result<Option<Update>> {
        match self {
            Backend::Esplora(c) => c.full_scan(wollet),
            Backend::Electrum(c) => c.full_scan(wollet),
        }
        .map_err(|e| anyhow!("Sync failed: {e}"))
    }

    /// Broadcast a finalized transaction, returning its txid.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        match self {
            Backend::Esplora(c) => c.broadcast(tx),
            Backend::Electrum(c) => c.broadcast(tx),
        }
        .map_err(|e| anyhow!("Broadcast failed: {e}"))
    }
}
