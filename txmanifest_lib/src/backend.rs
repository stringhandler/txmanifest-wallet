//! Blockchain backend abstraction.
//!
//! The wallet can talk to the chain through either an Esplora HTTP server or an
//! Electrum server. `lwk_wollet`'s `BlockchainBackend` trait has generic methods
//! (`full_scan<S: WolletState>`), so it is **not** object-safe and cannot be used
//! as `Box<dyn BlockchainBackend>`. Instead we wrap the two concrete clients in an
//! enum and delegate, which keeps a single connection type at every call site.

use anyhow::{anyhow, Result};
use lwk_wollet::blocking::BlockchainBackend;
use lwk_wollet::elements::confidential::{Asset, Value};
use lwk_wollet::elements::{AssetId, Transaction, Txid};
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

    /// Read one on-chain output's explicit amount and asset.
    ///
    /// Returns `None` when the output is **confidential**: its value and asset are
    /// commitments, and unblinding them needs a key this engine does not hold for a
    /// covenant UTXO. Covenant outputs are explicit by construction (that is what lets a
    /// Simplicity program introspect them), so in practice this resolves.
    ///
    /// The alternative — trusting the manifest or a `--input` flag for the amount — means
    /// the value the sighash commits to is whatever an operator typed, and a mistyped one
    /// produces a signature that is simply invalid against the real UTXO.
    pub fn fetch_explicit_txout(&self, txid: Txid, vout: u32) -> Result<Option<(u64, AssetId)>> {
        let txs = match self {
            Backend::Esplora(c) => c.get_transactions(&[txid]),
            Backend::Electrum(c) => c.get_transactions(&[txid]),
        }
        .map_err(|e| anyhow!("Cannot fetch transaction {txid}: {e}"))?;

        let tx = txs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Transaction {txid} not found on chain"))?;
        let out = tx
            .output
            .get(vout as usize)
            .ok_or_else(|| anyhow!("{txid} has no output at index {vout}"))?;

        Ok(match (out.value, out.asset) {
            (Value::Explicit(value), Asset::Explicit(asset)) => Some((value, asset)),
            _ => None,
        })
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
