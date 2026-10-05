//! The chain a run is on, chosen once.
//!
//! `lifecycle::run` used to carry an `Option<BitcoinRun>` and check it separately wherever
//! the chains differ — the run's network, the wallet's UTXOs, an outpoint's amount, the
//! assembly context, the fee estimator, the build. Every chain-specific bug the Bitcoin
//! work turned up lived in one of those checks: an input resolved to 0 sat because the
//! amount lookup asked the Elements backend, `fee` would not resolve because the estimator
//! asked an LWK wallet about a Bitcoin UTXO. A [`ChainSession`] is chosen once, at the top
//! of the run, and each of those questions is a method on it, so a new chain is one new
//! variant rather than another check at every site.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use console::style;
use lwk_wollet::{ElementsNetwork, Wollet};

use crate::assembly::{AssemblyContext, BitcoinContext, ElementsContext};
use crate::chain::{Capability, ChainFamily, Network};
use crate::manifest::Manifest;
use crate::pset_builder::{self, BuildPsetRequest};
use crate::target::Target;
use crate::wallet::{self, WalletFile};

/// What a Bitcoin run needs beyond the shared assembly: a wallet to sign with and a node
/// to broadcast to.
pub(crate) struct BitcoinRun {
    /// The Bitcoin network this run targets.
    ///
    /// Carried rather than derived from `network_for_asset`, which is an `ElementsNetwork`
    /// computed from the wallet file's mainnet flag and is meaningless here. Taking it from
    /// there would hand the covenant derivation the wrong chain.
    pub network: Network,
    pub wallet: crate::bitcoin_wallet::BitcoinWallet,
    /// Whichever backend the config selects — Esplora or a node's JSON-RPC.
    pub client: crate::bitcoin_backend::BitcoinChain,
    pub utxos: Vec<crate::bitcoin_backend::Utxo>,
    pub change_index: u32,
    pub receive_start: u32,
}

/// The chain a run is on, and whatever it needs to talk to it.
// One per run, so the size gap between the variants costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ChainSession {
    /// Elements. Chain access goes through the LWK wallet database the run opens later, so
    /// nothing is connected here. `network` is the wallet file's: on Elements it decides
    /// the LWK network, and through it the policy asset.
    Elements { network: Option<Network> },
    /// Bitcoin: connected, activation-checked and scanned.
    Bitcoin(BitcoinRun),
}

/// The per-chain [`AssemblyContext`], held so the trait object can borrow from it.
pub(crate) enum AssemblyCtx<'a> {
    Elements(ElementsContext<'a>),
    Bitcoin(BitcoinContext<'a>),
}

impl AssemblyCtx<'_> {
    pub(crate) fn as_dyn(&self) -> &dyn AssemblyContext {
        match self {
            AssemblyCtx::Elements(c) => c,
            AssemblyCtx::Bitcoin(c) => c,
        }
    }
}

impl ChainSession {
    /// Open the session for `manifest` on `target`.
    ///
    /// On Bitcoin this connects, confirms Simplicity when the manifest needs it, scans the
    /// wallet and picks the next unused addresses — all before input selection, which needs
    /// the scan. A missing wallet is fatal there: the Elements path can still do useful
    /// work without one (resolving, previewing), but a Bitcoin run that got this far has
    /// passed the capability gate and has nothing to fall back to.
    pub(crate) fn open(
        manifest: &Manifest,
        target: &Target,
        wallet: Option<&WalletFile>,
    ) -> Result<Self> {
        if manifest.chain_family() != ChainFamily::Bitcoin {
            return Ok(ChainSession::Elements {
                network: wallet.map(|w| Network::from(wallet::elements_network(w))),
            });
        }

        let w = wallet
            .ok_or_else(|| anyhow::anyhow!("no wallet loaded; a Bitcoin run needs one to sign"))?;
        let cfg = &target.config;
        let net = target.network;
        let btc_wallet = crate::bitcoin_wallet::BitcoinWallet::from_mnemonic(&w.mnemonic, net)?;
        let client = cfg.bitcoin_chain(net)?;
        // The capability gate believed the config; this asks the chain. Before the scan and
        // before any covenant address exists — see `confirm_simplicity` for why a wrong
        // belief here costs the coins rather than a broadcast.
        if manifest.requires.contains(&Capability::SIMPLICITY) {
            client.confirm_simplicity(net, cfg.bitcoin_checkpoint.is_some())?;
            println!("  {} Simplicity confirmed on {}", style("✓").green(), net);
        }

        println!("  {} Scanning {} for wallet UTXOs…", style("·").dim(), net);
        let utxos = client
            .scan(&btc_wallet, crate::bitcoin_backend::DEFAULT_GAP_LIMIT)
            .context("Cannot scan for wallet UTXOs")?;
        let total: u64 = utxos.iter().map(|u| u.value).sum();
        println!(
            "  {} {} UTXO(s), {} sat",
            style("✓").green(),
            utxos.len(),
            style(total).yellow()
        );

        // Change and receive both go to the first unused index on their branch, so a run
        // does not reuse an address that already has history.
        let (_, change_index) =
            client.next_unused(&btc_wallet, crate::bitcoin_wallet::Branch::Change)?;
        let (_, receive_start) =
            client.next_unused(&btc_wallet, crate::bitcoin_wallet::Branch::Receive)?;

        Ok(ChainSession::Bitcoin(BitcoinRun {
            network: net,
            wallet: btc_wallet,
            client,
            utxos,
            change_index,
            receive_start,
        }))
    }

    /// The network this run builds for, when it is known.
    ///
    /// Input selection derives both the asset it matches on and its address parser from
    /// this, so neither can drift from the other or from the UTXOs [`Self::spendable_utxos`]
    /// carries.
    pub(crate) fn network(&self) -> Option<Network> {
        match self {
            ChainSession::Elements { network } => *network,
            ChainSession::Bitcoin(r) => Some(r.network),
        }
    }

    /// The Bitcoin half, when this is a Bitcoin run.
    pub(crate) fn bitcoin(&self) -> Option<&BitcoinRun> {
        match self {
            ChainSession::Bitcoin(r) => Some(r),
            ChainSession::Elements { .. } => None,
        }
    }

    /// The wallet's UTXOs available for auto-selection, in the shape input selection takes.
    ///
    /// From the persisted LWK state on Elements, from the scan on Bitcoin — see
    /// `assembly::bitcoin_spendable_utxos` for what is real and what is synthesized there.
    pub(crate) fn spendable_utxos(
        &self,
        wallet: Option<&WalletFile>,
        data_dir: &Path,
    ) -> Result<Vec<lwk_wollet::WalletTxOut>> {
        match self {
            ChainSession::Bitcoin(r) => {
                // Immature coinbase outputs are filtered here rather than at the scan, so the
                // scan stays a faithful report of what the wallet holds and only *selection*
                // is restricted. A freshly mined coin is genuinely ours, and a balance that
                // omitted it would be wrong.
                let (spendable, immature): (Vec<_>, Vec<_>) =
                    r.utxos.iter().cloned().partition(|u| u.is_spendable());
                if !immature.is_empty() {
                    let held: u64 = immature.iter().map(|u| u.value).sum();
                    println!(
                        "  {} Ignoring {} immature coinbase output(s) holding {} sat — \
                         block rewards need {} confirmations before they can be spent.",
                        style("·").dim(),
                        immature.len(),
                        held,
                        crate::bitcoin_backend::COINBASE_MATURITY,
                    );
                }
                crate::assembly::bitcoin_spendable_utxos(&spendable)
            }
            ChainSession::Elements { .. } => Ok(match wallet {
                Some(w) if data_dir.exists() => wallet::utxos(w, data_dir).unwrap_or_default(),
                _ => vec![],
            }),
        }
    }

    /// The amount and asset of `txid:vout`, read from the chain.
    ///
    /// Best-effort by design: one network round-trip in the middle of input resolution,
    /// and a run that is offline, pointed at a lagging server, or spending a still
    /// unconfirmed output must keep working from the manifest's declared values. So a
    /// failure warns and returns `None` — but when the chain does answer, it wins over
    /// everything else, because it is the only source that cannot be wrong.
    ///
    /// Each chain through its own backend. The Elements backend knows nothing of a Bitcoin
    /// txid, and asking it was how a Bitcoin covenant input once resolved to 0 sat.
    pub(crate) fn txout(
        &self,
        target: &Target,
        wallet: Option<&WalletFile>,
        txid: &str,
        vout: u32,
    ) -> Option<(u64, String)> {
        match self {
            ChainSession::Bitcoin(r) => fetch_bitcoin_txout(&r.client, txid, vout),
            ChainSession::Elements { .. } => fetch_elements_txout(
                &target.config,
                txid,
                vout,
                wallet
                    .map(wallet::elements_network)
                    .unwrap_or(ElementsNetwork::LiquidTestnet),
            ),
        }
    }

    /// The chain-specific half of the shared assembly.
    ///
    /// `wollet` and `net` are the Elements wallet the run opened; the Bitcoin context does
    /// not consult them.
    pub(crate) fn assembly_context<'a>(
        &'a self,
        wollet: &'a Wollet,
        net: ElementsNetwork,
    ) -> AssemblyCtx<'a> {
        match self {
            ChainSession::Bitcoin(r) => AssemblyCtx::Bitcoin(BitcoinContext {
                wallet: &r.wallet,
                network: r.network,
                receive_start: r.receive_start,
                change_index: r.change_index,
                utxos: r.utxos.clone(),
            }),
            ChainSession::Elements { .. } => AssemblyCtx::Elements(ElementsContext {
                wollet,
                network: net,
            }),
        }
    }

    /// The network fee for `req`, estimated on the chain the transaction is for.
    ///
    /// This once called the Elements estimator unconditionally, which on a Bitcoin run asks
    /// an LWK wallet about a UTXO it has never heard of; the `fee` keyword then cannot
    /// resolve, and every output amount depending on it is wrong by exactly the fee.
    pub(crate) fn estimate_fee(
        &self,
        wollet: &Wollet,
        net: ElementsNetwork,
        req: &BuildPsetRequest,
    ) -> Result<u64> {
        match self {
            ChainSession::Bitcoin(r) => {
                let change = r
                    .wallet
                    .script_pubkey(crate::bitcoin_wallet::Branch::Change, r.change_index)?;
                let psbt_req = crate::psbt_builder::from_pset_request(req, Some(change))?;
                crate::psbt_builder::estimate_fee(&psbt_req)
            }
            ChainSession::Elements { .. } => pset_builder::estimate_fee(wollet, net, req),
        }
    }
}

/// An Elements outpoint's explicit amount and asset, through the configured Elements
/// backend. `None`, with a warning, when it is confidential or cannot be read.
fn fetch_elements_txout(
    cfg: &crate::config::Config,
    txid: &str,
    vout: u32,
    network: ElementsNetwork,
) -> Option<(u64, String)> {
    use crate::backend::{Backend, BackendKind};

    let parsed = lwk_wollet::elements::Txid::from_str(txid).ok()?;
    let kind = cfg.backend_kind();
    let url = match kind {
        BackendKind::Esplora => cfg.esplora_url().to_string(),
        BackendKind::Electrum => cfg.electrum_url().to_string(),
    };

    let result = Backend::connect(kind, &url, network)
        .and_then(|backend| backend.fetch_explicit_txout(parsed, vout));
    match result {
        Ok(Some((amount, asset))) => Some((amount, asset.to_string())),
        Ok(None) => {
            println!(
                "  {} {txid}:{vout} is confidential — falling back to the declared amount and asset.",
                style("[warn]").yellow()
            );
            None
        }
        Err(e) => {
            println!(
                "  {} Cannot read {txid}:{vout} from the chain ({e}) — falling back to the declared amount and asset.",
                style("[warn]").yellow()
            );
            None
        }
    }
}

/// A Bitcoin outpoint's amount through the run's backend, paired with the asset id Bitcoin
/// amounts carry in the shared assembly.
fn fetch_bitcoin_txout(
    client: &crate::bitcoin_backend::BitcoinChain,
    txid: &str,
    vout: u32,
) -> Option<(u64, String)> {
    let asset = crate::assembly::bitcoin_policy_asset().to_string();
    let result = txid
        .parse()
        .map_err(|e| anyhow::anyhow!("bad txid: {e}"))
        .and_then(|txid| client.txout(lwk_wollet::elements::bitcoin::OutPoint { txid, vout }));
    match result {
        Ok(Some(out)) => Some((out.value.to_sat(), asset)),
        Ok(None) => {
            println!(
                "  {} {txid}:{vout} is not on chain, or already spent — falling back to the declared amount.",
                style("[warn]").yellow()
            );
            None
        }
        Err(e) => {
            println!(
                "  {} Cannot read {txid}:{vout} from the chain ({e:#}) — falling back to the declared amount.",
                style("[warn]").yellow()
            );
            None
        }
    }
}
