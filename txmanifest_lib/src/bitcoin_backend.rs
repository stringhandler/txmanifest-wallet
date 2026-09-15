//! Bitcoin chain access over Esplora — the counterpart to [`crate::backend`].
//!
//! Esplora serves Bitcoin and Liquid from the same REST shape, so the API knowledge
//! carries over even though the client does not: `lwk_wollet`'s `EsploraClient` decodes
//! Elements transactions, whose outputs carry asset ids and commitments that no Bitcoin
//! response has. Only the base URL differs between the two — `/api` versus `/liquid/api`.
//!
//! Built on `ureq`, which this crate already uses to POST transactions, rather than on a
//! wallet framework's client. The surface needed here is four endpoints.
//!
//! # Parsing is separated from fetching
//!
//! Every response is decoded by a free function taking `&str`, with the HTTP call kept
//! separate. That is deliberate: the network calls cannot be exercised in a unit test, and
//! the decoding is where the mistakes actually live — a satoshi amount read as a float, a
//! txid byte order flipped, a missing field defaulted to zero. Splitting them means the
//! risky half is tested against captured responses and the untested half is a URL and a
//! `GET`.

use std::collections::HashMap;

use anyhow::{Context, Result};
use lwk_wollet::elements::bitcoin::{
    consensus::encode::{deserialize, serialize_hex},
    Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use serde::Deserialize;

use crate::bitcoin_wallet::{BitcoinWallet, Branch};
use crate::chain::Network;

/// How many consecutive unused addresses end a scan.
///
/// The BIP44 standard value. Raising it costs one request per extra address; lowering it
/// risks missing funds sent to an address past the gap, which is unrecoverable by scanning
/// alone.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// Esplora's default base URLs, per network.
///
/// `None` for regtest: there is no public instance, so the operator must configure one
/// rather than be silently pointed at somebody else's chain.
pub fn default_esplora_url(network: Network) -> Option<&'static str> {
    match network {
        Network::Bitcoin => Some("https://blockstream.info/api"),
        Network::BitcoinTestnet => Some("https://blockstream.info/testnet/api"),
        Network::BitcoinSignet => Some("https://blockstream.info/signet/api"),
        Network::BitcoinRegtest => None,
        // Elements networks are served by `crate::backend`; their URLs live in `config`.
        _ => None,
    }
}

/// One unspent output belonging to the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    /// The scriptPubKey paying this output.
    ///
    /// Filled in from the address that was queried rather than read from the response —
    /// Esplora's UTXO listing omits it, and it is not optional downstream: a taproot
    /// sighash commits to it, so a spend built without it is unsignable.
    pub script_pubkey: ScriptBuf,
    /// Which branch and index derived this output's key, so a signer can find it again.
    pub branch: Branch,
    pub index: u32,
    /// Block height, or `None` while unconfirmed.
    pub height: Option<u32>,
}

impl Utxo {
    pub fn txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.value),
            script_pubkey: self.script_pubkey.clone(),
        }
    }

    pub fn is_confirmed(&self) -> bool {
        self.height.is_some()
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WireStatus {
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct WireUtxo {
    txid: String,
    vout: u32,
    /// Satoshis. Esplora sends an integer here; `u64` rather than `f64` so a value that
    /// somehow arrives as a float is a parse error rather than a silently rounded amount.
    value: u64,
    status: WireStatus,
}

#[derive(Debug, Deserialize)]
struct WireStats {
    #[serde(default)]
    tx_count: u64,
}

#[derive(Debug, Deserialize)]
struct WireAddress {
    #[serde(default)]
    chain_stats: Option<WireStats>,
    #[serde(default)]
    mempool_stats: Option<WireStats>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Decode `GET /address/{addr}/utxo`.
///
/// `script_pubkey`, `branch` and `index` come from the caller, because the response
/// describes outputs without saying whose they are — the request already settled that.
fn parse_utxos(body: &str, script_pubkey: &ScriptBuf, branch: Branch, index: u32) -> Result<Vec<Utxo>> {
    let wire: Vec<WireUtxo> =
        serde_json::from_str(body).context("cannot decode Esplora UTXO listing")?;
    wire.into_iter()
        .map(|u| {
            // Esplora prints txids in the reversed (display) order that `Txid`'s FromStr
            // expects, so parsing the string is correct where reading raw bytes would not
            // be.
            let txid: Txid = u.txid.parse().with_context(|| format!("bad txid {:?}", u.txid))?;
            Ok(Utxo {
                outpoint: OutPoint { txid, vout: u.vout },
                value: u.value,
                script_pubkey: script_pubkey.clone(),
                branch,
                index,
                height: if u.status.confirmed { u.status.block_height } else { None },
            })
        })
        .collect()
}

/// Decode `GET /address/{addr}`, returning whether the address has ever been used.
///
/// Mempool activity counts. An address with an unconfirmed payment is used, and treating
/// it as free would hand it out again and merge two payments into one address.
fn parse_address_used(body: &str) -> Result<bool> {
    let wire: WireAddress =
        serde_json::from_str(body).context("cannot decode Esplora address stats")?;
    let chain = wire.chain_stats.map_or(0, |s| s.tx_count);
    let mempool = wire.mempool_stats.map_or(0, |s| s.tx_count);
    Ok(chain + mempool > 0)
}

/// Decode `GET /blocks/tip/height`, which is a bare number in the body.
fn parse_tip_height(body: &str) -> Result<u32> {
    body.trim()
        .parse()
        .with_context(|| format!("cannot decode tip height from {:?}", body.trim()))
}

/// Decode `GET /fee-estimates`: `{"<target blocks>": <sat/vB>, ...}`.
///
/// Returns the estimate for the smallest target at or above `target_blocks`. Esplora does
/// not promise every target is present, so picking the nearest available one above the
/// request errs toward confirming sooner rather than failing.
fn parse_fee_estimate(body: &str, target_blocks: u16) -> Result<Option<f32>> {
    let map: HashMap<String, f64> =
        serde_json::from_str(body).context("cannot decode Esplora fee estimates")?;
    let mut best: Option<(u16, f64)> = None;
    for (k, v) in map {
        let Ok(blocks) = k.parse::<u16>() else { continue };
        if blocks < target_blocks {
            continue;
        }
        if best.is_none_or(|(b, _)| blocks < b) {
            best = Some((blocks, v));
        }
    }
    Ok(best.map(|(_, rate)| rate as f32))
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A blocking Esplora client for Bitcoin.
pub struct EsploraClient {
    base_url: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for EsploraClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsploraClient").field("base_url", &self.base_url).finish()
    }
}

impl EsploraClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new().build(),
        }
    }

    /// The client for `network`'s default Esplora instance.
    pub fn for_network(network: Network) -> Result<Self> {
        let url = default_esplora_url(network).ok_or_else(|| {
            anyhow::anyhow!(
                "no default Esplora instance for '{network}'; set one in the wallet config"
            )
        })?;
        Ok(Self::new(url))
    }

    fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        match self.agent.get(&url).call() {
            Ok(resp) => resp
                .into_string()
                .with_context(|| format!("cannot read response body from {url}")),
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                anyhow::bail!("GET {url} failed with HTTP {status}: {}", body.trim())
            }
            Err(e) => anyhow::bail!("GET {url} failed: {e}"),
        }
    }

    /// Unspent outputs paying `address`.
    pub fn utxos(&self, address: &Address, branch: Branch, index: u32) -> Result<Vec<Utxo>> {
        let body = self.get(&format!("address/{address}/utxo"))?;
        parse_utxos(&body, &address.script_pubkey(), branch, index)
    }

    /// Whether `address` has any transaction history, confirmed or in the mempool.
    pub fn address_used(&self, address: &Address) -> Result<bool> {
        parse_address_used(&self.get(&format!("address/{address}"))?)
    }

    pub fn tip_height(&self) -> Result<u32> {
        parse_tip_height(&self.get("blocks/tip/height")?)
    }

    /// Fee rate in sat/vB for confirmation within `target_blocks`, if Esplora offers one.
    pub fn fee_estimate(&self, target_blocks: u16) -> Result<Option<f32>> {
        parse_fee_estimate(&self.get("fee-estimates")?, target_blocks)
    }

    /// Fetch a whole transaction.
    pub fn transaction(&self, txid: Txid) -> Result<Transaction> {
        let hex = self.get(&format!("tx/{txid}/hex"))?;
        let bytes = hex_to_bytes(hex.trim())
            .with_context(|| format!("Esplora returned non-hex for tx {txid}"))?;
        deserialize(&bytes).with_context(|| format!("cannot decode transaction {txid}"))
    }

    /// One output of an on-chain transaction.
    ///
    /// `None` when the transaction exists but has no such output, which is a caller error
    /// rather than a network condition and so is distinguished from a failure.
    pub fn txout(&self, outpoint: OutPoint) -> Result<Option<TxOut>> {
        let tx = self.transaction(outpoint.txid)?;
        Ok(tx.output.get(outpoint.vout as usize).cloned())
    }

    /// Broadcast a signed transaction, returning its txid.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let url = format!("{}/tx", self.base_url);
        let hex = serialize_hex(tx);
        let resp = match self.agent.post(&url).set("Content-Type", "text/plain").send_string(&hex) {
            Ok(r) => r.into_string().unwrap_or_default(),
            Err(ureq::Error::Status(status, r)) => {
                let body = r.into_string().unwrap_or_default();
                // Esplora returns the node's own rejection reason here, which is the only
                // useful thing in the failure, so it is surfaced verbatim.
                anyhow::bail!("broadcast rejected (HTTP {status}): {}", body.trim())
            }
            Err(e) => anyhow::bail!("broadcast failed: {e}"),
        };
        let returned: Txid = resp
            .trim()
            .parse()
            .with_context(|| format!("Esplora returned {:?} instead of a txid", resp.trim()))?;
        // The node echoes the txid it accepted. If it differs from what was sent, something
        // rewrote the transaction, and reporting the sent txid would mean tracking one that
        // does not exist.
        let expected = tx.compute_txid();
        if returned != expected {
            anyhow::bail!("broadcast returned txid {returned}, but the sent transaction is {expected}");
        }
        Ok(returned)
    }

    /// Scan a wallet's addresses and return every unspent output.
    ///
    /// Walks both branches from index 0, stopping after `gap_limit` consecutive addresses
    /// with no history. Address *history* ends the scan rather than the presence of UTXOs:
    /// an address that received and then spent has no UTXOs but is plainly used, and
    /// treating it as free would stop the scan early and hide funds beyond it.
    pub fn scan(&self, wallet: &BitcoinWallet, gap_limit: u32) -> Result<Vec<Utxo>> {
        let mut found = Vec::new();
        for branch in [Branch::Receive, Branch::Change] {
            let mut gap = 0;
            let mut index = 0u32;
            while gap < gap_limit {
                let address = wallet.address(branch, index)?;
                if self.address_used(&address)? {
                    gap = 0;
                    found.extend(self.utxos(&address, branch, index)?);
                } else {
                    gap += 1;
                }
                index += 1;
            }
        }
        Ok(found)
    }

    /// The first address on `branch` with no history — the next one safe to hand out.
    pub fn next_unused(&self, wallet: &BitcoinWallet, branch: Branch) -> Result<(Address, u32)> {
        let mut index = 0u32;
        loop {
            let address = wallet.address(branch, index)?;
            if !self.address_used(&address)? {
                return Ok((address, index));
            }
            index += 1;
        }
    }
}

/// Decode a hex string. Written here rather than pulled in, since this is the only place
/// the crate parses hex from the network.
fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has an odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("bad hex at byte {}: {e}", i / 2))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spk() -> ScriptBuf {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[0xab; 32]);
        ScriptBuf::from_bytes(v)
    }

    /// A captured `GET /address/{addr}/utxo` response, confirmed and unconfirmed.
    const UTXO_BODY: &str = r#"[
      {"txid":"5e3a7b1c8f2d4e6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a",
       "vout":1,
       "status":{"confirmed":true,"block_height":812345,
                 "block_hash":"0000000000000000000000000000000000000000000000000000000000000000",
                 "block_time":1690000000},
       "value":123456},
      {"txid":"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
       "vout":0,
       "status":{"confirmed":false},
       "value":7}
    ]"#;

    #[test]
    fn utxos_decode_with_amounts_and_confirmation_intact() {
        let utxos = parse_utxos(UTXO_BODY, &spk(), Branch::Receive, 3).expect("decodes");
        assert_eq!(utxos.len(), 2);

        assert_eq!(utxos[0].value, 123_456);
        assert_eq!(utxos[0].outpoint.vout, 1);
        assert_eq!(utxos[0].height, Some(812_345));
        assert!(utxos[0].is_confirmed());

        // Unconfirmed: no height, even though the response carries no `block_height` key.
        assert_eq!(utxos[1].value, 7);
        assert_eq!(utxos[1].height, None);
        assert!(!utxos[1].is_confirmed());

        // The scriptPubKey and derivation come from the request, since the response omits
        // them — and without the scriptPubKey the output cannot be signed for.
        assert_eq!(utxos[0].script_pubkey, spk());
        assert_eq!(utxos[0].txout().script_pubkey, spk());
        assert_eq!((utxos[0].branch, utxos[0].index), (Branch::Receive, 3));
    }

    /// Esplora prints txids in reversed (display) order, so the decoded id must match what
    /// the string says — reading raw bytes instead would flip it and produce an outpoint
    /// that names no transaction.
    #[test]
    fn txids_keep_their_display_byte_order() {
        let utxos = parse_utxos(UTXO_BODY, &spk(), Branch::Receive, 0).unwrap();
        assert_eq!(
            utxos[0].outpoint.txid.to_string(),
            "5e3a7b1c8f2d4e6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a"
        );
    }

    /// A fractional value would be a rounded amount if it were accepted. Refusing it is
    /// the safe direction: an amount off by a satoshi makes every signature invalid.
    #[test]
    fn a_non_integer_value_is_refused_rather_than_rounded() {
        let body = r#"[{"txid":"5e3a7b1c8f2d4e6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a",
                        "vout":0,"status":{"confirmed":true,"block_height":1},"value":1.5}]"#;
        assert!(parse_utxos(body, &spk(), Branch::Receive, 0).is_err());
    }

    /// A response captured verbatim from `blockstream.info/signet/api`, so the decoder is
    /// checked against what Esplora actually sends rather than against a fixture written
    /// from the same assumptions as the code.
    ///
    /// Note the amount: 2_503_134_036 sat exceeds `f64`'s exact-integer comfort only
    /// slightly, but it is the kind of value that a float-typed decoder would eventually
    /// round — and an amount off by one satoshi invalidates every signature over it.
    const LIVE_SIGNET_UTXO_BODY: &str = r#"[
      {"txid":"2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348",
       "vout":0,
       "status":{"confirmed":true,"block_height":320630,
                 "block_hash":"00000010ad7530a587c7fd927e6e3346eb90f6162e0e07fb22dd6382aeed9f95",
                 "block_time":1788504191},
       "value":2503134036}
    ]"#;

    #[test]
    fn a_captured_live_response_decodes() {
        let utxos = parse_utxos(LIVE_SIGNET_UTXO_BODY, &spk(), Branch::Change, 1).expect("decodes");
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].value, 2_503_134_036);
        assert_eq!(utxos[0].height, Some(320_630));
        assert_eq!(
            utxos[0].outpoint.txid.to_string(),
            "2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348"
        );
        // Fields Esplora sends but this decoder ignores must not make it fail.
        assert!(utxos[0].is_confirmed());
    }

    /// An address with history but no unspent outputs — the case that makes the gap limit
    /// count *history* rather than UTXOs.
    ///
    /// Not hypothetical: the BIP86 test mnemonic's first signet address has 153
    /// transactions and an empty UTXO set. A scan keyed on UTXO presence would treat it as
    /// unused, and with enough such addresses in a row would stop early and miss funds
    /// beyond them.
    #[test]
    fn a_used_address_with_no_utxos_still_counts_as_used() {
        let stats = r#"{"chain_stats":{"funded_txo_count":141,"spent_txo_count":141,"tx_count":153},
                        "mempool_stats":{"tx_count":0}}"#;
        assert!(parse_address_used(stats).unwrap());
        assert!(parse_utxos("[]", &spk(), Branch::Receive, 0).unwrap().is_empty());
    }

    #[test]
    fn address_use_counts_mempool_as_well_as_chain() {
        let unused = r#"{"chain_stats":{"tx_count":0},"mempool_stats":{"tx_count":0}}"#;
        assert!(!parse_address_used(unused).unwrap());

        let confirmed = r#"{"chain_stats":{"tx_count":2},"mempool_stats":{"tx_count":0}}"#;
        assert!(parse_address_used(confirmed).unwrap());

        // An unconfirmed payment makes the address used. Handing it out again would merge
        // two payments onto one address.
        let pending = r#"{"chain_stats":{"tx_count":0},"mempool_stats":{"tx_count":1}}"#;
        assert!(parse_address_used(pending).unwrap());
    }

    #[test]
    fn tip_height_decodes_a_bare_number() {
        assert_eq!(parse_tip_height("812345\n").unwrap(), 812_345);
        assert!(parse_tip_height("not a height").is_err());
    }

    /// Esplora offers a sparse set of targets, so the nearest one at or above the request
    /// is used — erring toward confirming sooner rather than failing outright.
    #[test]
    fn fee_estimates_pick_the_nearest_target_at_or_above_the_request() {
        let body = r#"{"1":30.5,"3":12.0,"6":6.25,"144":1.0}"#;
        assert_eq!(parse_fee_estimate(body, 1).unwrap(), Some(30.5));
        assert_eq!(parse_fee_estimate(body, 3).unwrap(), Some(12.0));
        // 4 is not offered; 6 is the next one up.
        assert_eq!(parse_fee_estimate(body, 4).unwrap(), Some(6.25));
        // Nothing slow enough: report absence rather than substituting a faster rate,
        // which would silently overpay.
        assert_eq!(parse_fee_estimate(body, 1000).unwrap(), None);
    }

    #[test]
    fn default_urls_cover_the_public_networks_and_refuse_regtest() {
        assert_eq!(
            default_esplora_url(Network::Bitcoin),
            Some("https://blockstream.info/api")
        );
        assert_eq!(
            default_esplora_url(Network::BitcoinSignet),
            Some("https://blockstream.info/signet/api")
        );
        // No public regtest instance: an operator must say where theirs is, rather than
        // being pointed at somebody else's chain.
        assert_eq!(default_esplora_url(Network::BitcoinRegtest), None);
        assert!(EsploraClient::for_network(Network::BitcoinRegtest).is_err());
    }

    #[test]
    fn base_urls_are_normalised_so_paths_do_not_double_up() {
        let c = EsploraClient::new("https://example.invalid/api/");
        assert_eq!(c.base_url, "https://example.invalid/api");
    }

    #[test]
    fn hex_decoding_rejects_malformed_input() {
        assert_eq!(hex_to_bytes("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(hex_to_bytes("abc").is_err(), "odd length");
        assert!(hex_to_bytes("zz").is_err(), "non-hex digits");
    }
}


// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/// Which kind of chain access to use for Bitcoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinBackendKind {
    /// An Esplora HTTP instance. Right against a public network.
    Esplora,
    /// A node's own JSON-RPC. Right against a chain you run yourself — notably a regtest,
    /// where standing up an Esplora would mean an indexer and an API server to serve a
    /// handful of blocks.
    Rpc,
}

impl BitcoinBackendKind {
    /// Parse a config string, defaulting to Esplora for anything unrecognized so an older
    /// config keeps its behaviour.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "rpc" | "bitcoind" | "node" => BitcoinBackendKind::Rpc,
            _ => BitcoinBackendKind::Esplora,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BitcoinBackendKind::Esplora => "esplora",
            BitcoinBackendKind::Rpc => "rpc",
        }
    }
}

/// A connected Bitcoin chain backend.
///
/// An enum rather than a trait object for the same reason [`crate::backend::Backend`] is
/// one: there are two of them, they are chosen once per run, and a single concrete type at
/// every call site is easier to follow than a dyn dispatch that never varies.
pub enum BitcoinChain {
    Esplora(EsploraClient),
    Rpc(crate::bitcoin_rpc::RpcClient),
}

impl BitcoinChain {
    /// Every unspent output belonging to `wallet`.
    ///
    /// The two backends differ in what bounds the search, and it is worth knowing which
    /// you have. Esplora reads address *history*, so it stops after `gap_limit` consecutive
    /// addresses that were never used and finds coins beyond a gap of spent addresses. A
    /// node's UTXO-set scan has no history at all, so `gap_limit` becomes the hard edge of
    /// how far it looks: a coin at index `gap_limit + 1` is invisible to it.
    pub fn scan(&self, wallet: &BitcoinWallet, gap_limit: u32) -> Result<Vec<Utxo>> {
        match self {
            BitcoinChain::Esplora(c) => c.scan(wallet, gap_limit),
            BitcoinChain::Rpc(c) => c.scan_wallet(wallet, gap_limit),
        }
    }

    pub fn broadcast(
        &self,
        tx: &lwk_wollet::elements::bitcoin::Transaction,
    ) -> Result<lwk_wollet::elements::bitcoin::Txid> {
        match self {
            BitcoinChain::Esplora(c) => c.broadcast(tx),
            BitcoinChain::Rpc(c) => c.broadcast(tx),
        }
    }

    pub fn tip_height(&self) -> Result<u32> {
        match self {
            BitcoinChain::Esplora(c) => c.tip_height(),
            BitcoinChain::Rpc(c) => Ok(c.block_count()? as u32),
        }
    }

    /// The first address on `branch` this backend considers free.
    ///
    /// "Free" means something weaker on RPC. Esplora can say an address was never touched;
    /// a UTXO-set scan can only say it holds nothing now, which is also true of an address
    /// that received and spent. So on a node backend this can hand back an address with a
    /// history — a privacy fault rather than a loss, and the honest trade for not running
    /// an indexer.
    pub fn next_unused(&self, wallet: &BitcoinWallet, branch: Branch) -> Result<(Address, u32)> {
        match self {
            BitcoinChain::Esplora(c) => c.next_unused(wallet, branch),
            BitcoinChain::Rpc(c) => {
                let held: std::collections::HashSet<u32> = c
                    .scan_wallet(wallet, DEFAULT_GAP_LIMIT)?
                    .into_iter()
                    .filter(|u| u.branch == branch)
                    .map(|u| u.index)
                    .collect();
                let index = (0..).find(|i| !held.contains(i)).expect("an index is free");
                Ok((wallet.address(branch, index)?, index))
            }
        }
    }

    /// Fee rate in sat/vB for confirmation within `target_blocks`, when the backend offers
    /// one. `None` is a normal answer on regtest, which has no fee market to estimate from.
    pub fn fee_estimate(&self, target_blocks: u16) -> Result<Option<f32>> {
        match self {
            BitcoinChain::Esplora(c) => c.fee_estimate(target_blocks),
            // `estimatesmartfee` errors rather than answering on a chain with no history,
            // which is the usual case for the node backend, so a failure is reported as
            // "no estimate" rather than as a broken backend.
            BitcoinChain::Rpc(c) => {
                let Ok(v) = c.call("estimatesmartfee", serde_json::json!([target_blocks])) else {
                    return Ok(None);
                };
                Ok(v.get("feerate")
                    .and_then(|f| f.as_f64())
                    // BTC/kvB on the wire; sat/vB everywhere in this crate.
                    .map(|btc_per_kvb| (btc_per_kvb * 100_000.0) as f32))
            }
        }
    }
}

impl std::fmt::Debug for BitcoinChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinChain::Esplora(c) => write!(f, "{c:?}"),
            BitcoinChain::Rpc(c) => write!(f, "{c:?}"),
        }
    }
}
