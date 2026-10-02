//! Bitcoin chain access over a node's JSON-RPC, as an alternative to
//! [`crate::bitcoin_backend`]'s Esplora client.
//!
//! Esplora is the right backend against a public network, where somebody else already runs
//! the indexer. It is the wrong one against a regtest you just started: standing up an
//! Esplora instance means an electrs and an API server alongside the node, to index a
//! chain with four blocks in it.
//!
//! A node speaks everything this engine needs on its own, and two of the RPCs matter more
//! than the rest:
//!
//! - **`scantxoutset`** finds our coins by scanning the UTXO set for descriptors we supply.
//!   No wallet, no rescan, no import — which is what makes this work against a node started
//!   thirty seconds ago, and against one built without wallet support at all.
//! - **`generatetoaddress`** mines to an address we choose, so a regtest wallet funds itself
//!   without a faucet.
//!
//! # Why this exists now
//!
//! Simplicity on Bitcoin is a soft fork nobody has activated on a public network, so the
//! only chain that will execute a Bitcoin covenant is one you run yourself — currently a
//! regtest of the `simplicity-inquisition` branch. Esplora cannot reach that chain without
//! a great deal of scaffolding; a node's own RPC can.

use std::collections::HashMap;

use anyhow::{Context, Result};
use lwk_wollet::elements::bitcoin::{
    consensus::encode::serialize_hex, Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut,
    Txid,
};
// Bitcoin Core reports amounts as JSON numbers in BTC, and they are read with rust-bitcoin's
// own helper: it takes the `f64` serde_json produces, prints it with Rust's `Display`
// (shortest round-trip, never exponent notation) and parses that decimal text exactly, so
// every amount Core can send arrives to the satoshi.
//
// What this replaced looked right, which is why it is recorded. The amount was kept as a
// `serde_json::Number` on the belief that its original text survived, and that text was
// parsed by hand. It survives only under serde_json's `arbitrary_precision` feature, which
// this build does not enable — so the text was re-rendered from an `f64`, serde_json renders
// anything under 1e-5 BTC in exponent form (`5.46e-6`), and the parser refused it. One
// output under 1,000 sat anywhere in the wallet failed every scan.
use lwk_wollet::elements::bitcoin::amount::serde::as_btc as btc_amount;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::bitcoin_backend::Utxo;
use crate::bitcoin_wallet::{BitcoinWallet, Branch};

/// A blocking JSON-RPC client for a Bitcoin node.
pub struct RpcClient {
    url: String,
    auth: Option<(String, String)>,
    agent: ureq::Agent,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The password is deliberately absent. A cookie or an rpcpassword in a log line is
        // a credential leak, and `{:?}` reaches logs by accident more than by design.
        f.debug_struct("RpcClient")
            .field("url", &self.url)
            .field("auth", &self.auth.as_ref().map(|(u, _)| u.as_str()))
            .finish()
    }
}

impl RpcClient {
    /// A client for `url`, optionally with HTTP basic auth credentials.
    pub fn new(url: impl Into<String>, auth: Option<(String, String)>) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            auth,
            agent: ureq::AgentBuilder::new().build(),
        }
    }

    /// A client reading credentials from a node's `.cookie` file.
    ///
    /// The cookie is `__cookie__:<random>`, rewritten on every start, which is what makes
    /// it the right thing to read rather than cache.
    pub fn with_cookie(url: impl Into<String>, cookie_path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(cookie_path)
            .with_context(|| format!("cannot read RPC cookie: {}", cookie_path.display()))?;
        let (user, pass) = raw.trim().split_once(':').ok_or_else(|| {
            anyhow::anyhow!("malformed RPC cookie in {}", cookie_path.display())
        })?;
        Ok(Self::new(url, Some((user.to_string(), pass.to_string()))))
    }

    /// Issue one JSON-RPC call and return its `result`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "1.0", "id": "txmanifest", "method": method, "params": params});
        let mut req = self.agent.post(&self.url).set("Content-Type", "application/json");
        if let Some((user, pass)) = &self.auth {
            req = req.set("Authorization", &basic_auth(user, pass));
        }
        // Serialized here rather than via `send_json`, which needs a ureq feature this
        // crate does not otherwise enable.
        let encoded = serde_json::to_string(&body).context("cannot encode RPC request")?;
        let text = match req.send_string(&encoded) {
            Ok(resp) => resp.into_string().context("cannot read RPC response")?,
            // A node reports an application error with an HTTP error status *and* a body
            // carrying the reason, so the body is the useful half and must not be dropped.
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                match parse_rpc_error(&body) {
                    Some(msg) => anyhow::bail!("{method} failed: {msg}"),
                    None => anyhow::bail!("{method} failed with HTTP {status}: {}", body.trim()),
                }
            }
            Err(e) => anyhow::bail!("{method} failed: {e}"),
        };
        parse_rpc_result(&text).with_context(|| format!("{method} returned an unusable response"))
    }

    pub fn block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([]))?
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("getblockcount did not return a number"))
    }

    /// The chain the node is on, as it names it (`main`, `test`, `signet`, `regtest`).
    pub fn chain(&self) -> Result<String> {
        let info = self.call("getblockchaininfo", json!([]))?;
        info.get("chain")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("getblockchaininfo carries no chain"))
    }

    /// Whether the node reports a deployment as active.
    ///
    /// Used to check that a node actually has Simplicity, rather than taking the wallet
    /// config's word for it — the config says what the operator believes, and a covenant
    /// address derived against a node that will not execute it is unspendable.
    pub fn deployment_active(&self, name: &str) -> Result<bool> {
        let info = self.call("getdeploymentinfo", json!([]))?;

        // Two places, because a rule can reach a node by two routes. A soft fork still
        // being deployed appears under `deployments` with a BIP9 status; one that is simply
        // *on* for this chain — which is how Simplicity arrives on an inquisition
        // regtest — appears only as an enabled script flag. Checking `deployments` alone
        // reports an active rule as inactive, which is the answer that stops a covenant run
        // that would have worked.
        if let Some(flags) = info.get("script_flags").and_then(Value::as_array) {
            if flags
                .iter()
                .filter_map(Value::as_str)
                .any(|f| f.eq_ignore_ascii_case(name))
            {
                return Ok(true);
            }
        }

        let Some(deployments) = info.get("deployments") else { return Ok(false) };
        let Some(entry) = deployments.get(name).or_else(|| {
            deployments
                .as_object()
                .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
        }) else {
            return Ok(false);
        };
        Ok(entry.get("active").and_then(Value::as_bool).unwrap_or(false)
            || entry.get("bip9").and_then(|b| b.get("status")).and_then(Value::as_str)
                == Some("active"))
    }

    /// Broadcast a signed transaction.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let hex = serialize_hex(tx);
        let returned: Txid = self
            .call("sendrawtransaction", json!([hex]))?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("sendrawtransaction did not return a txid"))?
            .parse()
            .context("sendrawtransaction returned an unparseable txid")?;
        // The node echoes what it accepted. A mismatch means something rewrote the
        // transaction, and reporting the sent txid would mean tracking one that does not
        // exist.
        let expected = tx.compute_txid();
        if returned != expected {
            anyhow::bail!("node accepted {returned}, but the sent transaction is {expected}");
        }
        Ok(returned)
    }

    /// An unspent output, or `None` when it does not exist or is already spent.
    ///
    /// `gettxout` rather than `getrawtransaction`: it needs no `-txindex`, and it reads the
    /// UTXO set, so a spent outpoint comes back empty instead of looking spendable.
    pub fn txout(&self, outpoint: OutPoint) -> Result<Option<TxOut>> {
        let v = self.call("gettxout", json!([outpoint.txid.to_string(), outpoint.vout, true]))?;
        if v.is_null() {
            return Ok(None);
        }
        let wire: WireTxOut = serde_json::from_value(v).context("cannot decode gettxout")?;
        Ok(Some(TxOut {
            value: wire.value,
            script_pubkey: ScriptBuf::from_bytes(
                bytes_of_hex(&wire.script_pub_key.hex).context("bad scriptPubKey hex")?,
            ),
        }))
    }

    /// Mine `blocks` blocks paying `address`. Regtest only.
    pub fn generate_to_address(&self, blocks: u32, address: &Address) -> Result<Vec<String>> {
        let hashes = self.call("generatetoaddress", json!([blocks, address.to_string()]))?;
        Ok(hashes
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default())
    }

    /// Find unspent outputs paying any of `scripts`, by scanning the node's UTXO set.
    ///
    /// Addressed by raw scriptPubKey (`raw(<hex>)`) rather than by address, because a
    /// covenant's scriptPubKey is derived rather than encoded — it has an address form, but
    /// building one only to have the node decode it back is a round trip that can only lose.
    pub fn scan_scripts(&self, scripts: &[ScriptBuf]) -> Result<Vec<ScannedOutput>> {
        if scripts.is_empty() {
            return Ok(Vec::new());
        }
        let descriptors: Vec<Value> = scripts
            .iter()
            .map(|s| json!(format!("raw({})", hex_of(s.as_bytes()))))
            .collect();
        let result = self.call("scantxoutset", json!(["start", descriptors]))?;

        // `success: false` means the scan was aborted, which is not the same as finding
        // nothing — treating it as an empty wallet would be a silent wrong answer.
        if result.get("success").and_then(Value::as_bool) == Some(false) {
            anyhow::bail!("scantxoutset did not complete");
        }
        let wire: Vec<WireScanUnspent> = serde_json::from_value(
            result.get("unspents").cloned().unwrap_or_else(|| json!([])),
        )
        .context("cannot decode scantxoutset unspents")?;

        wire.into_iter()
            .map(|u| {
                Ok(ScannedOutput {
                    outpoint: OutPoint {
                        txid: u.txid.parse().with_context(|| format!("bad txid {}", u.txid))?,
                        vout: u.vout,
                    },
                    script_pubkey: ScriptBuf::from_bytes(
                        bytes_of_hex(&u.script_pub_key).context("bad scriptPubKey hex")?,
                    ),
                    value: u.amount.to_sat(),
                    height: u.height,
                    coinbase: u.coinbase.then(|| crate::bitcoin_backend::CoinbaseInfo {
                        // A coinbase with no confirmation count is treated as brand new
                        // rather than mature: refusing to spend a mature coin costs a
                        // retry, while spending an immature one costs a rejected
                        // transaction and a confusing error.
                        confirmations: u.confirmations.unwrap_or(0),
                    }),
                })
            })
            .collect()
    }

    /// Scan for a wallet's own coins, deriving addresses up to `gap_limit` on each branch.
    ///
    /// A UTXO-set scan has no notion of address history, so it cannot stop at a gap the way
    /// [`crate::bitcoin_backend::EsploraClient::scan`] does — it simply looks at every
    /// script it is given. That makes the limit an input rather than a stopping rule.
    pub fn scan_wallet(&self, wallet: &BitcoinWallet, gap_limit: u32) -> Result<Vec<Utxo>> {
        let mut scripts = Vec::new();
        let mut origin: HashMap<Vec<u8>, (Branch, u32)> = HashMap::new();
        for branch in [Branch::Receive, Branch::Change] {
            for index in 0..gap_limit {
                let spk = wallet.script_pubkey(branch, index)?;
                origin.insert(spk.to_bytes(), (branch, index));
                scripts.push(spk);
            }
        }

        self.scan_scripts(&scripts)?
            .into_iter()
            .map(|found| {
                let (branch, index) = origin
                    .get(found.script_pubkey.as_bytes())
                    .copied()
                    // The node only reports scripts we asked about, so this cannot happen
                    // — and if it does, guessing a derivation would produce an input that
                    // is signed with the wrong key.
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "node reported {} for a script that was not scanned",
                            found.outpoint
                        )
                    })?;
                Ok(Utxo {
                    outpoint: found.outpoint,
                    value: found.value,
                    script_pubkey: found.script_pubkey,
                    branch,
                    index,
                    height: found.height,
                    coinbase: found.coinbase,
                })
            })
            .collect()
    }
}

/// One unspent output as `scantxoutset` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedOutput {
    pub outpoint: OutPoint,
    pub script_pubkey: ScriptBuf,
    pub value: u64,
    pub height: Option<u32>,
    /// Set when the output is a block reward; see [`crate::bitcoin_backend::Utxo::coinbase`].
    pub coinbase: Option<crate::bitcoin_backend::CoinbaseInfo>,
}

#[derive(Debug, Deserialize)]
struct WireScanUnspent {
    txid: String,
    vout: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: String,
    /// BTC, as a JSON number; see the note on `btc_amount` at the top of this module.
    #[serde(with = "btc_amount")]
    amount: Amount,
    #[serde(default)]
    height: Option<u32>,
    /// Whether this output is a block reward. Core reports it; Esplora does not.
    #[serde(default)]
    coinbase: bool,
    #[serde(default)]
    confirmations: Option<u32>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Pull `result` out of a JSON-RPC response, surfacing `error` when present.
fn parse_rpc_result(body: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(body)
        .with_context(|| format!("response is not JSON: {}", body.trim()))?;
    if let Some(err) = v.get("error") {
        if !err.is_null() {
            let msg = err.get("message").and_then(Value::as_str).unwrap_or("unknown error");
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            anyhow::bail!("node error {code}: {msg}");
        }
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("response carries no result: {}", body.trim()))
}

/// The `error.message` from an error-status response body, if it has one.
fn parse_rpc_error(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let err = v.get("error")?;
    let msg = err.get("message").and_then(Value::as_str)?;
    let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
    Some(format!("node error {code}: {msg}"))
}

/// The output fields this crate reads from `gettxout`.
#[derive(Debug, Deserialize)]
struct WireTxOut {
    #[serde(with = "btc_amount")]
    value: Amount,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: WireScriptPubKey,
}

#[derive(Debug, Deserialize)]
struct WireScriptPubKey {
    hex: String,
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes_of_hex(s: &str) -> Result<Vec<u8>> {
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

fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a `gettxout` body carrying `value`, and return its satoshis.
    fn gettxout_sats(value: &str) -> Result<u64, serde_json::Error> {
        let body = format!(r#"{{"value": {value}, "scriptPubKey": {{"hex": "5120ab"}}}}"#);
        serde_json::from_str::<WireTxOut>(&body).map(|w| w.value.to_sat())
    }

    /// Every amount Core can send arrives to the satoshi.
    #[test]
    fn btc_amounts_decode_exactly() {
        // Under 1e-5 BTC: serde_json renders these as `5.46e-6`, `1e-8` — the cases that
        // used to fail. 546 and 330 are the dust limits, so the wallet makes such outputs
        // itself.
        assert_eq!(gettxout_sats("0.00000546").unwrap(), 546);
        assert_eq!(gettxout_sats("0.00000330").unwrap(), 330);
        assert_eq!(gettxout_sats("0.00000001").unwrap(), 1);
        assert_eq!(gettxout_sats("0.00000999").unwrap(), 999);

        // The values a naive float conversion gets wrong: 0.1 BTC times 1e8 lands just
        // below 10_000_000 and truncates.
        assert_eq!(gettxout_sats("0.1").unwrap(), 10_000_000);
        assert_eq!(gettxout_sats("0.29").unwrap(), 29_000_000);
        assert_eq!(gettxout_sats("1.1").unwrap(), 110_000_000);
        assert_eq!(gettxout_sats("25.06084842").unwrap(), 2_506_084_842);

        assert_eq!(gettxout_sats("0").unwrap(), 0);
        assert_eq!(gettxout_sats("50").unwrap(), 5_000_000_000);
        assert_eq!(gettxout_sats("20999999.99999999").unwrap(), 2_099_999_999_999_999);

        assert!(gettxout_sats("-0.1").is_err(), "negative");
        assert!(gettxout_sats("0.000000001").is_err(), "sub-satoshi precision");
    }

    /// The one-satoshi step is exact across the whole range of small amounts — the range
    /// that broke, and the one a spot check is most likely to miss.
    #[test]
    fn every_amount_below_a_thousand_sat_decodes() {
        for sats in 0..=1_000u64 {
            let btc = format!("0.{sats:08}");
            assert_eq!(gettxout_sats(&btc).unwrap(), sats, "{btc}");
        }
    }

    /// A small coin in a `scantxoutset` result decodes rather than failing the whole scan.
    #[test]
    fn a_dust_sized_utxo_does_not_fail_a_scan() {
        let body = r#"[
          {"txid":"2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348",
           "vout":0,"scriptPubKey":"5120ab","amount":0.00000546},
          {"txid":"2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348",
           "vout":1,"scriptPubKey":"5120ab","amount":0.5}
        ]"#;
        let wire: Vec<WireScanUnspent> = serde_json::from_str(body).expect("decodes");
        assert_eq!(wire[0].amount.to_sat(), 546);
        assert_eq!(wire[1].amount.to_sat(), 50_000_000);
    }

    /// A node reports an application error in the body, not only in the status.
    #[test]
    fn rpc_errors_surface_the_nodes_own_message() {
        let body = r#"{"result":null,"error":{"code":-26,"message":"min relay fee not met"},"id":"x"}"#;
        let err = parse_rpc_result(body).unwrap_err().to_string();
        assert!(err.contains("min relay fee not met"), "{err}");
        assert!(err.contains("-26"), "{err}");

        assert_eq!(parse_rpc_error(body).unwrap(), "node error -26: min relay fee not met");
    }

    #[test]
    fn a_successful_response_yields_its_result() {
        let body = r#"{"result":812345,"error":null,"id":"x"}"#;
        assert_eq!(parse_rpc_result(body).unwrap().as_u64(), Some(812345));
    }

    /// A `scantxoutset` response, shaped as Bitcoin Core sends one.
    #[test]
    fn scan_results_decode_with_exact_amounts() {
        let body = r#"{
          "success": true,
          "txouts": 1,
          "height": 101,
          "unspents": [
            {"txid":"2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348",
             "vout":0,
             "scriptPubKey":"512042424242424242424242424242424242424242424242424242424242424242 42",
             "desc":"raw(...)",
             "amount":25.06084842,
             "height":101}
          ],
          "total_amount": 25.06084842
        }"#;
        // The embedded space above would be a real decode failure, so strip it the way a
        // real response would never need.
        let body = body.replace("42 42", "4242");
        let v: Value = serde_json::from_str(&body).unwrap();
        let wire: Vec<WireScanUnspent> =
            serde_json::from_value(v.get("unspents").cloned().unwrap()).expect("decodes");
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].vout, 0);
        assert_eq!(wire[0].height, Some(101));
        assert_eq!(wire[0].amount.to_sat(), 2_506_084_842);
    }

    /// Core reports `coinbase` and `confirmations`; both must survive decoding, since
    /// together they decide whether a coin can be spent at all.
    #[test]
    fn coinbase_status_survives_decoding() {
        let body = r#"[
          {"txid":"285a4a65e56c2c6993c68fe72485b5b12f645221f5607ee8aa495eb092db8300",
           "vout":0,"scriptPubKey":"5120fb","amount":6.25,
           "coinbase":true,"height":480,"confirmations":47},
          {"txid":"2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348",
           "vout":1,"scriptPubKey":"5120ab","amount":0.5,
           "coinbase":false,"height":100,"confirmations":427}
        ]"#;
        let wire: Vec<WireScanUnspent> = serde_json::from_str(body).expect("decodes");
        assert!(wire[0].coinbase);
        assert_eq!(wire[0].confirmations, Some(47));
        assert!(!wire[1].coinbase);
        assert_eq!(wire[0].amount.to_sat(), 625_000_000);
        assert_eq!(wire[1].amount.to_sat(), 50_000_000);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0x51, 0x20, 0xab, 0x00, 0xff];
        assert_eq!(bytes_of_hex(&hex_of(&bytes)).unwrap(), bytes);
        assert!(bytes_of_hex("abc").is_err());
        assert!(bytes_of_hex("zz").is_err());
    }

    /// Credentials must not reach a log line through `{:?}`.
    #[test]
    fn debug_output_omits_the_password() {
        let c = RpcClient::new(
            "http://localhost:18443",
            Some(("__cookie__".into(), "supersecret".into())),
        );
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("supersecret"), "{rendered}");
        assert!(rendered.contains("__cookie__"), "{rendered}");
    }
}
