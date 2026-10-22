//! Runs every spending path of `examples/oracle_demo/oracle_mint.simf` on the BitMachine,
//! against transactions built here, with the fake oracle's signed statements from
//! `examples/oracle_demo/data/`.
//!
//! Each path has a passing case and the failures that matter for the challenge window:
//! a forged or stale statement, a challenge within tolerance, a finalize before the
//! window, and a second treasury UTXO riding along with a request. And for the cold-key
//! certificates: a statement outside its certificate's range, a certificate from the
//! wrong key or for another oracle, and a challenge from an oracle certified later.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use lwk_wollet::elements::confidential::{Asset, Nonce, Value};
use lwk_wollet::elements::hashes::{sha256, Hash, HashEngine};
use lwk_wollet::elements::secp256k1_zkp::{
    ecdsa, Keypair, Message, PublicKey, Secp256k1, SecretKey,
};
use lwk_wollet::elements::{
    AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness, Txid,
};
use lwk_wollet::ElementsNetwork;
use serde_json::json;
use tx_manifest_lib::chain::ChainFamily;
use tx_manifest_lib::covenant;
use tx_manifest_lib::programs::ProgramSource;

const LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
/// A stand-in for the tUSDT asset id.
const USD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const WINDOW_BLOCKS: u32 = 5;
const SUPPLY: u64 = 1_000_000_000_000_000;
const LBTC_AMOUNT: u64 = 100_000;

fn example_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/oracle_demo")
}

fn program() -> ProgramSource {
    ProgramSource::read_unpinned(example_dir().join("oracle_mint.simf")).unwrap()
}

/// A statement split into the witnesses the program reads, its certificate's among them.
struct Statement {
    price_cents: u64,
    timestamp: u64,
    witnesses: BTreeMap<&'static str, String>,
}

impl Statement {
    /// This statement, presented with `cert` in place of any certificate it had.
    fn with_cert(mut self, cert: &Cert) -> Self {
        self.witnesses.extend(cert.witnesses());
        self
    }
}

/// A certificate: the cold key's BIP340 signature saying `oracle_key` may sign statements
/// timestamped from `valid_from` to `valid_until`.
struct Cert {
    oracle_key: [u8; 33],
    valid_from: u64,
    valid_until: u64,
    sig: [u8; 64],
}

impl Cert {
    fn witnesses(&self) -> [(&'static str, String); 4] {
        [
            (
                "CERT_ORACLE_KEY",
                format!("({}, 0x{})", self.oracle_key[0], hex(&self.oracle_key[1..])),
            ),
            ("CERT_VALID_FROM", self.valid_from.to_string()),
            ("CERT_VALID_UNTIL", self.valid_until.to_string()),
            ("CERT_SIG", format!("0x{}", hex(&self.sig))),
        ]
    }
}

const SOURCES: &str = "binance,bitstamp,coinbase,kraken,okx";

fn simf_list(text: &str) -> String {
    let bytes: Vec<String> = text.bytes().map(|b| b.to_string()).collect();
    format!("list![{}]", bytes.join(", "))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn read_json(name: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(example_dir().join(name)).unwrap()).unwrap()
}

fn secret(file: &str) -> SecretKey {
    SecretKey::from_str(read_json(file)["secret"].as_str().unwrap()).unwrap()
}

/// The fake oracle's key, which signed every statement in `data/`.
fn oracle_key() -> SecretKey {
    secret("data/example_oracle_key.json")
}

/// The service's cold key, which certifies oracle keys.
fn cold_key() -> SecretKey {
    secret("data/example_cold_key.json")
}

/// A second oracle, to rotate to. Any key will do.
fn second_oracle_key() -> SecretKey {
    SecretKey::from_slice(&[0x42; 32]).unwrap()
}

/// `cold` certifies `oracle` for statements timestamped `valid_from..=valid_until`.
fn certify(cold: &SecretKey, oracle: &SecretKey, valid_from: u64, valid_until: u64) -> Cert {
    let secp = Secp256k1::new();
    let oracle_key = PublicKey::from_secret_key(&secp, oracle).serialize();
    let tag = sha256::Hash::hash(b"oracle-demo/oracle-cert/v1");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_ref());
    engine.input(tag.as_ref());
    engine.input(&oracle_key);
    engine.input(&valid_from.to_be_bytes());
    engine.input(&valid_until.to_be_bytes());
    let msg = Message::from_digest_slice(sha256::Hash::from_engine(engine).as_ref()).unwrap();
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &Keypair::from_secret_key(&secp, cold));
    Cert {
        oracle_key,
        valid_from,
        valid_until,
        sig: *sig.as_ref(),
    }
}

/// The certificate fake_oracle.py made for the oracle key, `data/cert_oracle.json`.
/// Statements from `data/` carry it, so the program checks the script's BIP340 signer.
fn fixture_cert() -> Cert {
    let raw = read_json("data/cert_oracle.json");
    let bytes = |field: &str| unhex(raw[field].as_str().unwrap());
    Cert {
        oracle_key: bytes("oracle_pubkey").try_into().unwrap(),
        valid_from: raw["valid_from"].as_u64().unwrap(),
        valid_until: raw["valid_until"].as_u64().unwrap(),
        sig: bytes("signature").try_into().unwrap(),
    }
}

/// A statement's witnesses, given the variable fields as the witness splits them. It has
/// no certificate until [`Statement::with_cert`].
fn split(
    price: &str,
    sources: &str,
    method: &str,
    timestamp: &str,
    nonce: &str,
    compact_sig: [u8; 64],
) -> Statement {
    let (integer, fraction) = price.split_once('.').unwrap();
    let frac = fraction.as_bytes();
    let witnesses = BTreeMap::from([
        ("STATEMENT_PRICE_INT", simf_list(integer)),
        (
            "STATEMENT_PRICE_FRAC",
            format!("({}, {})", frac[0], frac[1]),
        ),
        ("STATEMENT_SOURCES", simf_list(sources)),
        ("STATEMENT_METHOD", simf_list(method)),
        ("STATEMENT_TIMESTAMP", simf_list(timestamp)),
        ("STATEMENT_NONCE", simf_list(nonce)),
        (
            "STATEMENT_SIG",
            format!(
                "(0x{}, 0x{})",
                hex(&compact_sig[..32]),
                hex(&compact_sig[32..])
            ),
        ),
    ]);
    Statement {
        price_cents: format!("{integer}{fraction}").parse().unwrap(),
        timestamp: timestamp.parse().unwrap(),
        witnesses,
    }
}

/// A statement the fake oracle signed, from `data/statement_<name>.json`, with the
/// fixture certificate.
fn statement(name: &str) -> Statement {
    let raw = read_json(&format!("data/statement_{name}.json"));
    let canonical = raw["canonical"].as_str().unwrap();
    let fields: Vec<&str> = canonical.split('|').collect();
    assert_eq!(fields.len(), 10, "{canonical}");

    let der = base64::engine::general_purpose::STANDARD
        .decode(raw["signature"].as_str().unwrap())
        .unwrap();
    let compact = ecdsa::Signature::from_der(&der)
        .unwrap()
        .serialize_compact();
    split(
        fields[3], fields[6], fields[7], fields[8], fields[9], compact,
    )
    .with_cert(&fixture_cert())
}

/// `oracle` signs `v1|PRICE|BTCUSD|<price>|USD|2|<sources>|<method>|<timestamp>|<nonce>`,
/// split into exactly those fields. No certificate yet.
fn signed_by(
    oracle: &SecretKey,
    price: &str,
    sources: &str,
    method: &str,
    timestamp: &str,
    nonce: &str,
) -> Statement {
    let canonical = format!("v1|PRICE|BTCUSD|{price}|USD|2|{sources}|{method}|{timestamp}|{nonce}");
    let digest = sha256::Hash::hash(canonical.as_bytes()).to_byte_array();
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from_digest_slice(&digest).unwrap(), oracle);
    split(
        price,
        sources,
        method,
        timestamp,
        nonce,
        sig.serialize_compact(),
    )
}

/// The fake oracle signs a string split into these fields, certified for any timestamp.
fn signed_split(
    price: &str,
    sources: &str,
    method: &str,
    timestamp: &str,
    nonce: &str,
) -> Statement {
    signed_by(&oracle_key(), price, sources, method, timestamp, nonce).with_cert(&certify(
        &cold_key(),
        &oracle_key(),
        0,
        u64::MAX,
    ))
}

const STATEMENT_WITNESSES: [&str; 11] = [
    "STATEMENT_PRICE_INT",
    "STATEMENT_PRICE_FRAC",
    "STATEMENT_SOURCES",
    "STATEMENT_METHOD",
    "STATEMENT_TIMESTAMP",
    "STATEMENT_NONCE",
    "STATEMENT_SIG",
    "CERT_ORACLE_KEY",
    "CERT_VALID_FROM",
    "CERT_VALID_UNTIL",
    "CERT_SIG",
];

/// One mint service, compiled once per test.
struct Service {
    program: ProgramSource,
    params: HashMap<String, String>,
    hints: HashMap<String, String>,
}

impl Service {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let (cold_pubkey, _) = cold_key().x_only_public_key(&secp);
        let params = HashMap::from([
            ("COLD_PUBKEY".into(), hex(&cold_pubkey.serialize())),
            ("LBTC_ASSET".into(), LBTC.into()),
            ("USD_ASSET".into(), USD.into()),
            ("WINDOW_BLOCKS".into(), WINDOW_BLOCKS.to_string()),
            ("TOLERANCE_BPS".into(), "50".into()),
        ]);
        let hints = HashMap::from([
            ("COLD_PUBKEY".into(), "pubkey".into()),
            ("LBTC_ASSET".into(), "liquid.asset_id".into()),
            ("USD_ASSET".into(), "liquid.asset_id".into()),
            ("WINDOW_BLOCKS".into(), "u16".into()),
            ("TOLERANCE_BPS".into(), "u64".into()),
        ]);
        Self {
            program: program(),
            params,
            hints,
        }
    }

    fn script(&self, leaf: &[u8]) -> Script {
        covenant::compute_covenant_address(
            &self.program,
            &self.params,
            &self.hints,
            &[leaf.to_vec()],
            ElementsNetwork::LiquidTestnet,
            false,
        )
        .unwrap()
        .script_pubkey()
    }

    fn treasury(&self) -> (Script, Vec<u8>) {
        (self.script(&[0]), vec![0])
    }

    fn pending(&self, req: &Request) -> (Script, Vec<u8>) {
        let mut leaf = vec![1];
        leaf.extend(req.price.to_be_bytes());
        leaf.extend(req.timestamp.to_be_bytes());
        leaf.extend(req.lbtc_amount.to_be_bytes());
        leaf.extend(sha256::Hash::hash(req.recipient.as_bytes()).to_byte_array());
        (self.script(&leaf), leaf)
    }

    /// Dry-run input `index` of `tx`, which spends `utxos`, as the covenant with `leaf`.
    fn run(
        &self,
        leaf: &[u8],
        witnesses: serde_json::Value,
        tx: &Transaction,
        utxos: &[TxOut],
        index: u32,
    ) -> anyhow::Result<()> {
        covenant::dry_run_covenant(
            &self.program,
            &self.params,
            &self.hints,
            &[leaf.to_vec()],
            Some(&witnesses),
            None,
            Arc::new(tx.clone()),
            utxos,
            index,
            BlockHash::all_zeros(),
            ChainFamily::Elements,
            false,
            false,
        )
    }
}

#[derive(Clone)]
struct Request {
    price: u64,
    timestamp: u64,
    lbtc_amount: u64,
    recipient: Script,
}

impl Request {
    fn from_statement(st: &Statement) -> Self {
        Self {
            price: st.price_cents,
            timestamp: st.timestamp,
            lbtc_amount: LBTC_AMOUNT,
            recipient: Script::from(Vec::from_iter([0x00, 0x14].into_iter().chain([0x42; 20]))),
        }
    }

    fn usd_amount(&self) -> u64 {
        self.lbtc_amount * self.price / 100
    }

    fn recipient_hash(&self) -> String {
        hex(&sha256::Hash::hash(self.recipient.as_bytes()).to_byte_array())
    }
}

fn witness(value: &str) -> serde_json::Value {
    json!({ "type": "simplicityhl", "value": value })
}

/// The witness map for one input: `path`, the request's fields or "unused", and the
/// statement's or "unused", padded when there is a statement.
fn witnesses(path: &str, req: Option<&Request>, st: Option<&Statement>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("PATH".into(), witness(path));
    let fields = req.map(|r| {
        [
            r.price.to_string(),
            r.timestamp.to_string(),
            r.lbtc_amount.to_string(),
            r.recipient_hash(),
        ]
    });
    for (i, name) in [
        "REQUEST_PRICE",
        "REQUEST_TIMESTAMP",
        "REQUEST_LBTC_AMOUNT",
        "REQUEST_RECIPIENT",
    ]
    .iter()
    .enumerate()
    {
        let value = match &fields {
            Some(f) => witness(&f[i]),
            None => json!("unused"),
        };
        map.insert((*name).into(), value);
    }
    for name in STATEMENT_WITNESSES {
        let value = match st {
            Some(s) => witness(&s.witnesses[name]),
            None => json!("unused"),
        };
        map.insert(name.into(), value);
    }
    // The paths that check a statement are the ones that need padding.
    let pad = match st {
        Some(_) => witness(BUDGET_PAD),
        None => json!("unused"),
    };
    map.insert("BUDGET_PAD".into(), pad);
    serde_json::Value::Object(map)
}

/// Assert that the program ran and refused the spend, rather than failing before it ran.
fn assert_rejected(result: anyhow::Result<()>) {
    let err = format!("{:#}", result.expect_err("the spend was accepted"));
    assert!(
        err.contains("satisfaction failed") || err.contains("execution failed"),
        "failed before the program ran: {err}"
    );
}

fn asset(id: &str) -> AssetId {
    AssetId::from_str(id).unwrap()
}

fn txout(script: &Script, asset_id: &str, amount: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset(asset_id)),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: script.clone(),
        witness: TxOutWitness::default(),
    }
}

fn fee(amount: u64) -> TxOut {
    TxOut::new_fee(amount, asset(LBTC))
}

fn burn(amount: u64) -> TxOut {
    txout(&Script::from(vec![0x6a]), LBTC, amount)
}

fn wallet_script() -> Script {
    Script::from(Vec::from_iter([0x00, 0x14].into_iter().chain([0x77; 20])))
}

fn txin(n: u8, sequence: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array([n; 32]), 0),
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence(sequence),
        asset_issuance: AssetIssuance::default(),
        witness: TxInWitness::default(),
    }
}

fn tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A request transaction, its spent outputs, and the treasury leaf.
fn request_tx(svc: &Service, req: &Request, usd_amount: u64) -> (Transaction, Vec<TxOut>, Vec<u8>) {
    let (treasury, treasury_leaf) = svc.treasury();
    let (pending, _) = svc.pending(req);
    let tx = tx(
        vec![txin(1, 0xffff_ffff), txin(2, 0xffff_ffff)],
        vec![
            txout(&pending, LBTC, req.lbtc_amount),
            txout(&pending, USD, usd_amount),
            txout(&treasury, USD, SUPPLY - usd_amount),
            txout(&wallet_script(), LBTC, 400_000 - req.lbtc_amount - 500),
            fee(500),
        ],
    );
    let utxos = vec![
        txout(&treasury, USD, SUPPLY),
        txout(&wallet_script(), LBTC, 400_000),
    ];
    (tx, utxos, treasury_leaf)
}

#[test]
fn request_opens_a_pending_mint() {
    let svc = Service::new();
    let st = statement("request");
    let req = Request::from_statement(&st);
    let (tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount());
    svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();
}

#[test]
fn request_refuses_more_tusdt_than_the_price_buys() {
    let svc = Service::new();
    let st = statement("request");
    let req = Request::from_statement(&st);
    let (tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount() + 1);
    assert_rejected(svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    ));
}

#[test]
fn request_refuses_a_forged_price() {
    let svc = Service::new();
    let mut st = statement("request");
    // 94231.50 under the signature on 84231.50.
    st.witnesses
        .insert("STATEMENT_PRICE_INT", simf_list("94231"));
    st.price_cents = 9_423_150;
    let req = Request::from_statement(&st);
    let (tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount());
    assert_rejected(svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    ));
}

#[test]
fn request_refuses_a_separator_inside_a_text_field() {
    // A signed string with two fields more than the format has. Read with the first
    // three fields after the decimals squeezed into "sources", it hashes to the same
    // bytes, so the signature verifies, and the nonce would read as a far-future
    // timestamp. Only the '|' check stands in the way.
    let svc = Service::new();
    let st = signed_split(
        "84231.50",
        "okx|median|1741514400",
        "482910",
        "9999999999",
        "0",
    );
    let req = Request::from_statement(&st);
    assert_eq!(req.timestamp, 9_999_999_999);
    let (tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount());
    assert_rejected(svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    ));

    // The same split without the separators is accepted, so it is the '|' that fails.
    let st = signed_split(
        "84231.50",
        "okx,median,1741514400",
        "482910",
        "9999999999",
        "0",
    );
    let req = Request::from_statement(&st);
    let (tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount());
    svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();
}

#[test]
fn request_refuses_a_pending_address_for_another_price() {
    let svc = Service::new();
    let st = statement("request");
    let req = Request::from_statement(&st);
    let (mut tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount());
    let (other, _) = svc.pending(&Request {
        price: req.price + 1,
        ..req.clone()
    });
    tx.output[0].script_pubkey = other.clone();
    tx.output[1].script_pubkey = other;
    assert_rejected(svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    ));
}

#[test]
fn a_second_treasury_utxo_cannot_ride_along() {
    // Both treasury UTXOs hold the supply, so input 0's checks on outputs 0-2 are met for
    // either. Input 1 would be free to pay its tUSDT anywhere if any path let it through.
    let svc = Service::new();
    let st = statement("request");
    let req = Request::from_statement(&st);
    let (treasury, leaf) = svc.treasury();
    let (mut tx, mut utxos, _) = request_tx(&svc, &req, req.usd_amount());
    utxos[1] = txout(&treasury, USD, SUPPLY);
    tx.output[3] = txout(&wallet_script(), USD, SUPPLY);

    svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();
    for path in [
        "Left(Left(()))",
        "Left(Right(()))",
        "Right(Left(()))",
        "Right(Right(()))",
    ] {
        assert_rejected(svc.run(
            &leaf,
            witnesses(path, Some(&req), Some(&st)),
            &tx,
            &utxos,
            1,
        ));
    }
}

// ---------------------------------------------------------------------------
// Finalize and challenge
// ---------------------------------------------------------------------------

/// Spend a pending request's two UTXOs, plus a wallet fee input.
fn settle_tx(
    svc: &Service,
    req: &Request,
    sequence: u32,
    outputs: Vec<TxOut>,
) -> (Transaction, Vec<TxOut>, Vec<u8>) {
    let (pending, leaf) = svc.pending(req);
    let tx = tx(
        vec![
            txin(3, sequence),
            txin(4, 0xffff_ffff),
            txin(5, 0xffff_ffff),
        ],
        outputs,
    );
    let utxos = vec![
        txout(&pending, LBTC, req.lbtc_amount),
        txout(&pending, USD, req.usd_amount()),
        txout(&wallet_script(), LBTC, 10_000),
    ];
    (tx, utxos, leaf)
}

fn finalize_outputs(req: &Request) -> Vec<TxOut> {
    vec![
        txout(&req.recipient, USD, req.usd_amount()),
        burn(req.lbtc_amount),
        txout(&wallet_script(), LBTC, 9_500),
        fee(500),
    ]
}

fn finalize(svc: &Service, req: &Request, sequence: u32) -> anyhow::Result<()> {
    let (tx, utxos, leaf) = settle_tx(svc, req, sequence, finalize_outputs(req));
    svc.run(
        &leaf,
        witnesses("Left(Right(()))", Some(req), None),
        &tx,
        &utxos,
        0,
    )?;
    svc.run(
        &leaf,
        witnesses("Right(Right(()))", None, None),
        &tx,
        &utxos,
        1,
    )
}

#[test]
fn finalize_after_the_window_pays_out_and_burns() {
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    finalize(&svc, &req, WINDOW_BLOCKS).unwrap();
}

#[test]
fn finalize_waits_for_the_window() {
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    assert_rejected(finalize(&svc, &req, WINDOW_BLOCKS - 1));
    // Relative lock disabled, and a time-based lock of the same number.
    assert_rejected(finalize(&svc, &req, 0x8000_0000 | WINDOW_BLOCKS));
    assert_rejected(finalize(&svc, &req, 0x0040_0000 | WINDOW_BLOCKS));
}

#[test]
fn finalize_pays_only_the_recipient() {
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    let mut outputs = finalize_outputs(&req);
    outputs[0].script_pubkey = wallet_script();
    let (tx, utxos, leaf) = settle_tx(&svc, &req, WINDOW_BLOCKS, outputs);
    assert_rejected(svc.run(
        &leaf,
        witnesses("Left(Right(()))", Some(&req), None),
        &tx,
        &utxos,
        0,
    ));
}

fn challenge(svc: &Service, req: &Request, newer: &str) -> anyhow::Result<()> {
    challenge_with(svc, req, &statement(newer))
}

fn challenge_with(svc: &Service, req: &Request, st: &Statement) -> anyhow::Result<()> {
    let (treasury, _) = svc.treasury();
    let outputs = vec![
        txout(&req.recipient, LBTC, req.lbtc_amount),
        txout(&treasury, USD, req.usd_amount()),
        txout(&wallet_script(), LBTC, 9_500),
        fee(500),
    ];
    let (tx, utxos, leaf) = settle_tx(svc, req, 0xffff_ffff, outputs);
    svc.run(
        &leaf,
        witnesses("Right(Left(()))", Some(req), Some(st)),
        &tx,
        &utxos,
        0,
    )?;
    svc.run(
        &leaf,
        witnesses("Right(Right(()))", None, None),
        &tx,
        &utxos,
        1,
    )
}

#[test]
fn challenge_with_a_newer_price_beyond_tolerance_refunds() {
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    // Both directions: the request's price was stale whichever way it moved.
    challenge(&svc, &req, "rose").unwrap();
    challenge(&svc, &req, "fell").unwrap();
}

#[test]
fn challenge_within_tolerance_is_refused() {
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    assert_rejected(challenge(&svc, &req, "close"));
}

#[test]
fn challenge_with_an_older_statement_is_refused() {
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    assert_rejected(challenge(&svc, &req, "older"));
    assert_rejected(challenge(&svc, &req, "request"));
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// A request at `st`'s price, checked by the treasury.
fn request(svc: &Service, st: &Statement) -> anyhow::Result<()> {
    let req = Request::from_statement(st);
    let (tx, utxos, leaf) = request_tx(svc, &req, req.usd_amount());
    svc.run(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(st)),
        &tx,
        &utxos,
        0,
    )
}

#[test]
fn a_certificate_bounds_the_timestamps_its_key_may_sign() {
    let svc = Service::new();
    let ts = statement("request").timestamp;
    let cert = |from, until| certify(&cold_key(), &oracle_key(), from, until);

    // Both ends are inclusive.
    request(&svc, &statement("request").with_cert(&cert(ts, ts))).unwrap();
    assert_rejected(request(
        &svc,
        &statement("request").with_cert(&cert(ts + 1, ts + 100)),
    ));
    assert_rejected(request(
        &svc,
        &statement("request").with_cert(&cert(ts - 100, ts - 1)),
    ));
}

#[test]
fn a_certificate_must_come_from_the_cold_key() {
    let svc = Service::new();
    let impostor = SecretKey::from_slice(&[0x13; 32]).unwrap();
    let cert = certify(&impostor, &oracle_key(), 0, u64::MAX);
    assert_rejected(request(&svc, &statement("request").with_cert(&cert)));
}

#[test]
fn a_certificate_only_covers_its_own_oracle_key() {
    // A genuine certificate for the second oracle, with a statement the first one signed.
    let svc = Service::new();
    let cert = certify(&cold_key(), &second_oracle_key(), 0, u64::MAX);
    assert_rejected(request(&svc, &statement("request").with_cert(&cert)));
}

#[test]
fn a_certificate_cannot_be_stretched() {
    let svc = Service::new();
    let ts = statement("request").timestamp;
    let mut cert = certify(&cold_key(), &oracle_key(), ts - 100, ts - 1);
    cert.valid_until = ts;
    assert_rejected(request(&svc, &statement("request").with_cert(&cert)));
}

#[test]
fn a_newly_certified_oracle_can_challenge_with_no_new_program() {
    // The first oracle signed the request. A second, certified afterwards, cancels it.
    let svc = Service::new();
    let req = Request::from_statement(&statement("request"));
    let newer = signed_by(
        &second_oracle_key(),
        "85231.50",
        SOURCES,
        "median",
        "1741514700",
        "1",
    )
    .with_cert(&certify(
        &cold_key(),
        &second_oracle_key(),
        1_741_514_600,
        1_741_514_600 + 30 * 86_400,
    ));
    challenge_with(&svc, &req, &newer).unwrap();
}

/// Zero words of budget padding, as the manifest's RequestMint and Challenge supply them.
const BUDGET_PAD: &str = "list![0, 0, 0, 0, 0, 0, 0, 0]";

#[test]
fn every_path_fits_its_budget() {
    // Finalizing checks the program's cost against the budget its witness buys, the check
    // the node makes. Unpadded, the request path fits by about 5 weight units at the time
    // of writing, so it carries BUDGET_PAD for margin; so does the challenge path.
    let svc = Service::new();
    let finalize =
        |leaf: &[u8], w: serde_json::Value, tx: &Transaction, utxos: &[TxOut], index: u32| {
            let mut input = lwk_wollet::elements::pset::Input::default();
            covenant::finalize_covenant_input(
                &svc.program,
                &svc.params,
                &svc.hints,
                &[leaf.to_vec()],
                Some(&w),
                None,
                Arc::new(tx.clone()),
                utxos,
                index,
                BlockHash::all_zeros(),
                ChainFamily::Elements,
                &mut input,
                false,
            )
        };

    let st = statement("request");
    let req = Request::from_statement(&st);
    let (tx, utxos, leaf) = request_tx(&svc, &req, req.usd_amount());
    finalize(
        &leaf,
        witnesses("Left(Left(()))", Some(&req), Some(&st)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();

    let (tx, utxos, leaf) = settle_tx(&svc, &req, WINDOW_BLOCKS, finalize_outputs(&req));
    finalize(
        &leaf,
        witnesses("Left(Right(()))", Some(&req), None),
        &tx,
        &utxos,
        0,
    )
    .unwrap();
    finalize(
        &leaf,
        witnesses("Right(Right(()))", None, None),
        &tx,
        &utxos,
        1,
    )
    .unwrap();

    let newer = statement("rose");
    let (treasury, _) = svc.treasury();
    let outputs = vec![
        txout(&req.recipient, LBTC, req.lbtc_amount),
        txout(&treasury, USD, req.usd_amount()),
        fee(500),
    ];
    let (tx, utxos, leaf) = settle_tx(&svc, &req, 0xffff_ffff, outputs);
    finalize(
        &leaf,
        witnesses("Right(Left(()))", Some(&req), Some(&newer)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();
}
