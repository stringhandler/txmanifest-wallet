//! Runs the oracle-liquidation paths of `examples/lending_v4/lending.simf` on the
//! BitMachine, against transactions built here, with statements signed by
//! `examples/oracle_demo`'s example oracle key and certified by its example cold key.
//!
//! The loan: 3,000 sat of L-BTC against 1.5 tUSDT at 1%, a debt of 151,500,000 base units.
//! At an 80% loan-to-value it may be liquidated below $63,125.00.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use lwk_wollet::elements::confidential::{Asset, Nonce, Value};
use lwk_wollet::elements::hashes::{sha256, Hash, HashEngine};
use lwk_wollet::elements::secp256k1_zkp::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
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
/// Stand-ins for tUSDT and the loan's two NFTs.
const USD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BORROWER_NFT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LENDER_NFT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

const COLLATERAL: u64 = 3_000;
const PRINCIPAL: u64 = 150_000_000;
const DEBT: u64 = 151_500_000;
const PROTOCOL_FEE: u64 = 150_000;
const WINDOW_BLOCKS: u32 = 5;
const MAX_FUTURE_SECONDS: u32 = 300;
const ENABLE_LOCKTIME: u32 = 0xffff_fffe;
const NOW: u64 = 1_792_660_000;
const SOURCES: &str = "binance,bitstamp,coinbase,kraken,okx";
const BUDGET_PAD: &str = "list![0, 0, 0, 0, 0, 0, 0, 0]";

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn simf_list(text: &str) -> String {
    let bytes: Vec<String> = text.bytes().map(|b| b.to_string()).collect();
    format!("list![{}]", bytes.join(", "))
}

fn secret(file: &str) -> SecretKey {
    let raw: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(examples().join("oracle_demo/data").join(file)).unwrap(),
    )
    .unwrap();
    SecretKey::from_str(raw["secret"].as_str().unwrap()).unwrap()
}

fn oracle_key() -> SecretKey {
    secret("example_oracle_key.json")
}

fn cold_key() -> SecretKey {
    secret("example_cold_key.json")
}

/// Scripts whose hashes stand in for the loan's covenant hashes, so outputs can pay them.
fn p2tr(n: u8) -> Script {
    Script::from([&[0x51, 0x20][..], &[n; 32]].concat())
}

fn script_hash(script: &Script) -> String {
    hex(&sha256::Hash::hash(script.as_bytes()).to_byte_array())
}

const LENDER_VAULT: u8 = 0x31;
const FINALIZED_LENDER_VAULT: u8 = 0x32;
const PROTOCOL_FEE_VAULT: u8 = 0x33;
const FINALIZED_PROTOCOL_FEE_VAULT: u8 = 0x34;

/// A certified statement split into the witnesses the program reads.
struct Statement {
    price_cents: u64,
    timestamp: u64,
    witnesses: Vec<(&'static str, String)>,
}

/// The example oracle signs a BTC/USD statement at `price` and `timestamp`, and the example
/// cold key certifies it for a day either side.
fn statement(price: &str, timestamp: u64) -> Statement {
    let canonical = format!("v1|PRICE|BTCUSD|{price}|USD|2|{SOURCES}|median|{timestamp}|1");
    let secp = Secp256k1::new();
    let digest = sha256::Hash::hash(canonical.as_bytes()).to_byte_array();
    let sig = secp
        .sign_ecdsa(&Message::from_digest_slice(&digest).unwrap(), &oracle_key())
        .serialize_compact();

    let oracle_pubkey = PublicKey::from_secret_key(&secp, &oracle_key()).serialize();
    let (valid_from, valid_until) = (timestamp - 86_400, timestamp + 86_400);
    let tag = sha256::Hash::hash(b"oracle-demo/oracle-cert/v1");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_ref());
    engine.input(tag.as_ref());
    engine.input(&oracle_pubkey);
    engine.input(&valid_from.to_be_bytes());
    engine.input(&valid_until.to_be_bytes());
    let cert_msg = Message::from_digest_slice(sha256::Hash::from_engine(engine).as_ref()).unwrap();
    let cert_sig =
        secp.sign_schnorr_no_aux_rand(&cert_msg, &Keypair::from_secret_key(&secp, &cold_key()));

    let (integer, fraction) = price.split_once('.').unwrap();
    let frac = fraction.as_bytes();
    Statement {
        price_cents: format!("{integer}{fraction}").parse().unwrap(),
        timestamp,
        witnesses: vec![
            ("STATEMENT_PRICE_INT", simf_list(integer)),
            (
                "STATEMENT_PRICE_FRAC",
                format!("({}, {})", frac[0], frac[1]),
            ),
            ("STATEMENT_SOURCES", simf_list(SOURCES)),
            ("STATEMENT_METHOD", simf_list("median")),
            ("STATEMENT_TIMESTAMP", simf_list(&timestamp.to_string())),
            ("STATEMENT_NONCE", simf_list("1")),
            (
                "STATEMENT_SIG",
                format!("(0x{}, 0x{})", hex(&sig[..32]), hex(&sig[32..])),
            ),
            (
                "CERT_ORACLE_KEY",
                format!("({}, 0x{})", oracle_pubkey[0], hex(&oracle_pubkey[1..])),
            ),
            ("CERT_VALID_FROM", valid_from.to_string()),
            ("CERT_VALID_UNTIL", valid_until.to_string()),
            ("CERT_SIG", format!("0x{}", hex(cert_sig.as_ref()))),
        ],
    }
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

/// Witnesses for one input: `PATH` (lending_v3's paths) or `LIQUIDATION`, and a statement
/// for the paths that check one.
fn witnesses(
    path: Option<&str>,
    liquidation: Option<&str>,
    st: Option<&Statement>,
) -> serde_json::Value {
    let value = |v: &str| json!({ "type": "simplicityhl", "value": v });
    let mut map = serde_json::Map::new();
    map.insert("PATH".into(), path.map_or(json!("unused"), value));
    map.insert(
        "LIQUIDATION".into(),
        liquidation.map_or(json!("unused"), |l| value(&format!("Some({l})"))),
    );
    for name in STATEMENT_WITNESSES {
        let w = st
            .and_then(|s| s.witnesses.iter().find(|(n, _)| *n == name))
            .map_or(json!("unused"), |(_, v)| value(v));
        map.insert(name.into(), w);
    }
    map.insert(
        "BUDGET_PAD".into(),
        st.map_or(json!("unused"), |_| value(BUDGET_PAD)),
    );
    serde_json::Value::Object(map)
}

/// The loan, compiled once per test.
struct Loan {
    program: ProgramSource,
    params: HashMap<String, String>,
    hints: HashMap<String, String>,
}

impl Loan {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let (cold_pubkey, _) = cold_key().x_only_public_key(&secp);
        let mut params = HashMap::new();
        let mut hints = HashMap::new();
        let mut set = |name: &str, value: String, hint: &str| {
            params.insert(name.to_string(), value);
            hints.insert(name.to_string(), hint.to_string());
        };
        set("COLLATERAL_ASSET_ID", LBTC.into(), "liquid.asset_id");
        set("PRINCIPAL_ASSET_ID", USD.into(), "liquid.asset_id");
        set(
            "BORROWER_NFT_ASSET_ID",
            BORROWER_NFT.into(),
            "liquid.asset_id",
        );
        set("LENDER_NFT_ASSET_ID", LENDER_NFT.into(), "liquid.asset_id");
        set("COLLATERAL_AMOUNT", COLLATERAL.to_string(), "u64");
        set("PRINCIPAL_AMOUNT", PRINCIPAL.to_string(), "u64");
        set("PRINCIPAL_INTEREST_RATE", "100".into(), "u64");
        set("LOAN_EXPIRATION_TIME", "3000000".into(), "u32");
        set(
            "LENDER_VAULT_COV_HASH",
            script_hash(&p2tr(LENDER_VAULT)),
            "bytes32",
        );
        set(
            "FINALIZED_LENDER_VAULT_COV_HASH",
            script_hash(&p2tr(FINALIZED_LENDER_VAULT)),
            "bytes32",
        );
        set(
            "PROTOCOL_FEE_VAULT_COV_HASH",
            script_hash(&p2tr(PROTOCOL_FEE_VAULT)),
            "bytes32",
        );
        set(
            "FINALIZED_PROTOCOL_FEE_VAULT_COV_HASH",
            script_hash(&p2tr(FINALIZED_PROTOCOL_FEE_VAULT)),
            "bytes32",
        );
        set(
            "PRINCIPAL_OUTPUT_SCRIPT_HASH",
            script_hash(&p2tr(0x35)),
            "bytes32",
        );
        set("COLD_PUBKEY", hex(&cold_pubkey.serialize()), "pubkey");
        set("MAX_FUTURE_SECONDS", MAX_FUTURE_SECONDS.to_string(), "u32");
        set("LIQUIDATION_LTV_BPS", "8000".into(), "u64");
        set("WINDOW_BLOCKS", WINDOW_BLOCKS.to_string(), "u16");
        Self {
            program: ProgramSource::read_unpinned(examples().join("lending_v4/lending.simf"))
                .unwrap(),
            params,
            hints,
        }
    }

    /// Slot 0 for the active state, and for a pending liquidation of `(timestamp, price)`.
    fn active_slot() -> Vec<u8> {
        let mut slot = vec![0; 32];
        slot[31] = 1;
        slot
    }

    fn pending_slot(claim: (u64, u64)) -> Vec<u8> {
        let mut slot = Vec::new();
        slot.extend(claim.0.to_be_bytes());
        slot.extend(claim.1.to_be_bytes());
        slot.extend(0u64.to_be_bytes());
        slot.extend(2u64.to_be_bytes());
        slot
    }

    fn leaves(slot0: Vec<u8>) -> [Vec<u8>; 2] {
        let mut debt = vec![0; 24];
        debt.extend(DEBT.to_be_bytes());
        [slot0, debt]
    }

    fn script(&self, slot0: Vec<u8>) -> Script {
        covenant::compute_covenant_address(
            &self.program,
            &self.params,
            &self.hints,
            &Self::leaves(slot0),
            ElementsNetwork::LiquidTestnet,
            true,
        )
        .unwrap()
        .script_pubkey()
    }

    fn run(
        &self,
        slot0: Vec<u8>,
        witnesses: serde_json::Value,
        tx: &Transaction,
        utxos: &[TxOut],
        index: u32,
    ) -> anyhow::Result<()> {
        covenant::dry_run_covenant(
            &self.program,
            &self.params,
            &self.hints,
            &Self::leaves(slot0),
            Some(&witnesses),
            None,
            Arc::new(tx.clone()),
            utxos,
            index,
            BlockHash::all_zeros(),
            ChainFamily::Elements,
            false,
            true,
        )
    }

    /// Finalize, which also checks the program's cost against its witness's budget.
    fn finalize(
        &self,
        slot0: Vec<u8>,
        witnesses: serde_json::Value,
        tx: &Transaction,
        utxos: &[TxOut],
        index: u32,
    ) -> anyhow::Result<()> {
        let mut input = lwk_wollet::elements::pset::Input::default();
        covenant::finalize_covenant_input(
            &self.program,
            &self.params,
            &self.hints,
            &Self::leaves(slot0),
            Some(&witnesses),
            None,
            Arc::new(tx.clone()),
            utxos,
            index,
            BlockHash::all_zeros(),
            ChainFamily::Elements,
            &mut input,
            true,
        )
    }
}

/// Assert that the program ran and refused the spend, rather than failing before it ran.
fn assert_rejected(result: anyhow::Result<()>) {
    let err = format!("{:#}", result.expect_err("the spend was accepted"));
    assert!(
        err.contains("satisfaction failed") || err.contains("execution failed"),
        "failed before the program ran: {err}"
    );
}

fn txout(script: &Script, asset: &str, amount: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(AssetId::from_str(asset).unwrap()),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: script.clone(),
        witness: TxOutWitness::default(),
    }
}

fn wallet() -> Script {
    Script::from(Vec::from_iter([0x00, 0x14].into_iter().chain([0x77; 20])))
}

fn burn(asset: &str, amount: u64) -> TxOut {
    txout(&Script::from(vec![0x6a]), asset, amount)
}

fn fee() -> TxOut {
    TxOut::new_fee(500, AssetId::from_str(LBTC).unwrap())
}

fn build_tx(sequences: &[u32], lock_time: u32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(lock_time),
        input: sequences
            .iter()
            .enumerate()
            .map(|(n, &sequence)| TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([n as u8 + 1; 32]), 0),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence(sequence),
                asset_issuance: AssetIssuance::default(),
                witness: TxInWitness::default(),
            })
            .collect(),
        output: outputs,
    }
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

fn claim_of(st: &Statement) -> (u64, u64) {
    (st.timestamp, st.price_cents)
}

/// A start transaction for `st`: the active loan and the lender NFT in, the pending loan
/// at `claim` and the NFT out, locked at the earliest time the statement allows.
fn start_tx(loan: &Loan, st: &Statement, claim: (u64, u64)) -> (Transaction, Vec<TxOut>) {
    let tx = build_tx(
        &[ENABLE_LOCKTIME; 3],
        (st.timestamp - MAX_FUTURE_SECONDS as u64) as u32,
        vec![
            txout(&loan.script(Loan::pending_slot(claim)), LBTC, COLLATERAL),
            txout(&wallet(), LENDER_NFT, 1),
            txout(&wallet(), LBTC, 9_500),
            fee(),
        ],
    );
    let utxos = vec![
        txout(&loan.script(Loan::active_slot()), LBTC, COLLATERAL),
        txout(&wallet(), LENDER_NFT, 1),
        txout(&wallet(), LBTC, 10_000),
    ];
    (tx, utxos)
}

fn start(loan: &Loan, st: &Statement, tx: &Transaction, utxos: &[TxOut]) -> anyhow::Result<()> {
    let step = format!("Left(Left({DEBT}))");
    loan.run(
        Loan::active_slot(),
        witnesses(None, Some(&step), Some(st)),
        tx,
        utxos,
        0,
    )
}

#[test]
fn a_lender_starts_a_liquidation_at_a_crashed_price() {
    let loan = Loan::new();
    let st = statement("60000.00", NOW);
    let (tx, utxos) = start_tx(&loan, &st, claim_of(&st));
    start(&loan, &st, &tx, &utxos).unwrap();
}

#[test]
fn a_liquidation_starts_only_below_the_threshold() {
    // 3,000 sat at $63,125.00 is worth 189,375,000, and 80% of that is exactly the debt.
    let loan = Loan::new();
    for (price, liquidatable) in [("63124.99", true), ("63125.00", false), ("84231.50", false)] {
        let st = statement(price, NOW);
        let (tx, utxos) = start_tx(&loan, &st, claim_of(&st));
        let result = start(&loan, &st, &tx, &utxos);
        if liquidatable {
            result.unwrap();
        } else {
            assert_rejected(result);
        }
    }
}

#[test]
fn a_liquidation_needs_the_lender_nft_shown_and_kept() {
    let loan = Loan::new();
    let st = statement("60000.00", NOW);

    let (tx, mut utxos) = start_tx(&loan, &st, claim_of(&st));
    utxos[1] = txout(&wallet(), BORROWER_NFT, 1);
    assert_rejected(start(&loan, &st, &tx, &utxos));

    let (mut tx, utxos) = start_tx(&loan, &st, claim_of(&st));
    tx.output[1] = txout(&wallet(), LBTC, 1);
    assert_rejected(start(&loan, &st, &tx, &utxos));
}

#[test]
fn a_liquidation_records_the_claim_it_was_started_with() {
    let loan = Loan::new();
    let st = statement("60000.00", NOW);
    let (tx, utxos) = start_tx(&loan, &st, (st.timestamp, st.price_cents + 1));
    assert_rejected(start(&loan, &st, &tx, &utxos));
}

#[test]
fn a_liquidation_statement_cannot_be_dated_ahead_of_its_lock_time() {
    let loan = Loan::new();
    let st = statement("60000.00", NOW);
    let (mut tx, utxos) = start_tx(&loan, &st, claim_of(&st));
    tx.lock_time = LockTime::from_consensus(tx.lock_time.to_consensus_u32() - 1);
    assert_rejected(start(&loan, &st, &tx, &utxos));
}

// ---------------------------------------------------------------------------
// Cancel, finish, repay
// ---------------------------------------------------------------------------

/// The claim a liquidation was started with: a crash to $60,000 at NOW.
fn pending_claim() -> (u64, u64) {
    (NOW, 6_000_000)
}

fn claim_step(kind: &str) -> String {
    let (ts, price) = pending_claim();
    format!("{kind}(({DEBT}, ({ts}, {price})))")
}

fn cancel(loan: &Loan, newer: &Statement, active_output: bool) -> anyhow::Result<()> {
    let to = match active_output {
        true => loan.script(Loan::active_slot()),
        false => wallet(),
    };
    let tx = build_tx(
        &[0xffff_ffff, 0xffff_ffff],
        0,
        vec![
            txout(&to, LBTC, COLLATERAL),
            txout(&wallet(), LBTC, 9_500),
            fee(),
        ],
    );
    let utxos = vec![
        txout(
            &loan.script(Loan::pending_slot(pending_claim())),
            LBTC,
            COLLATERAL,
        ),
        txout(&wallet(), LBTC, 10_000),
    ];
    let step = format!("Left({})", claim_step("Right"));
    loan.run(
        Loan::pending_slot(pending_claim()),
        witnesses(None, Some(&step), Some(newer)),
        &tx,
        &utxos,
        0,
    )
}

#[test]
fn a_newer_price_at_which_the_loan_is_fine_cancels_the_liquidation() {
    let loan = Loan::new();
    cancel(&loan, &statement("84231.50", NOW + 60), true).unwrap();
}

#[test]
fn a_liquidation_is_not_cancelled_by_a_price_that_still_justifies_it() {
    let loan = Loan::new();
    assert_rejected(cancel(&loan, &statement("61000.00", NOW + 60), true));
}

#[test]
fn a_liquidation_is_not_cancelled_by_an_older_statement() {
    let loan = Loan::new();
    assert_rejected(cancel(&loan, &statement("84231.50", NOW - 60), true));
    assert_rejected(cancel(&loan, &statement("84231.50", NOW), true));
}

#[test]
fn a_cancel_returns_the_loan_to_active() {
    let loan = Loan::new();
    assert_rejected(cancel(&loan, &statement("84231.50", NOW + 60), false));
}

fn finish_tx(loan: &Loan, sequence: u32, burned: TxOut) -> (Transaction, Vec<TxOut>) {
    let tx = build_tx(
        &[sequence, 0xffff_ffff, 0xffff_ffff],
        0,
        vec![
            burned,
            txout(&wallet(), LBTC, COLLATERAL),
            txout(&wallet(), LBTC, 9_500),
            fee(),
        ],
    );
    let utxos = vec![
        txout(
            &loan.script(Loan::pending_slot(pending_claim())),
            LBTC,
            COLLATERAL,
        ),
        txout(&wallet(), LENDER_NFT, 1),
        txout(&wallet(), LBTC, 10_000),
    ];
    (tx, utxos)
}

fn finish(loan: &Loan, tx: &Transaction, utxos: &[TxOut]) -> anyhow::Result<()> {
    let step = format!("Right({})", claim_step("Left"));
    loan.run(
        Loan::pending_slot(pending_claim()),
        witnesses(None, Some(&step), None),
        tx,
        utxos,
        0,
    )
}

#[test]
fn the_lender_takes_the_collateral_after_the_window() {
    let loan = Loan::new();
    let (tx, utxos) = finish_tx(&loan, WINDOW_BLOCKS, burn(LENDER_NFT, 1));
    finish(&loan, &tx, &utxos).unwrap();
}

#[test]
fn a_liquidation_waits_for_the_window() {
    let loan = Loan::new();
    let (tx, utxos) = finish_tx(&loan, WINDOW_BLOCKS - 1, burn(LENDER_NFT, 1));
    assert_rejected(finish(&loan, &tx, &utxos));
}

#[test]
fn finishing_burns_the_lender_nft() {
    let loan = Loan::new();
    let (tx, utxos) = finish_tx(&loan, WINDOW_BLOCKS, txout(&wallet(), LENDER_NFT, 1));
    assert_rejected(finish(&loan, &tx, &utxos));
}

/// A full repayment: the borrower NFT (input 0) burned, the loan (input 1), the repayment
/// (input 2); the lender's and the protocol's shares to their finalized vaults.
fn repay_tx(loan_script: Script) -> (Transaction, Vec<TxOut>) {
    let tx = build_tx(
        &[0xffff_ffff; 4],
        0,
        vec![
            burn(BORROWER_NFT, 1),
            txout(&p2tr(FINALIZED_LENDER_VAULT), USD, DEBT - PROTOCOL_FEE),
            txout(&p2tr(FINALIZED_PROTOCOL_FEE_VAULT), USD, PROTOCOL_FEE),
            txout(&wallet(), LBTC, COLLATERAL),
            txout(&wallet(), LBTC, 9_500),
            fee(),
        ],
    );
    let utxos = vec![
        txout(&wallet(), BORROWER_NFT, 1),
        txout(&loan_script, LBTC, COLLATERAL),
        txout(&wallet(), USD, DEBT),
        txout(&wallet(), LBTC, 10_000),
    ];
    (tx, utxos)
}

#[test]
fn the_borrower_can_repay_while_a_liquidation_is_pending() {
    let loan = Loan::new();
    let pending = Loan::pending_slot(pending_claim());
    let (tx, utxos) = repay_tx(loan.script(pending.clone()));
    let step = format!("Right({})", claim_step("Right"));
    loan.run(
        pending.clone(),
        witnesses(None, Some(&step), None),
        &tx,
        &utxos,
        1,
    )
    .unwrap();

    // lending_v3's repayment path still works on an active loan, and only there.
    let full_repayment = format!("Right(Left(Right({DEBT})))");
    let (tx, utxos) = repay_tx(loan.script(Loan::active_slot()));
    loan.run(
        Loan::active_slot(),
        witnesses(Some(&full_repayment), None, None),
        &tx,
        &utxos,
        1,
    )
    .unwrap();
    let (tx, utxos) = repay_tx(loan.script(pending.clone()));
    assert_rejected(loan.run(
        pending,
        witnesses(Some(&full_repayment), None, None),
        &tx,
        &utxos,
        1,
    ));
}

#[test]
fn every_liquidation_path_fits_its_budget() {
    let loan = Loan::new();

    let st = statement("60000.00", NOW);
    let (tx, utxos) = start_tx(&loan, &st, claim_of(&st));
    let step = format!("Left(Left({DEBT}))");
    loan.finalize(
        Loan::active_slot(),
        witnesses(None, Some(&step), Some(&st)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();

    let newer = statement("84231.50", NOW + 60);
    let tx = build_tx(
        &[0xffff_ffff, 0xffff_ffff],
        0,
        vec![
            txout(&loan.script(Loan::active_slot()), LBTC, COLLATERAL),
            txout(&wallet(), LBTC, 9_500),
            fee(),
        ],
    );
    let utxos = vec![
        txout(
            &loan.script(Loan::pending_slot(pending_claim())),
            LBTC,
            COLLATERAL,
        ),
        txout(&wallet(), LBTC, 10_000),
    ];
    let step = format!("Left({})", claim_step("Right"));
    loan.finalize(
        Loan::pending_slot(pending_claim()),
        witnesses(None, Some(&step), Some(&newer)),
        &tx,
        &utxos,
        0,
    )
    .unwrap();

    let (tx, utxos) = finish_tx(&loan, WINDOW_BLOCKS, burn(LENDER_NFT, 1));
    let step = format!("Right({})", claim_step("Left"));
    loan.finalize(
        Loan::pending_slot(pending_claim()),
        witnesses(None, Some(&step), None),
        &tx,
        &utxos,
        0,
    )
    .unwrap();
}
