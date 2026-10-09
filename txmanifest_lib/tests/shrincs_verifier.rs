//! The vendored SHRINCS verifier, run through the wallet's own Bitcoin finalize path.
//!
//! Phase 0, task T1 (`meta/pq-phase0/t1-verifier-spike.md`). The program is upstream's
//! `examples/shrincs/shrincs_main.simf`, unmodified, as `examples/pq_shrincs_smoke/build.sh`
//! flattens it, and the witnesses are upstream's own `.wit` files. Unmodified means the message and the public key are witness data, so the
//! program reads nothing from the transaction and any spending transaction will do.
//!
//! What this establishes is that our SimplicityHL fork compiles it under the Bitcoin jet set,
//! and that satisfying, pruning against a real `BitcoinEnv` and padding all succeed — the
//! same calls a covenant spend makes.
//!
//! Task T2 adds `examples/pq_shrincs/shrincs_spend.simf`, the wrapper that pins the key in
//! `param::PK` and takes the message from `jet::sig_all_hash()`. Its tests are at the end.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lwk_wollet::elements::bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use simplicityhl::simplicity::{jet::Bitcoin, BitIter, Cost, RedeemNode};
use tx_manifest_lib::chain::ChainFamily;
use tx_manifest_lib::covenant::{
    bitcoin_covenant_sighash, compute_tapleaf_hash, finalize_bitcoin_covenant_input,
    program_witness_types, CompileOpts, ProgramSource,
};

fn verifier_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../contrib/shrincs-simplicity-verifier")
}

fn program() -> ProgramSource {
    ProgramSource::read_unpinned(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/pq_shrincs_smoke/shrincs_main.simf"),
    )
    .expect("read the flattened verifier; run examples/pq_shrincs_smoke/build.sh")
}

/// An upstream `.wit` file, as a manifest's `witnesses` map.
///
/// Upstream writes `{"NAME": {"type": <Simplicity type>, "value": …}}`. A manifest names
/// the kind of witness in `type` instead and takes the Simplicity type from the program.
fn upstream_witnesses(file: &str) -> serde_json::Value {
    let path = verifier_dir().join("upstream/examples/shrincs").join(file);
    let text = std::fs::read_to_string(&path).expect("read upstream witness file");
    let wit: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&text).expect("upstream witness file is JSON");
    let mut out = serde_json::Map::new();
    for (name, def) in wit {
        let value = def["value"]
            .as_str()
            .expect("witness value is a string")
            .to_owned();
        out.insert(
            name,
            serde_json::json!({ "type": "simplicityhl", "value": value }),
        );
    }
    serde_json::Value::Object(out)
}

/// A one-in, one-out transaction. The program reads nothing from it, but pruning needs an
/// environment, and an environment needs a transaction and the output it spends.
fn spend() -> (Transaction, Vec<TxOut>) {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: format!("{:064x}", 1).parse().expect("txid"),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0x42; 32]].concat()),
        }],
    };
    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0x07; 32]].concat()),
    };
    (tx, vec![prevout])
}

fn bitcoin() -> CompileOpts {
    CompileOpts {
        family: ChainFamily::Bitcoin,
        ..CompileOpts::default()
    }
}

/// Satisfy, prune and pad the verifier with `witnesses`, returning the witness stack.
fn finalize(witnesses: &serde_json::Value) -> anyhow::Result<Vec<Vec<u8>>> {
    let (tx, prevouts) = spend();
    finalize_bitcoin_covenant_input(
        &program(),
        &HashMap::new(),
        &HashMap::new(),
        &[],
        Some(witnesses),
        None,
        &tx,
        &prevouts,
        0,
        bitcoin(),
    )
}

/// The Simplicity signet node's acceptance rule for a Simplicity leaf spend, from
/// `src/script/interpreter.cpp` on delta1/bitcoin's `simplicity-inquisition` branch, the
/// node `contrib/regtest` builds.
///
/// The node reads the stack from the end: the control block, the CMR, the program, the
/// witness, and then an optional padding item, so padding comes *first* on the wire. The
/// program's cost bound must fit the budget the whole stack buys. When there is padding,
/// the cost must also *not* fit the budget the stack would buy with one byte less of it:
/// padding has to be minimal, or the spend fails with `SIMPLICITY_ERR_OVERWEIGHT`.
fn node_check(stack: &[Vec<u8>]) -> Result<Cost, String> {
    let n = stack.len();
    if !(4..=5).contains(&n) {
        return Err(format!(
            "{n} stack items; a Simplicity spend has 4, or 5 with padding"
        ));
    }
    // TAPROOT_CONTROL_BASE_SIZE + k * TAPROOT_CONTROL_NODE_SIZE, k ≤ 128.
    let control = &stack[n - 1];
    if control.len() < 33
        || control.len() > 33 + 128 * 32
        || !(control.len() - 33).is_multiple_of(32)
    {
        return Err(format!(
            "the last item ({} B) is not a control block, so the node cannot find the leaf",
            control.len()
        ));
    }
    let program = &stack[n - 3];
    let witness = &stack[n - 4];
    let padding = (n == 5).then(|| &stack[0]);
    if padding.is_some_and(|p| p.iter().any(|&b| b != 0)) {
        return Err("the first item is padding and must be all zeros".into());
    }

    let node = RedeemNode::decode::<_, _, Bitcoin>(
        BitIter::from(&program[..]),
        BitIter::from(&witness[..]),
    )
    .map_err(|e| format!("cannot decode the program: {e:?}"))?;
    let cost = node.bounds().cost;
    if !cost.is_budget_valid(stack) {
        return Err(format!("{cost:?} exceeds the budget the stack buys"));
    }
    if let Some(p) = padding {
        if !p.is_empty() {
            let mut shorter = stack.to_vec();
            shorter[0].pop();
            if cost.is_budget_valid(&shorter) {
                return Err(format!(
                    "{cost:?} fits the budget with one byte less padding ({} B), so the \
                     padding is not minimal",
                    p.len()
                ));
            }
        }
    }
    Ok(cost)
}

/// Item sizes of a finalized stack, for the record in the T1 task file.
fn describe(stack: &[Vec<u8>]) -> String {
    let mut names = vec!["witness", "program", "cmr", "control block"];
    if stack.len() == 5 {
        names.insert(0, "padding");
    }
    let parts: Vec<String> = stack
        .iter()
        .enumerate()
        .map(|(i, item)| format!("{} {} B", names.get(i).unwrap_or(&"?"), item.len()))
        .collect();
    let total: usize = stack.iter().map(Vec::len).sum();
    format!("{} (items total {total} B)", parts.join(", "))
}

/// Finalize with an upstream witness file, then hold the stack to the node's rules.
fn spend_with(file: &str) {
    let stack = finalize(&upstream_witnesses(file))
        .unwrap_or_else(|e| panic!("{file} should verify: {e:#}"));
    eprintln!("{file}: {}", describe(&stack));
    match node_check(&stack) {
        Ok(cost) => eprintln!("{file}: the node would accept it; cost bound {cost:?}"),
        Err(why) => panic!("{file}: the node would reject this spend: {why}"),
    }
}

#[test]
fn stateful_signature_verifies() {
    spend_with("shrincs_main_stateful.wit");
}

#[test]
fn stateless_signature_verifies() {
    spend_with("shrincs_main_stateless.wit");
}

/// The negative control: without it, a verifier that accepted everything would pass both
/// tests above.
#[test]
fn tampered_signature_is_rejected() {
    let mut witnesses = upstream_witnesses("shrincs_main_stateful.wit");
    let proof = witnesses["PROOF"]["value"]
        .as_str()
        .expect("PROOF value")
        .to_owned();
    // The proof opens `(msg, (PK.seed, PK.root), …)`, and upstream signs the message 0.
    // Signing 1 instead changes the digest every later check depends on.
    let tampered = proof.replacen("(0, (", "(1, (", 1);
    assert_ne!(
        tampered, proof,
        "the message should be the proof's first field"
    );
    witnesses["PROOF"]["value"] = serde_json::Value::String(tampered);

    let err = finalize(&witnesses).expect_err("a signature over another message must fail");
    eprintln!("tampered: {err:#}");
}

// ── T2: the wrapper ──────────────────────────────────────────────────────────

fn wrapper() -> ProgramSource {
    ProgramSource::read_unpinned(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/pq_shrincs/shrincs_spend.simf"),
    )
    .expect("read the flattened wrapper; run examples/pq_shrincs/build.sh")
}

/// Upstream's example key, `PK.seed || PK.root`, from `shrincs_main_stateful.wit`.
const UPSTREAM_PK: &str = "0xb635ef10af1b120cec1095d7745fec060f8fbe02641f3479bd3131c0d5253926";

/// The spender supplies the signature and nothing else: no key, no message. A witness
/// named here that the program also took as a param would be the anyone-can-spend hole
/// this wrapper exists to close.
#[test]
fn wrapper_takes_only_the_signature_as_witness() {
    let types = program_witness_types(&wrapper(), bitcoin()).expect("wrapper compiles");
    let names: Vec<&str> = types.keys().map(String::as_str).collect();
    assert_eq!(names, ["OTHER_ROOT", "SIG"]);
}

/// The key goes in as one 32-byte `bytes32` param, and different keys give different
/// leaves, so each key has its own address.
#[test]
fn wrapper_commits_to_the_key() {
    let leaf = |pk: &str| {
        let params = HashMap::from([("PK".to_string(), pk.to_string())]);
        let hints = HashMap::from([("PK".to_string(), "bytes32".to_string())]);
        compute_tapleaf_hash(&wrapper(), &params, &hints, bitcoin())
            .unwrap_or_else(|e| panic!("wrapper compiles with PK={pk}: {e:#}"))
    };
    let other = "0x0000000000000000000000000000000000000000000000000000000000000001";
    assert_ne!(leaf(UPSTREAM_PK), leaf(other));
}

// ── T2 + T3: a real SHRINCS-locked spend ─────────────────────────────────────

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/shrincs")
        .join(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The public key of `fixtures/shrincs/test_seed.hex`, as
/// `contrib/shrincs-signer/bin/shrincs-signer pubkey` prints it.
const TEST_PK: &str = "0x202122232425262728292a2b2c2d2e2fdacfe7d7b4009ca34156124d54de2e72";

/// A coin locked by the wrapper to the test key, spent with a stateful signature (q = 1)
/// from `contrib/shrincs-signer` over the test transaction's `sig_all_hash`.
///
/// The signature is a fixture, so the test needs no C++ toolchain. To regenerate it, take
/// the sighash this test reports and run, with a fresh state file at q = 0:
///
/// ```text
/// printf '0\n' > /tmp/q.txt
/// contrib/shrincs-signer/bin/shrincs-signer sign \
///   --seed txmanifest_lib/tests/fixtures/shrincs/test_seed.hex --state /tmp/q.txt --msg <sighash>
/// ```
///
/// then put `msg`, `SIG` and `OTHER_ROOT` in `fixtures/shrincs/spend_q1.json`.
#[test]
fn signed_spend_of_a_shrincs_locked_coin() {
    let text = std::fs::read_to_string(fixture("spend_q1.json")).expect("read the fixture");
    let signed: serde_json::Value = serde_json::from_str(&text).expect("fixture is JSON");
    let params = HashMap::from([("PK".to_string(), TEST_PK.to_string())]);
    let hints = HashMap::from([("PK".to_string(), "bytes32".to_string())]);
    let witnesses = serde_json::json!({
        "SIG": { "type": "simplicityhl", "value": signed["SIG"] },
        "OTHER_ROOT": { "type": "simplicityhl", "value": signed["OTHER_ROOT"] },
    });
    let finalize_wrapper = |tx: &Transaction, prevouts: &[TxOut]| {
        finalize_bitcoin_covenant_input(
            &wrapper(),
            &params,
            &hints,
            &[],
            Some(&witnesses),
            None,
            tx,
            prevouts,
            0,
            bitcoin(),
        )
    };

    let (tx, prevouts) = spend();
    let hash = bitcoin_covenant_sighash(
        &wrapper(),
        &params,
        &hints,
        &[],
        &tx,
        &prevouts,
        0,
        bitcoin(),
    )
    .expect("compute the sighash");
    assert_eq!(
        signed["msg"].as_str(),
        Some(hex(&hash).as_str()),
        "the fixture signs another message; regenerate it (see this test's doc comment)"
    );

    let stack = finalize_wrapper(&tx, &prevouts)
        .unwrap_or_else(|e| panic!("the signed spend should verify: {e:#}"));
    eprintln!("signed spend: {}", describe(&stack));
    match node_check(&stack) {
        Ok(cost) => eprintln!("signed spend: the node would accept it; cost bound {cost:?}"),
        Err(why) => panic!("the node would reject the signed spend: {why}"),
    }

    // The signature covers this transaction: moved to one that pays a sat less, it fails.
    let mut other = tx.clone();
    other.output[0].value = Amount::from_sat(other.output[0].value.to_sat() - 1);
    assert!(
        finalize_wrapper(&other, &prevouts).is_err(),
        "a signature over one transaction must not spend another"
    );
}
