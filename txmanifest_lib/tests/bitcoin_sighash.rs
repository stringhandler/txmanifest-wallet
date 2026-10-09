//! `bitcoin_covenant_sighash` returns exactly the hash `jet::sig_all_hash` gives the
//! program, which is what `run --print-sighash` relies on.
//!
//! The check is end to end, through `examples/bitcoin_covenant/p2pk.simf`, a BIP340
//! checksig over `sig_all_hash`. Sign the computed hash outside the wallet, pass the
//! signature in as a plain literal witness rather than a `Signature` the engine computes,
//! and the program has to accept it.

use std::collections::HashMap;
use std::path::Path;

use lwk_wollet::elements::bitcoin::{
    absolute::LockTime,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use tx_manifest_lib::chain::ChainFamily;
use tx_manifest_lib::covenant::{
    bitcoin_covenant_sighash, finalize_bitcoin_covenant_input, CompileOpts, ProgramSource,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bitcoin() -> CompileOpts {
    CompileOpts {
        family: ChainFamily::Bitcoin,
        ..CompileOpts::default()
    }
}

/// A one-in, one-out spend paying `value` sat.
fn spend(value: u64) -> (Transaction, Vec<TxOut>) {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: format!("{:064x}", 7).parse().expect("txid"),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0x42; 32]].concat()),
        }],
    };
    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0x07; 32]].concat()),
    };
    (tx, vec![prevout])
}

#[test]
fn a_signature_over_the_computed_sighash_satisfies_the_program() {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[0x11; 32]).expect("secret key"),
    );
    let (pubkey, _) = keypair.x_only_public_key();

    let program = ProgramSource::read_unpinned(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/bitcoin_covenant/p2pk.simf"),
    )
    .expect("read p2pk.simf");
    let params = HashMap::from([("PUB_KEY".to_string(), hex(&pubkey.serialize()))]);
    let hints = HashMap::from([("PUB_KEY".to_string(), "pubkey".to_string())]);

    let finalize = |tx: &Transaction, prevouts: &[TxOut], sig: &str| {
        let witnesses = serde_json::json!({
            "SIGNATURE": { "type": "simplicityhl", "value": format!("0x{sig}") }
        });
        finalize_bitcoin_covenant_input(
            &program,
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

    // The first run: compute the hash and sign it, as an outside signer would.
    let (tx, prevouts) = spend(90_000);
    let hash =
        bitcoin_covenant_sighash(&program, &params, &hints, &[], &tx, &prevouts, 0, bitcoin())
            .expect("compute the sighash");
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), &keypair);
    let sig = hex(sig.as_ref());

    // The second run rebuilds the same transaction, so the signature verifies.
    finalize(&tx, &prevouts, &sig)
        .unwrap_or_else(|e| panic!("a signature over the computed hash should verify: {e:#}"));

    // A transaction that differs by one sat has another hash, so the same signature fails.
    // This is why the second run has to rebuild the first run's transaction exactly.
    let (other, prevouts) = spend(89_999);
    assert!(
        finalize(&other, &prevouts, &sig).is_err(),
        "the signature must be bound to the transaction it was made for"
    );
}
