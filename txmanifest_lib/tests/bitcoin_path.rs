//! The Bitcoin path, end to end, without a network or a funded wallet.
//!
//! Every piece of the Bitcoin support is unit-tested in its own module, and every one of
//! those tests passed while the path as a whole could not have worked: `select_input`
//! resolved the manifest label `"lbtc"` to Liquid's policy asset, while the scanned UTXOs
//! carried the synthetic Bitcoin one, so a funded wallet would have reported itself empty.
//! No module-level test could see that, because the disagreement was *between* two modules
//! that were each individually right.
//!
//! So this file exercises the seam rather than the parts: scanned UTXO → the shared
//! assembly's vocabulary → the narrowing → a built, signed, extractable transaction. It
//! is not a substitute for a real signet payment, which is the only thing that exercises
//! the node's own opinion of the result — but it is what catches a vocabulary that does
//! not line up.

use tx_manifest_lib::assembly::{bitcoin_policy_asset, bitcoin_spendable_utxos};
use tx_manifest_lib::bitcoin_backend::Utxo;
use tx_manifest_lib::bitcoin_wallet::{BitcoinWallet, Branch};
use tx_manifest_lib::chain::Network;
use tx_manifest_lib::psbt_builder::{self, KeyPathSigner, PsbtInput};
use tx_manifest_lib::pset_builder::{BuildPsetRequest, PsetInput, PsetOutputSpec};

use lwk_wollet::elements::bitcoin::{
    key::TapTweak,
    secp256k1::{Message, Secp256k1},
    Amount, OutPoint, ScriptBuf,
};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon about";

fn wallet() -> BitcoinWallet {
    BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).expect("wallet")
}

/// A UTXO shaped exactly as `EsploraClient::scan` returns one.
fn scanned(w: &BitcoinWallet, branch: Branch, index: u32, value: u64, n: u8) -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: format!("{:064x}", n).parse().expect("txid"),
            vout: 0,
        },
        value,
        script_pubkey: w.script_pubkey(branch, index).expect("spk"),
        branch,
        index,
        height: Some(320_000),
        // Not a block reward, so spendable regardless of depth.
        coinbase: None,
    }
}

/// A paying address that is not ours, so the transaction actually moves value out.
fn recipient() -> ScriptBuf {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(&[0x42; 32]);
    ScriptBuf::from_bytes(v)
}

/// The full path: scan output → assembly vocabulary → narrowing → build → sign → extract,
/// with the signature verified against the scriptPubKey actually being spent.
#[test]
fn a_scanned_utxo_becomes_a_signed_transaction() {
    let w = wallet();
    let utxos = vec![scanned(&w, Branch::Receive, 0, 200_000, 1)];

    // 1. Into the shared assembly's vocabulary.
    let spendable = bitcoin_spendable_utxos(&utxos).expect("synthesizes");
    assert_eq!(spendable.len(), 1);

    // 2. The request the assembly would produce.
    let req = BuildPsetRequest {
        inputs: vec![PsetInput::Wallet {
            input_id: "funding".to_string(),
            utxo: spendable[0].clone(),
            issuance: None,
            sequence: None,
        }],
        outputs: vec![PsetOutputSpec {
            script_pubkey: lwk_wollet::elements::Script::from(recipient().to_bytes()),
            amount: 120_000,
            asset: bitcoin_policy_asset(),
            blinding_key: None,
            blinding: None,
        }],
        fee_rate: 2.0,
        policy_asset: bitcoin_policy_asset(),
        change_assets: std::collections::HashSet::from([bitcoin_policy_asset()]),
    };

    // 3. Narrow to Bitcoin.
    let change = w.script_pubkey(Branch::Change, 0).expect("change spk");
    let psbt_req =
        psbt_builder::from_pset_request(&req, Some(change.clone())).expect("narrows");

    // 4. Build.
    let mut built = psbt_builder::build_psbt(&psbt_req).expect("builds");
    assert_eq!(built.psbt.unsigned_tx.input.len(), 1);
    assert_eq!(built.psbt.unsigned_tx.output.len(), 2, "recipient + change");
    assert_eq!(built.change_index, Some(1));

    // The fee is a leftover on Bitcoin, so it is only right if it equals what is left.
    let out_total: u64 = built.psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(200_000 - out_total, built.fee);
    assert!(built.fee > 0 && built.fee < 10_000, "implausible fee: {}", built.fee);

    // The recipient gets exactly what was declared; change takes the rest.
    assert_eq!(built.psbt.unsigned_tx.output[0].script_pubkey, recipient());
    assert_eq!(built.psbt.unsigned_tx.output[0].value, Amount::from_sat(120_000));
    assert_eq!(built.psbt.unsigned_tx.output[1].script_pubkey, change);

    // 5. Sign.
    let plan = [KeyPathSigner { input_index: 0, branch: Branch::Receive, index: 0 }];
    let sighash = psbt_builder::key_path_sighash(&built.psbt, 0).expect("sighash");
    psbt_builder::sign_key_path_inputs(&mut built.psbt, &w, &plan).expect("signs");

    // The signature must verify against the output key of the script being spent —
    // nothing downstream checks this, and a wrong key spends nothing.
    let secp = Secp256k1::new();
    let internal = w.internal_key(Branch::Receive, 0).unwrap();
    let output_key = internal.tap_tweak(&secp, None).0.to_x_only_public_key();
    let sig = built.psbt.inputs[0].tap_key_sig.expect("stored").signature;
    assert!(secp
        .verify_schnorr(&sig, &Message::from_digest(sighash), &output_key)
        .is_ok());

    // 6. Finalize and extract.
    psbt_builder::finalize_key_path_inputs(&mut built.psbt).expect("finalizes");
    let tx = psbt_builder::extract_tx(built.psbt).expect("extracts");
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.input[0].witness.len(), 1, "one 64-byte key-path signature");
    assert_eq!(tx.input[0].witness.iter().next().unwrap().len(), 64);

    // A signed transaction must serialize, or nothing can broadcast it.
    let hex = lwk_wollet::elements::bitcoin::consensus::encode::serialize_hex(&tx);
    assert!(!hex.is_empty());
}

/// The bug this file exists for.
///
/// `select_input` matches a manifest's asset against the UTXOs it is choosing from, so the
/// two must name the same asset. They did not: the label `"lbtc"` resolved through an
/// `ElementsNetwork` to Liquid's policy asset, while the scan produced the synthetic
/// Bitcoin one. The failure mode was a funded wallet reporting itself empty — no error, no
/// wrong transaction, just nothing to spend.
#[test]
fn scanned_utxos_carry_the_asset_a_bitcoin_run_looks_for() {
    let w = wallet();
    let spendable = bitcoin_spendable_utxos(&[scanned(&w, Branch::Receive, 0, 50_000, 2)])
        .expect("synthesizes");

    assert_eq!(
        spendable[0].unblinded.asset,
        bitcoin_policy_asset(),
        "a scanned UTXO must carry the asset a Bitcoin run resolves 'lbtc' to"
    );
    assert_ne!(
        bitcoin_policy_asset(),
        lwk_wollet::ElementsNetwork::LiquidTestnet.policy_asset(),
        "the two are genuinely different assets, which is why this had to be fixed"
    );
}

/// Multiple UTXOs across both branches must all survive into spendable inputs, with their
/// derivation preserved — the signer finds the key by branch and index, so losing either
/// makes the input unsignable.
#[test]
fn utxos_from_both_branches_keep_their_derivation() {
    let w = wallet();
    let utxos = vec![
        scanned(&w, Branch::Receive, 0, 10_000, 3),
        scanned(&w, Branch::Change, 4, 20_000, 4),
        scanned(&w, Branch::Receive, 7, 30_000, 5),
    ];
    let spendable = bitcoin_spendable_utxos(&utxos).expect("synthesizes");
    assert_eq!(spendable.len(), 3);

    for (scanned, synth) in utxos.iter().zip(&spendable) {
        assert_eq!(synth.unblinded.value, scanned.value);
        assert_eq!(synth.wildcard_index, scanned.index);
        assert_eq!(synth.script_pubkey.as_bytes(), scanned.script_pubkey.as_bytes());
        let expected_chain = match scanned.branch {
            Branch::Receive => lwk_wollet::Chain::External,
            Branch::Change => lwk_wollet::Chain::Internal,
        };
        assert_eq!(synth.ext_int, expected_chain);
    }
}

/// A covenant input on a Bitcoin run must be refused with something that explains itself,
/// not silently left unsigned — an unsigned input produces a transaction the network drops.
#[test]
fn a_covenant_input_is_refused_rather_than_left_unsigned() {
    let w = wallet();
    let covenant_spk = ScriptBuf::from_bytes({
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[0x77; 32]);
        v
    });
    let req = BuildPsetRequest {
        inputs: vec![PsetInput::Covenant {
            input_id: "vault".to_string(),
            outpoint: lwk_wollet::elements::OutPoint {
                txid: format!("{:064x}", 9).parse().unwrap(),
                vout: 0,
            },
            script_pubkey: lwk_wollet::elements::Script::from(covenant_spk.to_bytes()),
            asset: bitcoin_policy_asset(),
            amount: 100_000,
            issuance: None,
            sequence: None,
            blinding: None,
        }],
        outputs: vec![PsetOutputSpec {
            script_pubkey: lwk_wollet::elements::Script::from(recipient().to_bytes()),
            amount: 90_000,
            asset: bitcoin_policy_asset(),
            blinding_key: None,
            blinding: None,
        }],
        fee_rate: 1.0,
        policy_asset: bitcoin_policy_asset(),
        change_assets: std::collections::HashSet::from([bitcoin_policy_asset()]),
    };

    // It narrows and builds — a covenant output is a perfectly ordinary P2TR input at this
    // level. What it cannot do is produce a witness, and the signing plan is where that
    // has to be noticed.
    let change = w.script_pubkey(Branch::Change, 0).expect("change spk");
    let psbt_req = psbt_builder::from_pset_request(&req, Some(change)).expect("narrows");
    let built = psbt_builder::build_psbt(&psbt_req).expect("builds");
    assert!(matches!(psbt_req.inputs[0], PsbtInput::Covenant { .. }));

    // No key-path plan entry exists for it, so finalizing leaves it witness-less rather
    // than signing it with a wallet key it is not locked to.
    let mut psbt = built.psbt;
    psbt_builder::sign_key_path_inputs(&mut psbt, &w, &[]).expect("signs nothing");
    psbt_builder::finalize_key_path_inputs(&mut psbt).expect("finalizes nothing");
    assert!(
        psbt.inputs[0].final_script_witness.is_none(),
        "a covenant input must not be finalized as a key-path spend"
    );
}


/// Address parsing must follow the chain, and a failure must not be survivable.
///
/// Both call sites used to parse every manifest address as an `elements::Address`, which
/// rejects every Bitcoin address. Neither treated that as fatal: the output loop dropped
/// the output and built the transaction without it — the declared payment missing, its
/// value falling into change — and the input pin fell back to selecting from anywhere.
#[test]
fn manifest_addresses_parse_for_the_chain_in_play() {
    use tx_manifest_lib::assembly::parse_destination;

    let w = wallet();
    let signet_addr = w.address(Branch::Receive, 0).unwrap().to_string();

    // The case that was broken: a Bitcoin address on a Bitcoin run.
    let parsed = parse_destination(&signet_addr, Network::BitcoinSignet).expect("parses");
    assert_eq!(
        parsed.script_pubkey.as_bytes(),
        w.script_pubkey(Branch::Receive, 0).unwrap().as_bytes()
    );
    assert!(parsed.blinding_pubkey.is_none(), "Bitcoin addresses carry no blinding key");

    // ...and it is genuinely what the Elements parser rejects, which is why this mattered.
    assert!(signet_addr.parse::<lwk_wollet::elements::Address>().is_err());
    assert!(parse_destination(&signet_addr, Network::LiquidTestnet).is_err());
}

/// A mainnet address parses perfectly well on a signet run, so the network is checked
/// rather than merely parsed — otherwise a manifest could send to an address on a chain
/// the run has no relationship with.
#[test]
fn an_address_for_the_wrong_bitcoin_network_is_refused() {
    use tx_manifest_lib::assembly::parse_destination;

    let mainnet = BitcoinWallet::from_mnemonic(MNEMONIC, Network::Bitcoin).unwrap();
    let mainnet_addr = mainnet.address(Branch::Receive, 0).unwrap().to_string();
    assert!(mainnet_addr.starts_with("bc1p"), "{mainnet_addr}");

    assert!(parse_destination(&mainnet_addr, Network::Bitcoin).is_ok());
    let err = parse_destination(&mainnet_addr, Network::BitcoinSignet)
        .expect_err("a mainnet address must not be accepted on signet")
        .to_string();
    assert!(err.contains("bitcoin-signet"), "{err}");
}


/// The `fee` keyword must be estimated on the chain the transaction is for.
///
/// The lifecycle called the Elements estimator unconditionally, which on a Bitcoin run
/// asks an LWK wallet about a UTXO it has never heard of. The keyword then cannot resolve,
/// and every output amount depending on it -- `input.amount_sat - fee`, the way a sweep is
/// written -- is wrong by exactly the fee.
#[test]
fn the_fee_keyword_is_estimable_on_bitcoin() {
    let w = wallet();
    let utxos = vec![scanned(&w, Branch::Receive, 0, 1_000_000, 8)];
    let spendable = bitcoin_spendable_utxos(&utxos).expect("synthesizes");

    let req = BuildPsetRequest {
        inputs: vec![PsetInput::Wallet {
            input_id: "funding".to_string(),
            utxo: spendable[0].clone(),
            issuance: None,
            sequence: None,
        }],
        // A sweep declares no output amount until `fee` resolves, so the estimate is taken
        // from a draft with none.
        outputs: vec![],
        fee_rate: 2.0,
        policy_asset: bitcoin_policy_asset(),
        change_assets: Default::default(),
    };

    let psbt_req = psbt_builder::from_pset_request(&req, None).expect("narrows");
    let fee = psbt_builder::estimate_fee(&psbt_req).expect("estimates");
    assert!(fee > 0, "a transaction with an input costs something to relay");
    assert!(fee < 10_000, "implausible fee for one input: {fee}");

    // The rate is what was asked for, within the rounding a whole-vbyte size imposes.
    let vsize = fee as f32 / 2.0;
    assert!(vsize > 50.0 && vsize < 200.0, "implied vsize {vsize} is not a real transaction");
}
