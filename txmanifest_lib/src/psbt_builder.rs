//! Bitcoin PSBT construction — the counterpart to [`crate::pset_builder`].
//!
//! A separate module rather than a generic one. The two chains share the *shape* of the
//! job (gather inputs, place declared outputs, size the fee, return change) and almost
//! none of its substance: this module has no assets, no blinding, no issuance, no
//! rangeproofs, and no fee output. Roughly two thirds of `pset_builder` is machinery for
//! things Bitcoin does not have, so unifying them would mean a request type whose fields
//! are half-inapplicable on each chain, and a builder threading `if family.is_elements()`
//! through the parts that differ most.
//!
//! What is genuinely common — the input/output vocabulary the lifecycle speaks, and the
//! two-pass fee loop — is mirrored here deliberately, with the same names and the same
//! ordering guarantees, so a reader moving between the two files finds the same landmarks.
//!
//! # The fee is not an output
//!
//! This is the difference that reaches furthest. Elements carries the fee as a real
//! `TxOut`, so the builder *places* it and the transaction balances by construction.
//! Bitcoin defines the fee as inputs minus outputs, so nothing here writes it down: it is
//! whatever is left over, and the builder's job is to make sure that leftover is the
//! number it intended. A bug that would have produced a visibly wrong fee output on
//! Elements produces a silently overpaid fee here — so the balance is asserted explicitly
//! rather than assumed, and [`BuildPsbtResult::fee`] reports what was actually left.

use std::collections::HashMap;

use anyhow::{bail, Context as _, Result};
use lwk_wollet::elements::bitcoin::{
    absolute::LockTime,
    hashes::Hash as _,
    psbt::{Input as PsbtInputData, Output as PsbtOutputData, Psbt},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::Signature as TaprootSignature,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use crate::bitcoin_wallet::{BitcoinWallet, Branch};

/// Weight units per virtual byte.
const WU_PER_VBYTE: usize = 4;

/// Assumed witness weight for one taproot script-path covenant input, in weight units.
///
/// A draft PSBT has no witnesses, so a fee computed from it alone underpays. This is the
/// same allowance [`crate::pset_builder`] makes, for the same reason and with the same
/// caveat: it is an estimate, and a Simplicity witness is not a fixed size. Overshooting
/// costs a slightly high fee; undershooting produces a transaction the network will not
/// relay, so the number errs high.
const COVENANT_WITNESS_WU: usize = 1024;

/// Assumed witness weight for one key-path (P2TR keyspend) wallet input, in weight units.
/// A BIP341 keyspend witness is one 64-byte signature plus its length prefix.
const KEYSPEND_WITNESS_WU: usize = 66;

// ---------------------------------------------------------------------------
// Public input/output spec types
// ---------------------------------------------------------------------------

/// One input to spend. Mirrors `pset_builder::PsetInput` minus the Elements-only arms.
#[derive(Debug)]
pub enum PsbtInput {
    /// A wallet-owned UTXO, spent by key path.
    Wallet {
        input_id: String,
        outpoint: OutPoint,
        /// The output being spent. Required, not optional: a taproot sighash commits to
        /// every spent output's value and scriptPubKey, so signing without it produces a
        /// signature that is simply invalid.
        witness_utxo: TxOut,
        /// Raw `nSequence` (BIP68 relative timelock). `None` leaves it at `Sequence::MAX`.
        sequence: Option<u32>,
    },
    /// A covenant UTXO, spent through a Simplicity tapleaf.
    ///
    /// The prevout is reconstructed from `amount` and `script_pubkey` rather than fetched,
    /// exactly as `pset_builder::add_covenant_input` does: a taproot sighash commits to a
    /// spent output's value and scriptPubKey and nothing else, so those two rebuild it
    /// byte-for-byte as far as anything reading it is concerned. An offline run works.
    Covenant {
        input_id: String,
        outpoint: OutPoint,
        script_pubkey: ScriptBuf,
        amount: u64,
        sequence: Option<u32>,
    },
}

impl PsbtInput {
    pub fn input_id(&self) -> &str {
        match self {
            PsbtInput::Wallet { input_id, .. } | PsbtInput::Covenant { input_id, .. } => input_id,
        }
    }

    /// Value this input brings in, in satoshis.
    pub fn amount(&self) -> u64 {
        match self {
            PsbtInput::Wallet { witness_utxo, .. } => witness_utxo.value.to_sat(),
            PsbtInput::Covenant { amount, .. } => *amount,
        }
    }

    fn sequence(&self) -> Sequence {
        let raw = match self {
            PsbtInput::Wallet { sequence, .. } | PsbtInput::Covenant { sequence, .. } => *sequence,
        };
        raw.map_or(Sequence::MAX, Sequence::from_consensus)
    }

    fn outpoint(&self) -> OutPoint {
        match self {
            PsbtInput::Wallet { outpoint, .. } | PsbtInput::Covenant { outpoint, .. } => *outpoint,
        }
    }

    /// The output this input spends, real or reconstructed.
    fn witness_utxo(&self) -> TxOut {
        match self {
            PsbtInput::Wallet { witness_utxo, .. } => witness_utxo.clone(),
            PsbtInput::Covenant { script_pubkey, amount, .. } => TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: script_pubkey.clone(),
            },
        }
    }

    fn estimated_witness_wu(&self) -> usize {
        match self {
            PsbtInput::Wallet { .. } => KEYSPEND_WITNESS_WU,
            PsbtInput::Covenant { .. } => COVENANT_WITNESS_WU,
        }
    }
}

/// One declared output.
#[derive(Debug)]
pub struct PsbtOutputSpec {
    pub script_pubkey: ScriptBuf,
    pub amount: u64,
}

#[derive(Debug)]
pub struct BuildPsbtRequest {
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutputSpec>,
    pub fee_rate: f32,
    /// Where a surplus goes, when the manifest declared a change output.
    ///
    /// `None` means the action declared none, and any surplus is an error rather than a
    /// silently-invented output — the same rule `pset_builder` applies per asset. The
    /// alternative is a transaction that moves value the manifest never mentioned.
    pub change_script: Option<ScriptBuf>,
    /// Transaction-level `nLockTime`. `None` leaves it at zero (no absolute timelock).
    pub lock_time: Option<u32>,
}

#[derive(Debug)]
pub struct BuildPsbtResult {
    pub psbt: Psbt,
    /// What the transaction actually pays in fees — inputs minus outputs.
    ///
    /// Reported rather than assumed. On Bitcoin the fee is a leftover, so an arithmetic
    /// slip does not produce a wrong-looking fee output the way it would on Elements; it
    /// produces a correct-looking transaction that overpays. Returning the number lets the
    /// caller show it and lets tests assert on it.
    pub fee: u64,
    /// Index of the change output in the transaction, when one was added.
    pub change_index: Option<usize>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Build an unsigned PSBT for `req`.
///
/// Two passes, mirroring [`crate::pset_builder::build_pset`]: a draft to measure the
/// transaction, then the real build with the fee that measurement implies. The draft is
/// necessary because the fee depends on the size, and on Bitcoin the size depends on the
/// fee — a change output may appear or vanish as the fee moves.
pub fn build_psbt(req: &BuildPsbtRequest) -> Result<BuildPsbtResult> {
    // Draft with a nominal fee purely to measure. Its change output may differ from the
    // final one by a few satoshis, which does not change the transaction's size.
    let draft = build_inner(req, 0, Pass::Draft)?;
    let fee = estimate_fee_for(&draft.psbt, req);

    let built = build_inner(req, fee, Pass::Final)?;

    // The fee is a leftover here, so verify it rather than trusting the arithmetic that
    // produced it. This is the check that has no counterpart in `pset_builder`, where a
    // mistake would show up as a visibly wrong fee output.
    let in_total = total_in(req);
    let out_total: u64 = built
        .psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let actual = in_total
        .checked_sub(out_total)
        .ok_or_else(|| anyhow::anyhow!("outputs exceed inputs after fee placement"))?;
    if actual != built.fee {
        bail!(
            "internal error: transaction pays {actual} sat in fees but {} was intended",
            built.fee
        );
    }

    Ok(built)
}

/// Estimate the fee for a transaction shaped like `psbt`, at `req`'s rate.
///
/// Public because the lifecycle resolves a `fee` keyword in manifest formulas before it
/// commits to amounts — the same role [`crate::pset_builder::estimate_fee`] plays.
pub fn estimate_fee(req: &BuildPsbtRequest) -> Result<u64> {
    let draft = build_inner(req, 0, Pass::Draft)?;
    Ok(estimate_fee_for(&draft.psbt, req))
}

/// Which of the two passes a [`build_inner`] call is.
///
/// The distinction exists for one rule. A draft is built at fee zero, which makes its
/// surplus the largest it can be — so a manifest whose outputs correctly account for the
/// fee looks, at that moment, like it has an unexplained surplus. Enforcing the
/// no-undeclared-change rule there would reject exactly the manifests that got the
/// arithmetic right. The draft exists only to be measured; the rule belongs on the
/// transaction that will actually be broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    Draft,
    Final,
}

fn estimate_fee_for(psbt: &Psbt, req: &BuildPsbtRequest) -> u64 {
    // `unsigned_tx.weight()` counts a witness-less transaction. Every input will carry a
    // witness, so add an allowance for each; without it the fee underpays and the
    // transaction does not relay.
    let base_wu = psbt.unsigned_tx.weight().to_wu() as usize;
    let witness_wu: usize = req.inputs.iter().map(PsbtInput::estimated_witness_wu).sum();
    // A segwit transaction also carries a 2-byte marker+flag, which a witness-less
    // serialization omits.
    let marker_wu = 2;
    let vsize = (base_wu + witness_wu + marker_wu).div_ceil(WU_PER_VBYTE) as f32;
    (vsize * req.fee_rate).ceil() as u64
}

fn total_in(req: &BuildPsbtRequest) -> u64 {
    req.inputs.iter().map(PsbtInput::amount).sum()
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Build the transaction with `fee` as the intended leftover.
///
/// Declared outputs are appended first, in `req.outputs` order, so a declared output's
/// index in the request is its index in the transaction. Change lands after them. The
/// lifecycle relies on that correspondence to attach per-output data, and
/// `pset_builder::build_inner` guarantees the same thing.
fn build_inner(req: &BuildPsbtRequest, fee: u64, pass: Pass) -> Result<BuildPsbtResult> {
    if req.inputs.is_empty() {
        bail!("cannot build a transaction with no inputs");
    }

    let in_total = total_in(req);
    let declared_total: u64 = req
        .outputs
        .iter()
        .map(|o| o.amount)
        .try_fold(0u64, |acc, a| acc.checked_add(a))
        .ok_or_else(|| anyhow::anyhow!("declared output amounts overflow"))?;

    let spent = declared_total
        .checked_add(fee)
        .ok_or_else(|| anyhow::anyhow!("outputs plus fee overflow"))?;
    let surplus = in_total.checked_sub(spent).ok_or_else(|| {
        anyhow::anyhow!(
            "inputs total {in_total} sat but outputs plus fee need {spent} sat \
             ({declared_total} declared + {fee} fee): {} sat short",
            spent - in_total
        )
    })?;

    let mut tx_out: Vec<TxOut> = req
        .outputs
        .iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.amount),
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    // Change, and the two ways there is none.
    let mut change_index = None;
    let mut fee = fee;
    if surplus > 0 {
        let Some(change_script) = &req.change_script else {
            if pass == Pass::Draft {
                // Measuring only: no change output would be emitted here anyway, so size
                // the draft as-is and let the final pass judge the real surplus.
                return finish(req, fee + surplus, tx_out, None);
            }
            bail!(
                "{surplus} sat left over and this action declares no change output; \
                 declare one or account for the full input value"
            );
        };
        let dust = dust_threshold(change_script);
        if surplus >= dust {
            change_index = Some(tx_out.len());
            tx_out.push(TxOut {
                value: Amount::from_sat(surplus),
                script_pubkey: change_script.clone(),
            });
        } else {
            // A change output below the dust limit is unrelayable, so the surplus has
            // nowhere to go but the fee. Recording it keeps `fee` equal to what the
            // transaction actually pays, which is what `build_psbt` asserts on.
            fee += surplus;
        }
    }

    finish(req, fee, tx_out, change_index)
}

/// Assemble the transaction and wrap it in a PSBT.
fn finish(
    req: &BuildPsbtRequest,
    fee: u64,
    output: Vec<TxOut>,
    change_index: Option<usize>,
) -> Result<BuildPsbtResult> {
    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: req
            .lock_time
            .map(LockTime::from_consensus)
            .unwrap_or(LockTime::ZERO),
        input: req
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: i.sequence(),
                witness: Witness::new(),
            })
            .collect(),
        output,
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| anyhow::anyhow!("cannot start PSBT: {e}"))?;

    for (idx, input) in req.inputs.iter().enumerate() {
        psbt.inputs[idx] = PsbtInputData {
            witness_utxo: Some(input.witness_utxo()),
            ..Default::default()
        };
    }
    for out in psbt.outputs.iter_mut() {
        *out = PsbtOutputData::default();
    }

    Ok(BuildPsbtResult { psbt, fee, change_index })
}

/// Minimum relayable value for an output paying `script_pubkey`.
///
/// Bitcoin Core's rule: the output is dust if its value is below the cost of spending it
/// at the dust relay rate of 3000 sat/kvB. For the witness programs this builder emits —
/// P2TR and P2WPKH — that works out to the familiar 330 and 294 sat. Anything else gets
/// the conservative legacy figure rather than a guess, because emitting an unrelayable
/// change output is worse than folding a few extra satoshis into the fee.
fn dust_threshold(script_pubkey: &ScriptBuf) -> u64 {
    if script_pubkey.is_p2tr() {
        330
    } else if script_pubkey.is_p2wpkh() {
        294
    } else if script_pubkey.is_witness_program() {
        330
    } else {
        546
    }
}

/// Map from input id to its index in the built transaction.
///
/// Inputs keep `req.inputs` order, so this is positional — but the lifecycle addresses
/// inputs by manifest id when attaching witnesses, and open-coding the lookup at each site
/// is how an off-by-one becomes a signature over the wrong input.
pub fn input_indices(req: &BuildPsbtRequest) -> HashMap<String, usize> {
    req.inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| (inp.input_id().to_string(), i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: lwk_wollet::elements::bitcoin::Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    /// A P2TR script, which is what every output this engine builds actually looks like.
    fn p2tr(n: u8) -> ScriptBuf {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[n; 32]);
        ScriptBuf::from_bytes(v)
    }

    fn wallet_input(id: &str, sats: u64) -> PsbtInput {
        PsbtInput::Wallet {
            input_id: id.to_string(),
            outpoint: outpoint(1),
            witness_utxo: TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: p2tr(9),
            },
            sequence: None,
        }
    }

    fn req(inputs: Vec<PsbtInput>, outputs: Vec<PsbtOutputSpec>) -> BuildPsbtRequest {
        BuildPsbtRequest {
            inputs,
            outputs,
            fee_rate: 1.0,
            change_script: Some(p2tr(7)),
            lock_time: None,
        }
    }

    /// The property the whole module exists to get right: on Bitcoin nothing writes the
    /// fee down, so it must equal exactly what is left over.
    #[test]
    fn the_fee_is_the_leftover_and_nothing_else() {
        let r = req(
            vec![wallet_input("i0", 100_000)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 60_000 }],
        );
        let built = build_psbt(&r).expect("builds");

        let out_total: u64 = built.psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(100_000 - out_total, built.fee);
        // No fee output: Bitcoin has no such thing, and inventing one would be a burn.
        assert_eq!(built.psbt.unsigned_tx.output.len(), 2, "declared output + change only");
    }

    #[test]
    fn declared_outputs_keep_their_request_order_and_change_lands_after() {
        let r = req(
            vec![wallet_input("i0", 100_000)],
            vec![
                PsbtOutputSpec { script_pubkey: p2tr(1), amount: 10_000 },
                PsbtOutputSpec { script_pubkey: p2tr(2), amount: 20_000 },
            ],
        );
        let built = build_psbt(&r).expect("builds");
        let outs = &built.psbt.unsigned_tx.output;
        assert_eq!(outs[0].script_pubkey, p2tr(1));
        assert_eq!(outs[1].script_pubkey, p2tr(2));
        assert_eq!(built.change_index, Some(2));
        assert_eq!(outs[2].script_pubkey, p2tr(7));
    }

    /// The same rule `pset_builder` applies per asset: an undeclared surplus is an error,
    /// never a silently-invented output.
    #[test]
    fn a_surplus_with_no_declared_change_is_refused() {
        let mut r = req(
            vec![wallet_input("i0", 100_000)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 10_000 }],
        );
        r.change_script = None;
        let err = build_psbt(&r).expect_err("surplus with no change output").to_string();
        assert!(err.contains("declares no change output"), "{err}");
    }

    /// Dust change cannot be emitted, so it goes to the fee — and `fee` must say so, or
    /// the balance assertion in `build_psbt` would be reporting a number the transaction
    /// does not pay.
    #[test]
    fn dust_change_is_folded_into_the_fee() {
        // Leave ~200 sat over: below the 330 sat P2TR dust threshold.
        let r = req(
            vec![wallet_input("i0", 10_000)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 9_600 }],
        );
        let built = build_psbt(&r).expect("builds");
        assert_eq!(built.change_index, None, "dust change must not be emitted");
        assert_eq!(built.psbt.unsigned_tx.output.len(), 1);
        assert_eq!(built.fee, 10_000 - 9_600);
    }

    /// A manifest that accounts for the fee exactly, with no change output declared, must
    /// build.
    ///
    /// This is the case the two-pass structure originally broke: the draft is built at fee
    /// zero, so its surplus is the whole fee, and enforcing the no-undeclared-change rule
    /// there rejected precisely the manifests that got the arithmetic right. The rule
    /// belongs on the transaction that gets broadcast, not on the one built to be measured.
    #[test]
    fn outputs_that_account_for_the_fee_exactly_need_no_change_output() {
        let inputs = 100_000u64;
        let mut probe = req(
            vec![wallet_input("i0", inputs)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 1 }],
        );
        probe.change_script = None;
        // What the fee will be for a transaction of this shape...
        let fee = estimate_fee(&probe).expect("estimates");

        // ...so declaring outputs that consume exactly the rest must build cleanly.
        let mut r = req(
            vec![wallet_input("i0", inputs)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: inputs - fee }],
        );
        r.change_script = None;
        let built = build_psbt(&r).expect("exact accounting with no change must build");
        assert_eq!(built.change_index, None);
        assert_eq!(built.psbt.unsigned_tx.output.len(), 1);
        assert_eq!(built.fee, fee);
    }

    #[test]
    fn insufficient_funds_names_the_shortfall() {
        let r = req(
            vec![wallet_input("i0", 5_000)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 10_000 }],
        );
        let err = build_psbt(&r).expect_err("cannot fund").to_string();
        assert!(err.contains("short"), "{err}");
    }

    /// Every input needs a `witness_utxo`, including a covenant input whose prevout was
    /// never fetched — a taproot sighash commits to the spent output, so signing without
    /// one produces an invalid signature.
    #[test]
    fn covenant_inputs_carry_a_reconstructed_prevout() {
        let r = req(
            vec![PsbtInput::Covenant {
                input_id: "cov".to_string(),
                outpoint: outpoint(3),
                script_pubkey: p2tr(4),
                amount: 50_000,
                sequence: None,
            }],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 40_000 }],
        );
        let built = build_psbt(&r).expect("builds");
        let utxo = built.psbt.inputs[0].witness_utxo.as_ref().expect("witness_utxo present");
        assert_eq!(utxo.value.to_sat(), 50_000);
        assert_eq!(utxo.script_pubkey, p2tr(4));
    }

    #[test]
    fn sequence_and_locktime_are_carried_through() {
        let mut r = req(
            vec![PsbtInput::Wallet {
                input_id: "i0".to_string(),
                outpoint: outpoint(1),
                witness_utxo: TxOut { value: Amount::from_sat(100_000), script_pubkey: p2tr(9) },
                sequence: Some(144),
            }],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 60_000 }],
        );
        r.lock_time = Some(800_000);
        let built = build_psbt(&r).expect("builds");
        assert_eq!(built.psbt.unsigned_tx.input[0].sequence.to_consensus_u32(), 144);
        assert_eq!(built.psbt.unsigned_tx.lock_time.to_consensus_u32(), 800_000);

        // Default: no relative timelock.
        let plain = build_psbt(&req(
            vec![wallet_input("i0", 100_000)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 60_000 }],
        ))
        .expect("builds");
        assert_eq!(plain.psbt.unsigned_tx.input[0].sequence, Sequence::MAX);
    }

    /// A covenant input must be budgeted a much larger witness than a keyspend, or the
    /// fee underpays and the transaction will not relay.
    #[test]
    fn covenant_inputs_are_budgeted_more_witness_weight() {
        let outputs = || vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 40_000 }];
        let keyspend = estimate_fee(&req(vec![wallet_input("i0", 100_000)], outputs())).unwrap();
        let covenant = estimate_fee(&req(
            vec![PsbtInput::Covenant {
                input_id: "cov".to_string(),
                outpoint: outpoint(3),
                script_pubkey: p2tr(4),
                amount: 100_000,
                sequence: None,
            }],
            outputs(),
        ))
        .unwrap();
        assert!(covenant > keyspend, "covenant {covenant} should cost more than keyspend {keyspend}");
    }

    // -- narrowing from the Elements request -------------------------------

    fn policy() -> lwk_wollet::elements::AssetId {
        lwk_wollet::elements::AssetId::from_slice(&[1u8; 32]).unwrap()
    }

    fn other_asset() -> lwk_wollet::elements::AssetId {
        lwk_wollet::elements::AssetId::from_slice(&[2u8; 32]).unwrap()
    }

    fn el_script() -> lwk_wollet::elements::Script {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[0xcd; 32]);
        lwk_wollet::elements::Script::from(v)
    }

    fn el_outpoint() -> lwk_wollet::elements::OutPoint {
        lwk_wollet::elements::OutPoint {
            txid: lwk_wollet::elements::Txid::from_slice(&[3u8; 32]).unwrap(),
            vout: 2,
        }
    }

    fn covenant_pset_request(asset: lwk_wollet::elements::AssetId) -> crate::pset_builder::BuildPsetRequest {
        crate::pset_builder::BuildPsetRequest {
            inputs: vec![crate::pset_builder::PsetInput::Covenant {
                input_id: "cov".to_string(),
                outpoint: el_outpoint(),
                script_pubkey: el_script(),
                asset,
                amount: 100_000,
                issuance: None,
                sequence: Some(144),
                blinding: None,
            }],
            outputs: vec![crate::pset_builder::PsetOutputSpec {
                script_pubkey: el_script(),
                amount: 60_000,
                asset,
                blinding_key: None,
                blinding: None,
            }],
            fee_rate: 2.0,
            policy_asset: policy(),
            change_assets: std::collections::HashSet::from([policy()]),
        }
    }

    /// Scripts and outpoints carry across unchanged — an Elements and a Bitcoin P2TR
    /// scriptPubKey are the same bytes, and only the address encoding differs.
    #[test]
    fn narrowing_preserves_scripts_outpoints_and_sequences() {
        let pset = covenant_pset_request(policy());
        let psbt = from_pset_request(&pset, Some(p2tr(7))).expect("narrows");

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.inputs[0].amount(), 100_000);
        let PsbtInput::Covenant { script_pubkey, outpoint: op, .. } = &psbt.inputs[0] else {
            panic!("covenant input should stay a covenant input");
        };
        assert_eq!(script_pubkey.as_bytes(), el_script().as_bytes());
        assert_eq!(op.vout, 2);
        assert_eq!(op.txid.to_string(), el_outpoint().txid.to_string());

        assert_eq!(psbt.outputs[0].amount, 60_000);
        assert_eq!(psbt.outputs[0].script_pubkey.as_bytes(), el_script().as_bytes());
        assert_eq!(psbt.fee_rate, 2.0);
        assert_eq!(psbt.change_script, Some(p2tr(7)));
    }

    /// Change is emitted only where the action declared it, matching the Elements rule
    /// that an undeclared surplus is an error rather than an invented output.
    #[test]
    fn change_is_dropped_when_the_action_declared_none() {
        let mut pset = covenant_pset_request(policy());
        pset.change_assets.clear();
        let psbt = from_pset_request(&pset, Some(p2tr(7))).expect("narrows");
        assert_eq!(psbt.change_script, None);
    }

    /// The refusals are the point of this function. Each of these got past `validate`,
    /// which should have caught it — so dropping the field silently would turn a bug in
    /// that check into a transaction meaning something other than the manifest said.
    #[test]
    fn anything_bitcoin_cannot_express_is_refused_rather_than_dropped() {
        // A second asset, on an input.
        let mut pset = covenant_pset_request(other_asset());
        pset.outputs[0].asset = policy();
        let err = from_pset_request(&pset, None).expect_err("second asset").to_string();
        assert!(err.contains("only one asset"), "{err}");

        // A second asset, on an output.
        let mut pset = covenant_pset_request(policy());
        pset.outputs[0].asset = other_asset();
        let err = from_pset_request(&pset, None).expect_err("second asset").to_string();
        assert!(err.contains("only one asset"), "{err}");

        // A confidential output.
        let mut pset = covenant_pset_request(policy());
        pset.outputs[0].blinding_key = Some(lwk_wollet::elements::bitcoin::PublicKey::from_slice(
            &[
                2, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35,
                0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf,
                0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
            ],
        ).unwrap());
        let err = from_pset_request(&pset, None).expect_err("confidential").to_string();
        assert!(err.contains("always explicit"), "{err}");

        // Pinned blinding factors on a covenant input.
        let mut pset = covenant_pset_request(policy());
        if let crate::pset_builder::PsetInput::Covenant { blinding, .. } = &mut pset.inputs[0] {
            *blinding = Some(crate::pset_builder::PinnedBlinding::default());
        }
        let err = from_pset_request(&pset, None).expect_err("blinding").to_string();
        assert!(err.contains("always explicit"), "{err}");

        // Change declared in a non-policy asset.
        let mut pset = covenant_pset_request(policy());
        pset.change_assets.insert(other_asset());
        let err = from_pset_request(&pset, None).expect_err("change asset").to_string();
        assert!(err.contains("only one asset"), "{err}");
    }

    /// A narrowed request must build, so the two halves actually compose.
    #[test]
    fn a_narrowed_request_builds() {
        let pset = covenant_pset_request(policy());
        let psbt_req = from_pset_request(&pset, Some(p2tr(7))).expect("narrows");
        let built = build_psbt(&psbt_req).expect("builds");
        assert_eq!(built.psbt.unsigned_tx.input[0].sequence.to_consensus_u32(), 144);
        let total_out: u64 = built.psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(100_000 - total_out, built.fee);
    }

    // -- signing ----------------------------------------------------------

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";

    fn signing_wallet() -> BitcoinWallet {
        BitcoinWallet::from_mnemonic(MNEMONIC, crate::chain::Network::BitcoinSignet).unwrap()
    }

    /// A request spending one wallet-owned output, so the prevout's scriptPubKey really is
    /// the one the signing key controls.
    fn owned_request(w: &BitcoinWallet) -> BuildPsbtRequest {
        BuildPsbtRequest {
            inputs: vec![PsbtInput::Wallet {
                input_id: "i0".to_string(),
                outpoint: outpoint(1),
                witness_utxo: TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: w.script_pubkey(Branch::Receive, 0).unwrap(),
                },
                sequence: None,
            }],
            outputs: vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 60_000 }],
            fee_rate: 1.0,
            change_script: Some(w.script_pubkey(Branch::Change, 0).unwrap()),
            lock_time: None,
        }
    }

    /// The signature must verify against the output key the spent output actually commits
    /// to — the tweaked one. Nothing else in this pipeline checks that, and a signature
    /// over the wrong key is well-formed and simply never spends.
    #[test]
    fn key_path_signatures_verify_against_the_spent_output() {
        use lwk_wollet::elements::bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};
        use lwk_wollet::elements::bitcoin::key::TapTweak;

        let w = signing_wallet();
        let mut built = build_psbt(&owned_request(&w)).expect("builds");
        let plan = [KeyPathSigner { input_index: 0, branch: Branch::Receive, index: 0 }];

        let sighash = key_path_sighash(&built.psbt, 0).expect("sighash");
        sign_key_path_inputs(&mut built.psbt, &w, &plan).expect("signs");

        let sig = built.psbt.inputs[0].tap_key_sig.expect("signature stored");
        let secp = Secp256k1::new();
        let internal = w.internal_key(Branch::Receive, 0).unwrap();
        let output_key = internal.tap_tweak(&secp, None).0.to_x_only_public_key();
        assert!(secp
            .verify_schnorr(&sig.signature, &Message::from_digest(sighash), &output_key)
            .is_ok());
        let _: Signature = sig.signature;
    }

    /// A taproot sighash commits to every spent output, so one missing prevout would
    /// silently change every signature in the transaction. Refuse rather than sign.
    #[test]
    fn a_missing_prevout_blocks_signing_of_every_input() {
        let w = signing_wallet();
        let mut built = build_psbt(&owned_request(&w)).expect("builds");
        built.psbt.inputs[0].witness_utxo = None;
        let err = key_path_sighash(&built.psbt, 0).expect_err("must refuse").to_string();
        assert!(err.contains("commits to every spent output"), "{err}");
    }

    /// Only the planned inputs are signed, so a mixed transaction can be signed here and
    /// have its covenant inputs finalized elsewhere without either clobbering the other.
    #[test]
    fn covenant_inputs_are_left_for_the_covenant_finalizer() {
        let w = signing_wallet();
        let mut r = owned_request(&w);
        r.inputs.push(PsbtInput::Covenant {
            input_id: "cov".to_string(),
            outpoint: outpoint(5),
            script_pubkey: p2tr(4),
            amount: 50_000,
            sequence: None,
        });
        r.outputs[0].amount = 140_000;

        let mut built = build_psbt(&r).expect("builds");
        sign_key_path_inputs(
            &mut built.psbt,
            &w,
            &[KeyPathSigner { input_index: 0, branch: Branch::Receive, index: 0 }],
        )
        .expect("signs");

        assert!(built.psbt.inputs[0].tap_key_sig.is_some());
        assert!(built.psbt.inputs[1].tap_key_sig.is_none(), "covenant input must be untouched");

        finalize_key_path_inputs(&mut built.psbt).expect("finalizes");
        let wit = built.psbt.inputs[0].final_script_witness.as_ref().expect("witness built");
        // A SIGHASH_DEFAULT key-path witness is exactly one 64-byte signature.
        assert_eq!(wit.len(), 1);
        assert_eq!(wit.iter().next().unwrap().len(), 64);
        assert!(built.psbt.inputs[1].final_script_witness.is_none());
    }

    #[test]
    fn signing_an_out_of_range_input_is_refused() {
        let w = signing_wallet();
        let built = build_psbt(&owned_request(&w)).expect("builds");
        assert!(key_path_sighash(&built.psbt, 7).is_err());
    }

    #[test]
    fn input_indices_track_request_order() {
        let r = req(
            vec![wallet_input("first", 50_000), wallet_input("second", 50_000)],
            vec![PsbtOutputSpec { script_pubkey: p2tr(1), amount: 60_000 }],
        );
        let idx = input_indices(&r);
        assert_eq!(idx["first"], 0);
        assert_eq!(idx["second"], 1);
    }
}


// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Which wallet key signs one input, for callers assembling a signing plan.
///
/// Covenant inputs are absent by construction: they are satisfied by a Simplicity witness,
/// not by a wallet signature, and `covenant::finalize_covenant_input` handles them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPathSigner {
    pub input_index: usize,
    pub branch: Branch,
    pub index: u32,
}

/// The BIP341 sighash for a key-path spend of `input_index`.
///
/// `SIGHASH_DEFAULT` — the taproot default, committing to every input and output. The
/// sighash commits to *all* spent outputs, not just this one, which is why every input's
/// `witness_utxo` must be present before any of them can be signed: one missing prevout
/// silently changes every signature in the transaction.
pub fn key_path_sighash(psbt: &Psbt, input_index: usize) -> Result<[u8; 32]> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            inp.witness_utxo.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "input {i} has no witness_utxo, so no input in this transaction can be \
                     signed: a taproot sighash commits to every spent output"
                )
            })
        })
        .collect::<Result<_>>()?;

    if input_index >= prevouts.len() {
        bail!("input {input_index} is out of range for a transaction with {} inputs", prevouts.len());
    }

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| anyhow::anyhow!("cannot compute taproot sighash: {e}"))?;
    Ok(sighash.to_byte_array())
}

/// Sign the listed key-path inputs in place, filling each one's `tap_key_sig`.
///
/// Only the inputs named in `plan` are touched, so a transaction mixing wallet and
/// covenant inputs can be signed here and finalized elsewhere without either step
/// clobbering the other's work.
pub fn sign_key_path_inputs(
    psbt: &mut Psbt,
    wallet: &BitcoinWallet,
    plan: &[KeyPathSigner],
) -> Result<()> {
    for entry in plan {
        let sighash = key_path_sighash(psbt, entry.input_index)?;
        let raw = wallet
            .sign_key_path(entry.branch, entry.index, &sighash)
            .with_context(|| format!("cannot sign input {}", entry.input_index))?;
        let signature = lwk_wollet::elements::bitcoin::secp256k1::schnorr::Signature::from_slice(&raw)
            .map_err(|e| anyhow::anyhow!("wallet produced an invalid signature: {e}"))?;
        psbt.inputs[entry.input_index].tap_key_sig = Some(TaprootSignature {
            signature,
            // Must match the sighash type the signature was computed over. Storing a
            // different one produces a witness the network rejects for a reason that
            // points nowhere near the mistake.
            sighash_type: TapSighashType::Default,
        });
    }
    Ok(())
}

/// Move each signed key-path input's signature into its final witness.
///
/// A `SIGHASH_DEFAULT` key-path witness is exactly one 64-byte signature. Inputs with no
/// `tap_key_sig` are left alone — those are the covenant inputs, whose witness is built by
/// `covenant::finalize_covenant_input`.
pub fn finalize_key_path_inputs(psbt: &mut Psbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let Some(sig) = input.tap_key_sig.take() else { continue };
        if !input.final_script_witness.as_ref().is_none_or(Witness::is_empty) {
            bail!("input {i} already has a final witness");
        }
        let mut witness = Witness::new();
        witness.push(sig.to_vec());
        input.final_script_witness = Some(witness);
    }
    Ok(())
}

/// Extract the signed transaction, ready to broadcast.
pub fn extract_tx(psbt: Psbt) -> Result<Transaction> {
    psbt.extract_tx()
        .map_err(|e| anyhow::anyhow!("cannot extract transaction from PSBT: {e}"))
}


// ---------------------------------------------------------------------------
// Narrowing from the Elements request
// ---------------------------------------------------------------------------

/// Build a Bitcoin request from the Elements one the lifecycle already assembles.
///
/// The lifecycle's input/output assembly is ~800 lines that resolve destinations, derive
/// covenant addresses, evaluate amounts and record state metadata. Almost none of that is
/// chain-specific, and duplicating it for Bitcoin would produce two copies that drift.
/// So there is one assembly path, and the chains part company here.
///
/// This is a **narrowing**, not a translation: the Elements request is strictly richer,
/// and every field Bitcoin cannot express is refused rather than dropped. That matters
/// more than the convenience. `validate` already rejects a Bitcoin manifest that uses
/// assets, issuance or blinding, so anything reaching this function with those set got
/// past a check that should have caught it — and silently ignoring it would turn a bug in
/// that check into a transaction that quietly means something other than the manifest
/// said. Refusing keeps the failure loud and local.
///
/// `change_script` is supplied by the caller because the Elements request carries a set of
/// change *assets* rather than a script; the Elements builder derives the address from the
/// wallet at build time, and the Bitcoin builder cannot see a wallet.
pub fn from_pset_request(
    pset: &crate::pset_builder::BuildPsetRequest,
    change_script: Option<ScriptBuf>,
) -> Result<BuildPsbtRequest> {
    use crate::pset_builder::PsetInput as EIn;

    let policy = pset.policy_asset;

    let mut inputs = Vec::with_capacity(pset.inputs.len());
    for input in &pset.inputs {
        let id = input.input_id();
        match input {
            EIn::Wallet { utxo, issuance, sequence, .. } => {
                if issuance.is_some() {
                    bail!("input '{id}' carries an asset issuance, which Bitcoin has no way to express");
                }
                if utxo.unblinded.asset != policy {
                    bail!(
                        "input '{id}' holds asset {}, but Bitcoin has only one asset",
                        utxo.unblinded.asset
                    );
                }
                inputs.push(PsbtInput::Wallet {
                    input_id: id.to_string(),
                    outpoint: convert_outpoint(utxo.outpoint),
                    witness_utxo: TxOut {
                        value: Amount::from_sat(utxo.unblinded.value),
                        script_pubkey: convert_script(&utxo.script_pubkey),
                    },
                    sequence: *sequence,
                });
            }
            EIn::Covenant { outpoint, script_pubkey, asset, amount, issuance, sequence, blinding, .. } => {
                if issuance.is_some() {
                    bail!("input '{id}' carries a reissuance, which Bitcoin has no way to express");
                }
                if blinding.is_some() {
                    bail!("input '{id}' has blinding factors, but Bitcoin amounts are always explicit");
                }
                if *asset != policy {
                    bail!("input '{id}' holds asset {asset}, but Bitcoin has only one asset");
                }
                inputs.push(PsbtInput::Covenant {
                    input_id: id.to_string(),
                    outpoint: convert_outpoint(*outpoint),
                    script_pubkey: convert_script(script_pubkey),
                    amount: *amount,
                    sequence: *sequence,
                });
            }
        }
    }

    let mut outputs = Vec::with_capacity(pset.outputs.len());
    for (i, out) in pset.outputs.iter().enumerate() {
        if out.blinding_key.is_some() {
            bail!("output #{i} is confidential, but Bitcoin amounts are always explicit");
        }
        if out.blinding.is_some() {
            bail!("output #{i} pins blinding factors, which Bitcoin has no way to express");
        }
        if out.asset != policy {
            bail!("output #{i} pays asset {}, but Bitcoin has only one asset", out.asset);
        }
        outputs.push(PsbtOutputSpec {
            script_pubkey: convert_script(&out.script_pubkey),
            amount: out.amount,
        });
    }

    for asset in &pset.change_assets {
        if *asset != policy {
            bail!("change was declared in asset {asset}, but Bitcoin has only one asset");
        }
    }

    Ok(BuildPsbtRequest {
        inputs,
        outputs,
        fee_rate: pset.fee_rate,
        // A change output is emitted only where the action declared one, which on Bitcoin
        // means the policy asset appeared in `change_assets`.
        change_script: change_script.filter(|_| pset.change_assets.contains(&policy)),
        // The Elements request has no transaction-level locktime; absolute timelocks reach
        // a covenant through its own `check_lock_height` rather than through the builder.
        lock_time: None,
    })
}

/// Copy a script across, byte for byte.
///
/// **This does not re-derive anything.** A P2TR scriptPubKey has the same *shape* on both
/// chains, but the tweaked key inside it does not: the taproot tweak is domain-separated
/// (`TapTweak/elements` versus `TapTweak`), so one covenant tree yields different script
/// bytes per chain. See `covenant::covenant_script_pubkey_for`.
///
/// So this is only correct for a script already derived for the target chain — which is
/// the caller's responsibility, and the reason `from_pset_request` exists as a narrowing
/// rather than a general translation. An Elements-derived covenant script copied here
/// would be a well-formed P2TR output on Bitcoin that nobody can ever spend.
fn convert_script(script: &lwk_wollet::elements::Script) -> ScriptBuf {
    ScriptBuf::from_bytes(script.as_bytes().to_vec())
}

/// Outpoints differ only in the txid's type; the bytes and display order match.
fn convert_outpoint(outpoint: lwk_wollet::elements::OutPoint) -> OutPoint {
    use lwk_wollet::elements::bitcoin::hashes::Hash as _;
    OutPoint {
        txid: lwk_wollet::elements::bitcoin::Txid::from_byte_array(
            outpoint.txid.to_byte_array(),
        ),
        vout: outpoint.vout,
    }
}
