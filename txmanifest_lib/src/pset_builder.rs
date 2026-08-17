use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{Context, Result};
use lwk_wollet::{
    elements::{
        confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor},
        hashes::{sha256, Hash as _},
        pset::{Input, Output, PartiallySignedTransaction},
        secp256k1_zkp::{RangeProof, SecretKey, SurjectionProof, Tweak},
        AssetId, ContractHash, OutPoint, Script, Sequence, Txid, TxOut, TxOutWitness,
        BlindAssetProofs, BlindValueProofs, RangeProofMessage, SurjectionInput, TxOutSecrets,
    },
    ElementsNetwork, WalletTxOut, Wollet, EC,
};
use rand::thread_rng;

use crate::covenant;

// ---------------------------------------------------------------------------
// Public input/output spec types
// ---------------------------------------------------------------------------

pub enum IssuanceKind {
    New {
        asset_amount: u64,
        inflation_amount: u64,
    },
    Reissue {
        asset_amount: u64,
        /// Pre-computed issuance entropy (32 bytes), from the original new-issuance outpoint.
        entropy: [u8; 32],
    },
}

pub enum PsetInput {
    /// A wallet-owned UTXO (LWK-tracked, confidential). May carry a new issuance.
    Wallet {
        input_id: String,
        utxo: WalletTxOut,
        issuance: Option<IssuanceKind>,
        /// Raw `nSequence` to set on this input (BIP68 relative timelock). `None` →
        /// leave at `Sequence::MAX` (relative locktime disabled).
        sequence: Option<u32>,
    },
    /// A covenant UTXO with explicit (unblinded) value/asset. May carry a reissuance.
    Covenant {
        input_id: String,
        outpoint: lwk_wollet::elements::OutPoint,
        script_pubkey: Script,
        asset: AssetId,
        amount: u64,
        issuance: Option<IssuanceKind>,
        /// Raw `nSequence` to set on this input (BIP68 relative timelock). `None` →
        /// leave at `Sequence::MAX` (relative locktime disabled).
        sequence: Option<u32>,
    },
}

impl PsetInput {
    pub fn input_id(&self) -> &str {
        match self {
            PsetInput::Wallet { input_id, .. } => input_id,
            PsetInput::Covenant { input_id, .. } => input_id,
        }
    }
}

pub struct PsetOutputSpec {
    pub script_pubkey: Script,
    pub amount: u64,
    pub asset: AssetId,
    /// Set for confidential outputs; None for explicit outputs.
    pub blinding_key: Option<lwk_wollet::elements::bitcoin::PublicKey>,
    /// Blinding factors the manifest pinned for this output. `None` (the usual case)
    /// leaves both to the blinder. See [`PinnedBlinding`].
    pub blinding: Option<PinnedBlinding>,
}

/// Blinding factors chosen by the manifest rather than by the blinder.
///
/// Needed when a covenant *reads* an output's factors — deadcat_v3 requires each
/// recreated reissuance token to advance both by exactly one — because `blind_last`
/// picks every factor itself and offers no way to say which. A pinned factor is used
/// verbatim; an unpinned one is drawn at random as usual.
#[derive(Debug, Clone, Copy, Default)]
pub struct PinnedBlinding {
    pub asset_bf: Option<AssetBlindingFactor>,
    pub value_bf: Option<ValueBlindingFactor>,
}

pub struct BuildPsetRequest {
    pub inputs: Vec<PsetInput>,
    pub outputs: Vec<PsetOutputSpec>,
    pub fee_rate: f32,
    pub policy_asset: AssetId,
    /// The assets for which the action declared a `"change"` output.
    ///
    /// The builder adds a change output only for an asset in this set. Every other output
    /// a transaction carries has to come from the manifest — the fee is the single
    /// exception, because it has no manifest spelling. A surplus in an asset with no
    /// declared change output is an error rather than a silently-invented output: the
    /// alternative is a transaction that moves value the manifest never mentioned.
    pub change_assets: std::collections::HashSet<AssetId>,
}

pub struct IssuanceResult {
    pub input_id: String,
    pub asset_id: AssetId,
    pub token_id: AssetId,
    /// Issuance entropy (32-byte SHA256 midstate). Set only for new issuances.
    pub entropy: Option<[u8; 32]>,
}

pub struct BuildPsetResult {
    pub pset: PartiallySignedTransaction,
    pub issuances: Vec<IssuanceResult>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn build_pset(wollet: &Wollet, network: ElementsNetwork, req: &BuildPsetRequest) -> Result<BuildPsetResult> {
    let secp = EC.clone();
    let mut rng = thread_rng();

    let wallet_blinding_pk = wollet
        .address(Some(0))
        .context("Cannot derive wallet address for blinding key")?
        .address()
        .blinding_pubkey
        .context("Wallet address has no blinding key — not a CT descriptor")?;
    let wallet_blinding_pk_btc = btc_pubkey(wallet_blinding_pk);

    // First pass: temp fee=1 to estimate weight.
    let (temp_pset, temp_sec, _) =
        build_inner(wollet, &secp, &mut rng, req, 1, wallet_blinding_pk_btc, network, false, false)?;
    let fee = {
        let mut tmp = temp_pset.clone();
        let mut tmp_rng = thread_rng();
        if pset_has_confidential_output(&tmp) {
            tmp.blind_last(&mut tmp_rng, &secp, &temp_sec)
                .map_err(|e| anyhow::anyhow!("Fee estimation blind failed: {e}"))?;
        }
        let tx = tmp
            .extract_tx()
            .map_err(|e| anyhow::anyhow!("Fee estimation extract_tx failed: {e}"))?;
        let tx_weight = tx.weight();
        let inp_weight = estimated_input_witness_weight(req);
        let vsize = (tx_weight + inp_weight).div_ceil(4) as f32;
        (vsize * req.fee_rate).ceil() as u64
    };

    // Second pass: real fee.
    let (mut pset, inp_txout_sec, issuances) =
        build_inner(wollet, &secp, &mut rng, req, fee, wallet_blinding_pk_btc, network, false, true)?;

    wollet
        .add_details(&mut pset)
        .map_err(|e| anyhow::anyhow!("add_details failed: {e}"))?;

    // A fully-explicit tx (e.g. a covenant spend with only covenant + fee outputs)
    // has nothing to blind; `blind_last` errors if asked to blind with no
    // confidential output, so only blind when one is present.
    if pset_has_confidential_output(&pset) {
        // `build_inner` appends the declared outputs first, in order, so a declared
        // output's index in `req.outputs` is its index in the PSET. Change and fee land
        // after them and are never pinned.
        let pins: HashMap<usize, PinnedBlinding> = req
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.blinding.map(|b| (i, b)))
            .collect();
        if pins.is_empty() {
            pset.blind_last(&mut rng, &secp, &inp_txout_sec)
                .map_err(|e| anyhow::anyhow!("PSET blinding failed: {e}"))?;
        } else {
            blind_with_pinned_factors(&mut pset, &secp, &mut rng, &inp_txout_sec, &pins)
                .context("PSET blinding failed")?;
        }
    }

    Ok(BuildPsetResult { pset, issuances })
}

/// True if any PSET output is confidential (carries a blinding key). Fully-explicit
/// transactions need no blinding pass.
fn pset_has_confidential_output(pset: &PartiallySignedTransaction) -> bool {
    pset.outputs().iter().any(|o| o.blinding_key.is_some())
}

/// Blind every confidential output, using the manifest's factors where it pinned them.
///
/// This is `blind_last` rewritten with a seam. The upstream routine draws every abf/vbf
/// itself and solves the *last* output's vbf so the transaction balances; here the pinned
/// factors are used verbatim, and the balancing role moves to the last output whose vbf
/// is still free. Everything else — the surjection domain, the rangeproof message, the
/// explicit blind_{asset,value} proofs — is the same work in the same order, because a
/// PSET blinded any other way is not a PSET Elements will accept.
///
/// The residue has to land somewhere: blinding factors sum to zero across a transaction,
/// so at least one confidential output must keep a free vbf for the solver. Pinning all
/// of them is not a tighter transaction, it is an unsatisfiable one.
fn blind_with_pinned_factors(
    pset: &mut PartiallySignedTransaction,
    secp: &lwk_wollet::elements::secp256k1_zkp::Secp256k1<lwk_wollet::elements::secp256k1_zkp::All>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    inp_txout_sec: &HashMap<usize, TxOutSecrets>,
    pins: &HashMap<usize, PinnedBlinding>,
) -> Result<()> {
    for (i, inp) in pset.inputs().iter().enumerate() {
        if inp.has_issuance() && inp.blinded_issuance.unwrap_or(1) == 1 {
            anyhow::bail!("Input {i} asks for a blinded issuance, which is not supported");
        }
    }

    // Which outputs get blinded, by the same rule `blind_last` applies: a blinding key, a
    // blinder_index in range, and secrets for the input it names.
    let mut to_blind: Vec<usize> = Vec::new();
    for (i, out) in pset.outputs().iter().enumerate() {
        if out.blinding_key.is_none() {
            continue;
        }
        let blinder = out
            .blinder_index
            .ok_or_else(|| anyhow::anyhow!("Output {i} is confidential but names no blinder input"))?
            as usize;
        if blinder >= pset.inputs().len() {
            anyhow::bail!("Output {i} names blinder input {blinder}, which does not exist");
        }
        if inp_txout_sec.contains_key(&blinder) {
            to_blind.push(i);
        }
    }
    for i in pins.keys() {
        if !to_blind.contains(i) {
            anyhow::bail!(
                "Output {i} pins blinding factors but is not being blinded — a pinned factor \
                 only means something on a confidential output"
            );
        }
    }

    // The balancer: the last output whose vbf nobody pinned. An output may pin only its
    // abf (the half Elements reads as a reissuance's nonce) and still take this role.
    let free = to_blind
        .iter()
        .rev()
        .copied()
        .find(|i| pins.get(i).is_none_or(|p| p.value_bf.is_none()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Every confidential output pins its value blinding factor, so nothing is left \
                 to absorb the balance residue and the transaction cannot be blinded.\n\
                 Leave one output — normally the change — with its `value_bf` unpinned."
            )
        })?;

    let surject_inputs = pset
        .surjection_inputs(inp_txout_sec)
        .map_err(|e| anyhow::anyhow!("surjection inputs: {e}"))?;

    // Blind everything but the balancer, collecting the secrets the solver needs.
    let mut out_secrets: Vec<(u64, AssetBlindingFactor, ValueBlindingFactor)> = Vec::new();
    for &i in &to_blind {
        if i == free {
            continue;
        }
        let pin = pins.get(&i).copied().unwrap_or_default();
        let abf = pin.asset_bf.unwrap_or_else(|| AssetBlindingFactor::new(rng));
        let vbf = pin.value_bf.unwrap_or_else(|| ValueBlindingFactor::new(rng));
        let value = blind_one_output(pset, i, secp, rng, &surject_inputs, abf, vbf)?;
        out_secrets.push((value, abf, vbf));
    }

    // Explicit outputs (the fee, any `confidential: false` leg) carry zero factors and so
    // contribute nothing to the sum, but the solver is given the whole output set.
    for (i, out) in pset.outputs().iter().enumerate() {
        if to_blind.contains(&i) {
            continue;
        }
        let amount = out
            .amount
            .ok_or_else(|| anyhow::anyhow!("Explicit output {i} has no amount"))?;
        out_secrets.push((amount, AssetBlindingFactor::zero(), ValueBlindingFactor::zero()));
    }

    let inp_secrets: Vec<(u64, AssetBlindingFactor, ValueBlindingFactor)> = inp_txout_sec
        .values()
        .map(|s| (s.value, s.asset_bf, s.value_bf))
        .collect();

    let free_abf = pins
        .get(&free)
        .and_then(|p| p.asset_bf)
        .unwrap_or_else(|| AssetBlindingFactor::new(rng));
    let free_value = pset.outputs()[free]
        .amount
        .ok_or_else(|| anyhow::anyhow!("Output {free} has no explicit amount to blind"))?;
    let free_vbf =
        ValueBlindingFactor::last(secp, free_value, free_abf, &inp_secrets, &out_secrets);
    blind_one_output(pset, free, secp, rng, &surject_inputs, free_abf, free_vbf)?;

    // Nothing was left for another blinder to finish, so no scalar is carried.
    Ok(())
}

/// Blind one PSET output with the given factors, writing back the commitments and all
/// four proofs. Returns the output's explicit amount, which the balance solver needs.
fn blind_one_output(
    pset: &mut PartiallySignedTransaction,
    idx: usize,
    secp: &lwk_wollet::elements::secp256k1_zkp::Secp256k1<lwk_wollet::elements::secp256k1_zkp::All>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    surject_inputs: &[SurjectionInput],
    abf: AssetBlindingFactor,
    vbf: ValueBlindingFactor,
) -> Result<u64> {
    let out = &pset.outputs()[idx];
    let asset_id = out
        .asset
        .ok_or_else(|| anyhow::anyhow!("Output {idx} has no explicit asset to blind"))?;
    let value = out
        .amount
        .ok_or_else(|| anyhow::anyhow!("Output {idx} has no explicit amount to blind"))?;
    let blinding_pk = out
        .blinding_key
        .ok_or_else(|| anyhow::anyhow!("Output {idx} has no blinding key"))?
        .inner;
    let script_pubkey = out.script_pubkey.clone();

    let (asset_comm, surjection_proof) = Asset::Explicit(asset_id)
        .blind(rng, secp, abf, surject_inputs)
        .map_err(|e| anyhow::anyhow!("Output {idx} asset blinding failed: {e}"))?;
    let (value_comm, nonce, rangeproof) = Value::Explicit(value)
        .blind(
            secp,
            vbf,
            blinding_pk,
            SecretKey::new(rng),
            &script_pubkey,
            &RangeProofMessage { asset: asset_id, bf: abf },
        )
        .map_err(|e| anyhow::anyhow!("Output {idx} value blinding failed: {e}"))?;

    let asset_gen = asset_comm
        .commitment()
        .ok_or_else(|| anyhow::anyhow!("Output {idx} asset commitment missing"))?;
    let value_commitment = value_comm
        .commitment()
        .ok_or_else(|| anyhow::anyhow!("Output {idx} value commitment missing"))?;
    // The explicit-value / explicit-asset proofs: what lets a verifier check the
    // commitments against the amounts the PSET still states in the clear.
    let blind_asset_proof = SurjectionProof::blind_asset_proof(rng, secp, asset_id, abf)
        .map_err(|e| anyhow::anyhow!("Output {idx} blind_asset_proof failed: {e}"))?;
    let blind_value_proof =
        RangeProof::blind_value_proof(rng, secp, value, value_commitment, asset_gen, vbf)
            .map_err(|e| anyhow::anyhow!("Output {idx} blind_value_proof failed: {e}"))?;

    let out = &mut pset.outputs_mut()[idx];
    out.value_rangeproof = Some(Box::new(rangeproof));
    out.asset_surjection_proof = Some(Box::new(surjection_proof));
    out.amount_comm = Some(value_commitment);
    out.asset_comm = Some(asset_gen);
    out.ecdh_pubkey = nonce.commitment().map(|pk| lwk_wollet::elements::bitcoin::PublicKey {
        inner: pk,
        compressed: true,
    });
    out.blind_asset_proof = Some(Box::new(blind_asset_proof));
    out.blind_value_proof = Some(Box::new(blind_value_proof));

    Ok(value)
}

/// Rough per-input witness weight (WU) for fee estimation. The unsigned draft PSET
/// carries no input witnesses, so we add an allowance: a single-sig spend for wallet
/// inputs, and a (larger) allowance for the Simplicity witness — program, control
/// block, signature — of covenant inputs, whose exact size is only known after
/// finalization. Erring high here keeps recursive-covenant spends above the relay
/// minimum; the leftover is absorbed by the fee.
fn estimated_input_witness_weight(req: &BuildPsetRequest) -> usize {
    const WALLET_INPUT_WU: usize = 108;
    const COVENANT_INPUT_WU: usize = 800;
    req.inputs.iter().map(|i| match i {
        PsetInput::Wallet { .. } => WALLET_INPUT_WU,
        PsetInput::Covenant { .. } => COVENANT_INPUT_WU,
    }).sum()
}

/// Estimate the network fee (sats) for `req`, from the resulting transaction's
/// vsize and the requested fee rate. Used to resolve the `fee` formula keyword
/// before output amounts are finalized; the output amounts don't affect vsize, so
/// a draft built from the current (fee=0) amounts gives the right size.
///
/// Note: like the builder's own estimate, this counts a fixed witness allowance
/// for wallet inputs but not the (large, variable) Simplicity witness of covenant
/// inputs — so covenant spends are under-counted, same as elsewhere in the tool.
pub fn estimate_fee(wollet: &Wollet, network: ElementsNetwork, req: &BuildPsetRequest) -> Result<u64> {
    let secp = EC.clone();
    let mut rng = thread_rng();

    let wallet_blinding_pk = wollet
        .address(Some(0))
        .context("Cannot derive wallet address for blinding key")?
        .address()
        .blinding_pubkey
        .context("Wallet address has no blinding key — not a CT descriptor")?;
    let wallet_blinding_pk_btc = btc_pubkey(wallet_blinding_pk);

    let (draft_pset, draft_sec, _) =
        build_inner(wollet, &secp, &mut rng, req, 0, wallet_blinding_pk_btc, network, true, false)?;
    let mut tmp = draft_pset;
    if pset_has_confidential_output(&tmp) {
        tmp.blind_last(&mut rng, &secp, &draft_sec)
            .map_err(|e| anyhow::anyhow!("Fee estimation blind failed: {e}"))?;
    }
    let tx = tmp
        .extract_tx()
        .map_err(|e| anyhow::anyhow!("Fee estimation extract_tx failed: {e}"))?;
    let tx_weight = tx.weight();
    let inp_weight = estimated_input_witness_weight(req);
    let vsize = (tx_weight + inp_weight).div_ceil(4) as f32;
    Ok((vsize * req.fee_rate).ceil() as u64)
}

// ---------------------------------------------------------------------------
// Inner builder (called twice for fee estimation)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_inner(
    wollet: &Wollet,
    secp: &lwk_wollet::elements::secp256k1_zkp::Secp256k1<lwk_wollet::elements::secp256k1_zkp::All>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    req: &BuildPsetRequest,
    fee: u64,
    wallet_blinding_pk: lwk_wollet::elements::bitcoin::PublicKey,
    network: ElementsNetwork,
    // Estimation pass: don't enforce balance or add change — the fee absorbs any
    // surplus (possibly 0). Used only to measure the resulting tx's vsize.
    draft: bool,
    // Only the final pass checks the absorbed surplus. The weight-estimation pass runs with
    // a placeholder fee of 1, against which every real surplus looks absurd.
    enforce_fee_sanity: bool,
) -> Result<(PartiallySignedTransaction, HashMap<usize, TxOutSecrets>, Vec<IssuanceResult>)> {
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut inp_txout_sec: HashMap<usize, TxOutSecrets> = HashMap::new();
    let mut issuances: Vec<IssuanceResult> = Vec::new();
    let mut total_lbtc_in: u64 = 0;
    // Track non-LBTC wallet input amounts for automatic change output generation.
    let mut wallet_asset_in: HashMap<AssetId, u64> = HashMap::new();

    // Add inputs
    for pset_input in &req.inputs {
        match pset_input {
            PsetInput::Wallet { input_id, utxo, issuance, sequence } => {
                let idx = add_wallet_input(&mut pset, &mut inp_txout_sec, wollet, secp, rng, utxo)?;
                apply_sequence(&mut pset, idx, *sequence);
                if let Some(iso) = issuance {
                    apply_new_issuance(&mut pset, idx, iso)?;
                    let (asset_id, token_id) = pset.inputs()[idx].issuance_ids();
                    // Compute entropy so the caller can store it for future reissuances.
                    let entropy = match iso {
                        IssuanceKind::New { .. } => {
                            let midstate = AssetId::generate_asset_entropy(
                                utxo.outpoint,
                                ContractHash::from_byte_array([0u8; 32]),
                            );
                            Some(midstate.to_byte_array())
                        }
                        IssuanceKind::Reissue { entropy, .. } => Some(*entropy),
                    };
                    issuances.push(IssuanceResult { input_id: input_id.clone(), asset_id, token_id, entropy });
                }
                if utxo.unblinded.asset == req.policy_asset {
                    total_lbtc_in += utxo.unblinded.value;
                } else {
                    *wallet_asset_in.entry(utxo.unblinded.asset).or_default() += utxo.unblinded.value;
                }
            }
            PsetInput::Covenant { input_id, outpoint, script_pubkey, asset, amount, issuance, sequence } => {
                let idx = add_covenant_input(&mut pset, &mut inp_txout_sec, *outpoint, script_pubkey.clone(), *asset, *amount)?;
                apply_sequence(&mut pset, idx, *sequence);
                if let Some(iso) = issuance {
                    // A covenant input may carry either a NEW issuance (e.g. an issuance-factory
                    // covenant minting a fresh NFT from its own outpoint) or a reissuance.
                    let entropy = match iso {
                        IssuanceKind::New { .. } => {
                            apply_new_issuance(&mut pset, idx, iso)?;
                            let midstate = AssetId::generate_asset_entropy(
                                *outpoint,
                                ContractHash::from_byte_array([0u8; 32]),
                            );
                            Some(midstate.to_byte_array())
                        }
                        IssuanceKind::Reissue { entropy, .. } => {
                            apply_reissuance(&mut pset, idx, iso)?;
                            Some(*entropy)
                        }
                    };
                    let (asset_id, token_id) = pset.inputs()[idx].issuance_ids();
                    issuances.push(IssuanceResult { input_id: input_id.clone(), asset_id, token_id, entropy });
                }
                if *asset == req.policy_asset {
                    total_lbtc_in += amount;
                }
            }
        }
    }

    // L-BTC accounting
    let total_lbtc_out: u64 = req.outputs.iter()
        .filter(|o| o.asset == req.policy_asset)
        .map(|o| o.amount)
        .sum();
    // When the action declares a change output, the fee is the estimate and any
    // surplus becomes change. When it doesn't, the fee absorbs the whole surplus
    // (no change output is ever added) — so the tx is exactly the declared outputs
    // plus the fee, as recursive covenants require.
    let (change, fee) = if draft {
        (0u64, total_lbtc_in.saturating_sub(total_lbtc_out))
    } else if req.change_assets.contains(&req.policy_asset) {
        let lbtc_needed = total_lbtc_out + fee;
        if total_lbtc_in < lbtc_needed {
            anyhow::bail!(
                "Insufficient L-BTC: have {} sat, need {} sat (outputs {} + fee {})",
                total_lbtc_in, lbtc_needed, total_lbtc_out, fee
            );
        }
        (total_lbtc_in - lbtc_needed, fee)
    } else {
        if total_lbtc_in <= total_lbtc_out {
            anyhow::bail!(
                "No change output declared, but L-BTC inputs ({} sat) do not exceed outputs ({} sat) — nothing left to cover the fee",
                total_lbtc_in, total_lbtc_out
            );
        }
        let surplus = total_lbtc_in - total_lbtc_out;
        // No change permitted for L-BTC, so the surplus IS the fee — and anything the fee
        // does not account for is value leaving the wallet to no declared destination.
        // Paying it to miners silently is exactly the failure `allow_change` exists to
        // prevent, so the difference is an error, not a donation.
        if enforce_fee_sanity && surplus != fee {
            anyhow::bail!(
                "L-BTC does not balance: inputs exceed outputs by {surplus} sat, but the fee \
                 is {fee} sat, leaving {} sat unaccounted for.\n\
                 This action does not permit L-BTC change, so there is nowhere for it to go. \
                 Either set \"allow_change\": \"lbtc_only\" on the action, declare a change \
                 output, or size the input to outputs + fee exactly.",
                surplus.saturating_sub(fee)
            );
        }
        (0u64, surplus)
    };

    // blinder_index must reference an input whose secrets are in inp_txout_sec (i.e. a wallet
    // input).  Inputs may arrive in any order so we pick the first wallet input by key.
    let blinder_idx = inp_txout_sec
        .keys()
        .copied()
        .min()
        .unwrap_or(0) as u32;

    // Add specified outputs
    for o in &req.outputs {
        pset.add_output(build_output(o.script_pubkey.clone(), o.amount, o.asset, o.blinding_key, blinder_idx));
    }

    // L-BTC change output (if any)
    if change > 0 {
        let change_addr = wollet.change(None).context("Cannot derive change address")?.address().clone();
        let change_bpk = change_addr
            .blinding_pubkey
            .map(btc_pubkey)
            .unwrap_or(wallet_blinding_pk);
        pset.add_output(confidential_output(
            change_addr.script_pubkey(), change, req.policy_asset, change_bpk, blinder_idx
        ));
    }

    // Non-LBTC change outputs: for any wallet-input asset where the input exceeds the outputs.
    let total_non_lbtc_out: HashMap<AssetId, u64> = req.outputs.iter()
        .filter(|o| o.asset != req.policy_asset)
        .fold(HashMap::new(), |mut m, o| { *m.entry(o.asset).or_default() += o.amount; m });
    for (asset, in_amt) in &wallet_asset_in {
        let out_amt = total_non_lbtc_out.get(asset).copied().unwrap_or(0);
        if *in_amt > out_amt && !req.change_assets.contains(asset) {
            // Only the fee may be an output the manifest did not declare. Inventing a
            // change output here would move an asset to an address of the engine's
            // choosing, in an amount nobody wrote down.
            anyhow::bail!(
                "Asset {asset} does not balance: inputs provide {} sat but the outputs \
                 account for only {out_amt} sat.\n\
                 This action does not permit change in that asset, so there is nowhere for \
                 the remaining {} sat to go. Either set \"allow_change\" on the action, \
                 declare a change output for it, or size the input to what the action spends.",
                in_amt,
                in_amt - out_amt
            );
        }
        if *in_amt > out_amt {
            let surplus = in_amt - out_amt;
            let change_addr = wollet.change(None).context("Cannot derive change address")?.address().clone();
            let change_bpk = change_addr.blinding_pubkey.map(btc_pubkey).unwrap_or(wallet_blinding_pk);
            pset.add_output(confidential_output(
                change_addr.script_pubkey(), surplus, *asset, change_bpk, blinder_idx
            ));
        }
    }

    // Fee output
    pset.add_output(Output::new_explicit(Script::default(), fee, req.policy_asset, None));

    let _ = network; // reserved for future address encoding
    Ok((pset, inp_txout_sec, issuances))
}

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------

fn add_wallet_input(
    pset: &mut PartiallySignedTransaction,
    inp_txout_sec: &mut HashMap<usize, TxOutSecrets>,
    wollet: &Wollet,
    secp: &lwk_wollet::elements::secp256k1_zkp::Secp256k1<lwk_wollet::elements::secp256k1_zkp::All>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    utxo: &WalletTxOut,
) -> Result<usize> {
    let txid = Txid::from_str(&utxo.outpoint.txid.to_string()).context("Cannot parse txid")?;
    let wallet_tx = wollet
        .transaction(&txid)
        .context("Cannot look up transaction")?
        .ok_or_else(|| anyhow::anyhow!("Transaction {} not found in wallet", txid))?;
    let mut txout = wallet_tx
        .tx
        .output
        .get(utxo.outpoint.vout as usize)
        .ok_or_else(|| anyhow::anyhow!("vout {} not found in tx", utxo.outpoint.vout))?
        .clone();

    let mut input = Input::from_prevout(utxo.outpoint);
    input.asset = Some(utxo.unblinded.asset);
    input.amount = Some(utxo.unblinded.value);

    // Explicit wallet UTXOs (e.g. outputs sent with confidential: false) carry no commitments.
    // Treat them like covenant inputs: zero blinding factors, no range/surjection proofs.
    let secrets = if txout.value.commitment().is_none() {
        input.witness_utxo = Some(txout);
        TxOutSecrets {
            value: utxo.unblinded.value,
            value_bf: ValueBlindingFactor::zero(),
            asset: utxo.unblinded.asset,
            asset_bf: AssetBlindingFactor::zero(),
        }
    } else {
        let value_comm = txout.value.commitment()
            .ok_or_else(|| anyhow::anyhow!("Input TxOut value is not a commitment"))?;
        let asset_gen = txout.asset.commitment()
            .ok_or_else(|| anyhow::anyhow!("Input TxOut asset is not a commitment"))?;
        input.in_utxo_rangeproof = txout.witness.rangeproof.take();
        input.witness_utxo = Some(txout);
        input.blind_asset_proof = Some(Box::new(
            SurjectionProof::blind_asset_proof(rng, secp, utxo.unblinded.asset, utxo.unblinded.asset_bf)
                .map_err(|e| anyhow::anyhow!("blind_asset_proof failed: {e}"))?,
        ));
        input.blind_value_proof = Some(Box::new(
            RangeProof::blind_value_proof(
                rng, secp,
                utxo.unblinded.value, value_comm, asset_gen,
                utxo.unblinded.value_bf,
            )
            .map_err(|e| anyhow::anyhow!("blind_value_proof failed: {e}"))?,
        ));
        utxo.unblinded
    };

    pset.add_input(input);
    let idx = pset.inputs().len() - 1;
    inp_txout_sec.insert(idx, secrets);
    Ok(idx)
}

/// Add a covenant UTXO with explicit (unblinded) value and asset.
///
/// Covenant inputs have explicit (zero-blinded) values. We add them to `inp_txout_sec` with
/// zero blinding factors so the surjection proof builder treats them as Known inputs rather than
/// Unknown — this is required when reissued assets flow through covenant inputs.
fn add_covenant_input(
    pset: &mut PartiallySignedTransaction,
    inp_txout_sec: &mut HashMap<usize, TxOutSecrets>,
    outpoint: lwk_wollet::elements::OutPoint,
    script_pubkey: Script,
    asset: AssetId,
    amount: u64,
) -> Result<usize> {
    let txout = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    };
    let mut input = Input::from_prevout(outpoint);
    input.witness_utxo = Some(txout);
    input.asset = Some(asset);
    input.amount = Some(amount);
    pset.add_input(input);
    let idx = pset.inputs().len() - 1;
    inp_txout_sec.insert(idx, TxOutSecrets {
        value: amount,
        value_bf: ValueBlindingFactor::zero(),
        asset,
        asset_bf: AssetBlindingFactor::zero(),
    });
    Ok(idx)
}

/// Set the `nSequence` on input `idx`, if one was requested. The value is the raw
/// consensus encoding (callers pre-encode BIP68 relative-block/-time locks); see
/// `lifecycle::encode_sequence`.
fn apply_sequence(pset: &mut PartiallySignedTransaction, idx: usize, sequence: Option<u32>) {
    if let Some(seq) = sequence {
        pset.inputs_mut()[idx].sequence = Some(Sequence::from_consensus(seq));
    }
}

fn apply_new_issuance(pset: &mut PartiallySignedTransaction, idx: usize, iso: &IssuanceKind) -> Result<()> {
    if let IssuanceKind::New { asset_amount, inflation_amount } = iso {
        let input = &mut pset.inputs_mut()[idx];
        if *asset_amount > 0 {
            input.issuance_value_amount = Some(*asset_amount);
        }
        if *inflation_amount > 0 {
            input.issuance_inflation_keys = Some(*inflation_amount);
        }
        input.issuance_asset_entropy = Some([0u8; 32]); // contract hash = zeros
        input.blinded_issuance = Some(0x00); // 0x00 = explicit (not confidential)
    }
    Ok(())
}

fn apply_reissuance(pset: &mut PartiallySignedTransaction, idx: usize, iso: &IssuanceKind) -> Result<()> {
    if let IssuanceKind::Reissue { asset_amount, entropy } = iso {
        let input = &mut pset.inputs_mut()[idx];
        input.issuance_value_amount = Some(*asset_amount);
        input.issuance_asset_entropy = Some(*entropy);
        input.blinded_issuance = Some(0x00); // 0x00 = explicit (not confidential)
        // issuance_blinding_nonce must be non-zero so issuance_ids() takes the re-issuance
        // code path (entropy used directly) rather than the new-issuance path (entropy derived
        // from outpoint). For explicit (non-confidential) RT UTXOs the actual asset blinding
        // factor is zero, but ZERO_TWEAK would be misread as "new issuance". Use the minimal
        // non-zero scalar [0..0, 1] as a conventional explicit-reissuance marker.
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[31] = 1;
        input.issuance_blinding_nonce = Some(
            Tweak::from_slice(&nonce_bytes)
                .map_err(|e| anyhow::anyhow!("reissuance nonce: {e}"))?,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn build_output(
    script_pubkey: Script,
    amount: u64,
    asset: AssetId,
    blinding_key: Option<lwk_wollet::elements::bitcoin::PublicKey>,
    blinder_idx: u32,
) -> Output {
    match blinding_key {
        Some(bpk) => confidential_output(script_pubkey, amount, asset, bpk, blinder_idx),
        None => Output::new_explicit(script_pubkey, amount, asset, None),
    }
}

fn confidential_output(
    script_pubkey: Script,
    amount: u64,
    asset: AssetId,
    blinding_key: lwk_wollet::elements::bitcoin::PublicKey,
    blinder_idx: u32,
) -> Output {
    Output {
        script_pubkey,
        amount: Some(amount),
        asset: Some(asset),
        blinding_key: Some(blinding_key),
        blinder_index: Some(blinder_idx),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Asset ID computation from issuance outpoint
// ---------------------------------------------------------------------------

/// Compute (asset_id, token_id) deterministically from a new-issuance outpoint.
///
/// Uses the elements library's canonical formula:
///   prevout_hash = SHA256D(consensus_encode(outpoint))
///   entropy      = fast_merkle_root([prevout_hash, zero_contract_hash])
///   asset        = SHA256(entropy || 0x00) as Midstate
///   token        = SHA256(entropy || 0x01) as Midstate  (explicit, confidential=false)
pub fn compute_asset_ids_from_outpoint(txid_display: &str, vout: u32) -> Result<(AssetId, AssetId)> {
    let txid = Txid::from_str(txid_display)
        .map_err(|e| anyhow::anyhow!("Cannot parse txid '{txid_display}': {e}"))?;
    let outpoint = OutPoint::new(txid, vout);
    let contract_hash = ContractHash::from_byte_array([0u8; 32]);
    let asset_id = AssetId::new_issuance(outpoint, contract_hash);
    let token_id = AssetId::new_reissuance_token(outpoint, contract_hash, false);
    Ok((asset_id, token_id))
}

/// Compute the reissued asset_id from a known issuance entropy (32 bytes, SHA256 midstate).
pub fn compute_asset_from_entropy(entropy: &[u8; 32]) -> Result<AssetId> {
    let midstate = sha256::Midstate::from_byte_array(*entropy);
    Ok(AssetId::from_entropy(midstate))
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn btc_pubkey(pk: lwk_wollet::elements::secp256k1_zkp::PublicKey) -> lwk_wollet::elements::bitcoin::PublicKey {
    lwk_wollet::elements::bitcoin::PublicKey { inner: pk, compressed: true }
}

/// Resolve the covenant address for a utxo_type and return its script_pubkey.
pub fn covenant_script_pubkey(
    simf_path: &std::path::Path,
    compile_params: &HashMap<String, String>,
    type_hints: &HashMap<String, String>,
    extra_leaf_payloads: &[Vec<u8>],
    network: ElementsNetwork,
    opts: impl Into<covenant::CompileOpts>,
) -> Result<Script> {
    let addr = covenant::compute_covenant_address(simf_path, compile_params, type_hints, extra_leaf_payloads, network, opts)
        .with_context(|| "Cannot compute covenant address")?;
    Ok(addr.script_pubkey())
}

/// Decode a 32-byte hex string into bytes.
pub fn decode_entropy_hex(hex: &str) -> Result<[u8; 32]> {
    let clean = hex.trim_start_matches("0x");
    if clean.len() != 64 {
        anyhow::bail!("Expected 64 hex chars for entropy, got {}", clean.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("Invalid hex byte at position {i}"))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pinned_blinding_tests {
    use super::*;
    use lwk_wollet::elements::secp256k1_zkp::PublicKey;

    /// The 32-byte scalar `n`, right-aligned — the spelling `"1"` resolves to.
    fn scalar(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = n;
        b
    }

    fn test_asset(tag: u8) -> AssetId {
        AssetId::from_entropy(sha256::Midstate::from_byte_array([tag; 32]))
    }

    fn test_spk(tag: u8) -> Script {
        let mut b = Vec::with_capacity(34);
        b.push(0x51);
        b.push(0x20);
        b.extend_from_slice(&[tag; 32]);
        Script::from(b)
    }

    /// One explicit input, two confidential outputs (the first with pinned factors) and a
    /// fee. The transaction must verify the way a node verifies it, and the pinned output
    /// must open to exactly the factors the manifest named — the whole point being that the
    /// next spender can reproduce them without holding a secret.
    #[test]
    fn pinned_factors_reach_the_chain_and_the_tx_still_balances() {
        let secp = EC.clone();
        let mut rng = rand::thread_rng();
        let asset = test_asset(7);
        let one_abf = AssetBlindingFactor::from_slice(&scalar(1)).unwrap();
        let one_vbf = ValueBlindingFactor::from_slice(&scalar(1)).unwrap();

        let prev = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(1000),
            nonce: Nonce::Null,
            script_pubkey: test_spk(1),
            witness: TxOutWitness::default(),
        };
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([1u8; 32]),
            0,
        ));
        input.witness_utxo = Some(prev.clone());
        input.asset = Some(asset);
        input.amount = Some(1000);
        pset.add_input(input);

        let mut secrets = HashMap::new();
        secrets.insert(0usize, TxOutSecrets {
            value: 1000,
            value_bf: ValueBlindingFactor::zero(),
            asset,
            asset_bf: AssetBlindingFactor::zero(),
        });

        let pinned_sk = SecretKey::new(&mut rng);
        let free_sk = SecretKey::new(&mut rng);
        pset.add_output(confidential_output(
            test_spk(2), 600, asset, btc_pubkey(PublicKey::from_secret_key(&secp, &pinned_sk)), 0,
        ));
        pset.add_output(confidential_output(
            test_spk(3), 300, asset, btc_pubkey(PublicKey::from_secret_key(&secp, &free_sk)), 0,
        ));
        pset.add_output(Output::new_explicit(Script::default(), 100, asset, None));

        let pins = HashMap::from([(
            0usize,
            PinnedBlinding { asset_bf: Some(one_abf), value_bf: Some(one_vbf) },
        )]);
        blind_with_pinned_factors(&mut pset, &secp, &mut rng, &secrets, &pins)
            .expect("pinned blinding");

        let tx = pset.extract_tx().expect("extract_tx");
        tx.verify_tx_amt_proofs(&secp, &[prev])
            .expect("rangeproofs, surjection proofs and the commitment balance must all check");

        let opened = tx.output[0].unblind(&secp, pinned_sk).expect("unblind pinned output");
        assert_eq!(opened.asset_bf, one_abf, "pinned abf must reach the chain verbatim");
        assert_eq!(opened.value_bf, one_vbf, "pinned vbf must reach the chain verbatim");
        assert_eq!(opened.value, 600);
        assert_eq!(opened.asset, asset);
    }

    /// Pinning every confidential output leaves the balance residue nowhere to go. That is
    /// unsatisfiable rather than merely unusual, so it must fail loudly at build time — not
    /// produce a transaction a node rejects.
    #[test]
    fn pinning_every_value_bf_is_rejected() {
        let secp = EC.clone();
        let mut rng = rand::thread_rng();
        let asset = test_asset(9);
        let one_abf = AssetBlindingFactor::from_slice(&scalar(1)).unwrap();
        let one_vbf = ValueBlindingFactor::from_slice(&scalar(1)).unwrap();

        let prev = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(1000),
            nonce: Nonce::Null,
            script_pubkey: test_spk(1),
            witness: TxOutWitness::default(),
        };
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([2u8; 32]), 0));
        input.witness_utxo = Some(prev);
        input.asset = Some(asset);
        input.amount = Some(1000);
        pset.add_input(input);

        let mut secrets = HashMap::new();
        secrets.insert(0usize, TxOutSecrets {
            value: 1000,
            value_bf: ValueBlindingFactor::zero(),
            asset,
            asset_bf: AssetBlindingFactor::zero(),
        });

        let sk = SecretKey::new(&mut rng);
        pset.add_output(confidential_output(
            test_spk(2), 900, asset, btc_pubkey(PublicKey::from_secret_key(&secp, &sk)), 0,
        ));
        pset.add_output(Output::new_explicit(Script::default(), 100, asset, None));

        let pins = HashMap::from([(
            0usize,
            PinnedBlinding { asset_bf: Some(one_abf), value_bf: Some(one_vbf) },
        )]);
        let err = blind_with_pinned_factors(&mut pset, &secp, &mut rng, &secrets, &pins)
            .expect_err("no output left free to balance");
        assert!(
            err.to_string().contains("value blinding factor"),
            "error must name the missing free factor, got: {err}"
        );
    }
}
