use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{Context, Result};
use lwk_wollet::{
    elements::{
        confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor},
        hashes::{sha256, Hash as _},
        pset::{Input, Output, PartiallySignedTransaction},
        secp256k1_zkp::{RangeProof, SurjectionProof, Tweak},
        AssetId, ContractHash, OutPoint, Script, Sequence, Txid, TxOut, TxOutWitness,
        BlindAssetProofs, BlindValueProofs, TxOutSecrets,
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
}

pub struct BuildPsetRequest {
    pub inputs: Vec<PsetInput>,
    pub outputs: Vec<PsetOutputSpec>,
    pub fee_rate: f32,
    pub policy_asset: AssetId,
    /// Whether the action declared an explicit `"change"` output. When `false`,
    /// the builder never adds a change output — any L-BTC surplus is folded into
    /// the fee instead. This keeps the output set to exactly the declared outputs
    /// plus the fee, which recursive covenants (e.g. last-will Refresh) require.
    pub build_change: bool,
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
        build_inner(wollet, &secp, &mut rng, req, 1, wallet_blinding_pk_btc, network, false)?;
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
        build_inner(wollet, &secp, &mut rng, req, fee, wallet_blinding_pk_btc, network, false)?;

    wollet
        .add_details(&mut pset)
        .map_err(|e| anyhow::anyhow!("add_details failed: {e}"))?;

    // A fully-explicit tx (e.g. a covenant spend with only covenant + fee outputs)
    // has nothing to blind; `blind_last` errors if asked to blind with no
    // confidential output, so only blind when one is present.
    if pset_has_confidential_output(&pset) {
        pset.blind_last(&mut rng, &secp, &inp_txout_sec)
            .map_err(|e| anyhow::anyhow!("PSET blinding failed: {e}"))?;
    }

    Ok(BuildPsetResult { pset, issuances })
}

/// True if any PSET output is confidential (carries a blinding key). Fully-explicit
/// transactions need no blinding pass.
fn pset_has_confidential_output(pset: &PartiallySignedTransaction) -> bool {
    pset.outputs().iter().any(|o| o.blinding_key.is_some())
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
        build_inner(wollet, &secp, &mut rng, req, 0, wallet_blinding_pk_btc, network, true)?;
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
                    apply_reissuance(&mut pset, idx, iso)?;
                    let (asset_id, token_id) = pset.inputs()[idx].issuance_ids();
                    if let IssuanceKind::Reissue { entropy, .. } = iso {
                        let direct = compute_asset_from_entropy(entropy).unwrap_or_default();
                        eprintln!("[debug] reissuance idx={idx} asset_id={asset_id} token_id={token_id} direct_asset={direct} match={}", asset_id == direct);
                    }
                    issuances.push(IssuanceResult { input_id: input_id.clone(), asset_id, token_id, entropy: None });
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
    } else if req.build_change {
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
        (0u64, total_lbtc_in - total_lbtc_out)
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
) -> Result<Script> {
    let addr = covenant::compute_covenant_address(simf_path, compile_params, type_hints, extra_leaf_payloads, network)
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
