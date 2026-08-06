// Dump a saved PSET's per-asset balance, to find out which asset does not add up.
//
//   cargo run -p tx-manifest-lib --example pset_balance -- <path-to-pset.hex>
//
// Elements rejects an unbalanced transaction with `bad-txns-in-ne-out`, which names no
// asset and no index. This prints every leg the PSET knows about — inputs, issuances,
// outputs — grouped by asset, so the missing or surplus amount is visible directly.
// Confidential legs are reported as such rather than guessed at.
use std::collections::BTreeMap;

use lwk_wollet::elements::encode::Decodable;
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements::AssetId;

#[derive(Default)]
struct Leg {
    inputs: u64,
    issued: u64,
    outputs: u64,
    blinded_in: usize,
    blinded_out: usize,
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: pset_balance <pset.hex>");
    let hex = std::fs::read_to_string(&path).expect("read pset").trim().to_string();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let pset = PartiallySignedTransaction::consensus_decode(&bytes[..]).expect("decode pset");

    let mut legs: BTreeMap<String, Leg> = BTreeMap::new();
    let mut unknown_in = 0usize;

    println!("== inputs ==");
    for (i, inp) in pset.inputs().iter().enumerate() {
        match inp.witness_utxo.as_ref() {
            Some(u) => println!(
                "  witness_utxo #{i}: asset={} value={}",
                short(&format!("{:?}", u.asset)),
                short(&format!("{:?}", u.value))
            ),
            None => println!("  witness_utxo #{i}: MISSING"),
        }
    }
    for (i, inp) in pset.inputs().iter().enumerate() {
        let utxo = inp.witness_utxo.as_ref();
        let asset = inp.asset.map(|a| a.to_string()).or_else(|| {
            utxo.and_then(|u| match u.asset {
                lwk_wollet::elements::confidential::Asset::Explicit(a) => Some(a.to_string()),
                _ => None,
            })
        });
        let amount = inp.amount.or_else(|| {
            utxo.and_then(|u| match u.value {
                lwk_wollet::elements::confidential::Value::Explicit(v) => Some(v),
                _ => None,
            })
        });
        match (&asset, amount) {
            (Some(a), Some(v)) => {
                legs.entry(a.clone()).or_default().inputs += v;
                println!("  #{i}  {v:>12}  {a}");
            }
            _ => {
                unknown_in += 1;
                println!(
                    "  #{i}  {:>12}  {}",
                    "confidential",
                    asset.clone().unwrap_or_else(|| "?".into())
                );
                if let Some(a) = asset {
                    legs.entry(a).or_default().blinded_in += 1;
                }
            }
        }

        // Issuance legs. `issuance_value_amount` mints the asset; `issuance_inflation_keys`
        // mints reissuance tokens. Both add to the input side of the balance.
        let (asset_id, token_id) = inp.issuance_ids();
        if let Some(v) = inp.issuance_value_amount {
            legs.entry(asset_id.to_string()).or_default().issued += v;
            let kind = if inp.issuance_blinding_nonce.is_some() { "reissue" } else { "new" };
            println!("      + issuance ({kind}) {v:>10}  {asset_id}");
        }
        if let Some(v) = inp.issuance_inflation_keys {
            legs.entry(token_id.to_string()).or_default().issued += v;
            println!("      + inflation keys  {v:>10}  {token_id}");
        }
    }

    println!("\n== outputs ==");
    for (i, out) in pset.outputs().iter().enumerate() {
        let asset = out.asset.map(|a: AssetId| a.to_string());
        match (&asset, out.amount) {
            (Some(a), Some(v)) => {
                legs.entry(a.clone()).or_default().outputs += v;
                let kind = if out.script_pubkey.is_empty() { " (fee)" } else { "" };
                println!("  #{i}  {v:>12}  {a}{kind}");
            }
            _ => {
                println!("  #{i}  {:>12}  {}", "confidential", asset.clone().unwrap_or_else(|| "?".into()));
                if let Some(a) = asset {
                    legs.entry(a).or_default().blinded_out += 1;
                }
            }
        }
    }

    println!("\n== balance by asset ==");
    println!(
        "  {:<66} {:>12} {:>10} {:>12} {:>10}",
        "asset", "in", "issued", "out", "delta"
    );
    let mut any_bad = false;
    for (asset, leg) in &legs {
        let lhs = leg.inputs + leg.issued;
        let delta = lhs as i128 - leg.outputs as i128;
        let blinded = leg.blinded_in > 0 || leg.blinded_out > 0;
        let note = if blinded {
            format!("  <- {} blinded leg(s), delta not meaningful", leg.blinded_in + leg.blinded_out)
        } else if delta != 0 {
            any_bad = true;
            "  <== DOES NOT BALANCE".to_string()
        } else {
            String::new()
        };
        println!(
            "  {:<66} {:>12} {:>10} {:>12} {:>10}{}",
            asset, leg.inputs, leg.issued, leg.outputs, delta, note
        );
    }
    if unknown_in > 0 {
        println!("\n  ({unknown_in} input(s) had no explicit amount in the PSET)");
    }
    if !any_bad {
        println!("\n  every fully-explicit asset balances; the imbalance is on a blinded leg");
    }

    // The PSET balancing is necessary but not sufficient: what consensus sees is the
    // EXTRACTED transaction. If finalization dropped or altered the issuance legs, the
    // PSET can add up while the broadcast transaction does not.
    if let Some(tx_path) = std::env::args().nth(2) {
        println!("\n== extracted transaction ==");
        let hex = std::fs::read_to_string(&tx_path).expect("read tx").trim().to_string();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let tx = lwk_wollet::elements::Transaction::consensus_decode(&bytes[..]).expect("decode tx");
        for (i, inp) in tx.input.iter().enumerate() {
            let iss = &inp.asset_issuance;
            if iss.is_null() {
                println!("  in #{i}: no issuance");
            } else {
                println!(
                    "  in #{i}: issuance amount={:?} inflation={:?} entropy={} nonce={}",
                    iss.amount,
                    iss.inflation_keys,
                    hex_le(&iss.asset_entropy),
                    hex_le(iss.asset_blinding_nonce.as_ref()),
                );
            }
        }
        for (i, out) in tx.output.iter().enumerate() {
            println!(
                "  out #{i}: asset={:?} value={:?}",
                short(&format!("{:?}", out.asset)),
                short(&format!("{:?}", out.value))
            );
        }

        verify_commitment_balance(&pset, &tx);
        verify_reissuances(&pset, &tx);
        verify_surjections(&pset, &tx);
    }
}

/// Verify each confidential output's surjection proof against the domain consensus builds:
/// every input's asset generator, plus a generator for each issuance leg, in input order.
///
/// `VerifyAmounts` reports a surjection failure under the same `bad-txns-in-ne-out` string
/// as an arithmetic imbalance, so this is the remaining way to tell them apart.
fn verify_surjections(
    pset: &PartiallySignedTransaction,
    tx: &lwk_wollet::elements::Transaction,
) {
    use lwk_wollet::elements::confidential::{Asset, Value};
    use lwk_wollet::elements::secp256k1_zkp::{Generator, Secp256k1, Tag};

    let secp = Secp256k1::new();
    let unblinded = |a: lwk_wollet::elements::AssetId| {
        Generator::new_unblinded(&secp, Tag::from(a.into_inner().to_byte_array()))
    };

    let mut domain: Vec<Generator> = Vec::new();
    for (i, inp) in pset.inputs().iter().enumerate() {
        if let Some(utxo) = inp.witness_utxo.as_ref() {
            match utxo.asset {
                Asset::Explicit(a) => domain.push(unblinded(a)),
                Asset::Confidential(g) => domain.push(g),
                _ => {}
            }
        }
        let (asset_id, token_id) = inp.issuance_ids();
        let iss = &tx.input[i].asset_issuance;
        if !matches!(iss.amount, Value::Null) {
            domain.push(unblinded(asset_id));
        }
        if !matches!(iss.inflation_keys, Value::Null) {
            domain.push(unblinded(token_id));
        }
    }

    println!("\n== surjection proofs ==");
    println!("  domain: {} generator(s)", domain.len());
    for (i, out) in tx.output.iter().enumerate() {
        let Asset::Confidential(out_gen) = out.asset else { continue };
        println!(
            "  out #{i}: rangeproof {} bytes, surjection {} bytes",
            out.witness.rangeproof.as_ref().map(|p| p.serialize().len()).unwrap_or(0),
            out.witness.surjection_proof.as_ref().map(|p| p.serialize().len()).unwrap_or(0),
        );
        match &out.witness.surjection_proof {
            None => println!("  out #{i}: CONFIDENTIAL BUT NO SURJECTION PROOF"),
            Some(proof) => {
                let ok = proof.verify(&secp, out_gen, &domain);
                println!(
                    "  out #{i}: surjection proof {}",
                    if ok { "verifies" } else { "FAILS <== this is the rejection" }
                );
            }
        }
    }
}

/// For every reissuance, check the two things consensus checks: that the entropy produces
/// the asset the transaction claims to be minting, and that the UTXO being spent really is
/// that entropy's reissuance token.
///
/// The second is the one worth testing. The token id depends on whether the ORIGINAL
/// issuance blinded its amounts (`CalculateReissuanceToken(entropy, fBlinded)`), and this
/// engine hardcodes `false` when it derives the token. If the chain disagrees, the input is
/// simply not the token for this entropy and the reissuance is invalid.
fn verify_reissuances(
    pset: &PartiallySignedTransaction,
    tx: &lwk_wollet::elements::Transaction,
) {
    use lwk_wollet::elements::confidential::Asset;
    use lwk_wollet::elements::hashes::sha256;
    use lwk_wollet::elements::AssetId;

    println!("\n== reissuance validity ==");
    for (i, inp) in pset.inputs().iter().enumerate() {
        let iss = &tx.input[i].asset_issuance;
        if iss.is_null() || iss.asset_blinding_nonce.as_ref().iter().all(|b| *b == 0) {
            continue; // not a reissuance
        }
        let entropy = sha256::Midstate::from_byte_array(iss.asset_entropy);
        let derived_asset = AssetId::from_entropy(entropy);

        let spent = inp.witness_utxo.as_ref().map(|u| u.asset);
        let spent_explicit = match spent {
            Some(Asset::Explicit(a)) => Some(a),
            _ => None,
        };

        println!("  in #{i}");
        println!("    entropy            {}", hex_le(&iss.asset_entropy));
        println!("    derived asset      {derived_asset}");
        for confidential in [false, true] {
            let token = AssetId::reissuance_token_from_entropy(entropy, confidential);
            let hit = spent_explicit.map(|a| a == token).unwrap_or(false);
            println!(
                "    token (blinded={confidential:<5})  {token}{}",
                if hit { "  <== matches the UTXO being spent" } else { "" }
            );
        }
        match spent_explicit {
            Some(a) => {
                let ok = (0..2).any(|c| AssetId::reissuance_token_from_entropy(entropy, c == 1) == a);
                println!("    spending           {a}");
                if !ok {
                    println!(
                        "    ^^ this UTXO is NOT the reissuance token for that entropy — the \
                         reissuance is invalid regardless of how the amounts balance"
                    );
                }
            }
            None => println!("    spending           (confidential asset)"),
        }
    }
}

/// Check the Pedersen balance the way consensus does: sum(input commitments) +
/// sum(issuance commitments) == sum(output commitments).
///
/// This is what separates the two candidate causes. If the commitments balance, the
/// transaction is arithmetically fine and Elements is rejecting it for an issuance-validity
/// reason (which it reports under the same `bad-txns-in-ne-out` string). If they do not,
/// the blinder produced the wrong final blinding factor.
fn verify_commitment_balance(
    pset: &PartiallySignedTransaction,
    tx: &lwk_wollet::elements::Transaction,
) {
    use lwk_wollet::elements::confidential::{Asset, Value};
    use lwk_wollet::elements::secp256k1_zkp::{
        self, Generator, PedersenCommitment, Secp256k1, Tag,
    };

    let secp = Secp256k1::new();
    let gen_for = |asset: &Asset| -> Option<Generator> {
        match asset {
            Asset::Explicit(a) => {
                Some(Generator::new_unblinded(&secp, Tag::from(a.into_inner().to_byte_array())))
            }
            Asset::Confidential(g) => Some(*g),
            _ => None,
        }
    };
    let commit = |value: &Value, gen: Generator| -> Option<PedersenCommitment> {
        match value {
            Value::Explicit(v) => Some(PedersenCommitment::new_unblinded(&secp, *v, gen)),
            Value::Confidential(c) => Some(*c),
            _ => None,
        }
    };

    let mut lhs: Vec<PedersenCommitment> = Vec::new();
    let mut rhs: Vec<PedersenCommitment> = Vec::new();
    let mut skipped = 0;

    for (i, inp) in pset.inputs().iter().enumerate() {
        let Some(utxo) = inp.witness_utxo.as_ref() else { skipped += 1; continue };
        match gen_for(&utxo.asset).and_then(|g| commit(&utxo.value, g)) {
            Some(c) => lhs.push(c),
            None => skipped += 1,
        }
        // Explicit issuance legs enter the input side as value * H_asset, unblinded.
        let (asset_id, token_id) = inp.issuance_ids();
        let tx_iss = &tx.input[i].asset_issuance;
        if let Value::Explicit(v) = tx_iss.amount {
            let g = Generator::new_unblinded(&secp, Tag::from(asset_id.into_inner().to_byte_array()));
            lhs.push(PedersenCommitment::new_unblinded(&secp, v, g));
        }
        if let Value::Explicit(v) = tx_iss.inflation_keys {
            let g = Generator::new_unblinded(&secp, Tag::from(token_id.into_inner().to_byte_array()));
            lhs.push(PedersenCommitment::new_unblinded(&secp, v, g));
        }
    }

    for out in &tx.output {
        match gen_for(&out.asset).and_then(|g| commit(&out.value, g)) {
            Some(c) => rhs.push(c),
            None => skipped += 1,
        }
    }

    let ok = secp256k1_zkp::verify_commitments_sum_to_equal(&secp, &lhs, &rhs);
    println!(
        "\n== pedersen balance ==\n  {} input+issuance commitments vs {} output commitments{}",
        lhs.len(),
        rhs.len(),
        if skipped > 0 { format!(" ({skipped} leg(s) skipped)") } else { String::new() }
    );
    if ok {
        println!("  BALANCES — the commitments sum to equal, so the arithmetic is fine and");
        println!("  Elements is rejecting this for an issuance-validity reason instead.");
    } else {
        println!("  DOES NOT BALANCE — the blinder produced a final blinding factor that does");
        println!("  not account for every leg. This is the cause of bad-txns-in-ne-out.");
    }
}

fn hex_le(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn short(s: &str) -> String {
    if s.len() > 44 { format!("{}…", &s[..44]) } else { s.to_string() }
}
