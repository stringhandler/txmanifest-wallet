//! Messages carried inside a confidential output's value rangeproof.
//!
//! Elements signs every confidential output's rangeproof over an author-supplied
//! message and uses only the first 64 bytes of it (asset id ‖ asset blinding factor).
//! The rest is recovered verbatim by a rewind, is readable only by the holder of the
//! output's blinding key, and — because `min_bits = 52` forces the ring count — costs
//! nothing in proof size. That unused tail is what this module writes into.
//!
//! The frame written after the Elements prefix is byte-compatible with `lrp-core`
//! (the `liquidrangeproof` / `liquid-nostr-bridge` proof of concept), so an output
//! built here reads back with those tools and with the bridge relay:
//!
//! ```text
//! magic "LRPM" (4B) | version u8 | len u16 LE | payload (len B) | crc32 u32 LE
//! ```
//!
//! Unlike that proof of concept, nothing here rewinds and replaces an already-built
//! proof. The engine is the blinder, so it knows the ephemeral secret and can sign the
//! extended message on the first pass — which also means an embed can ride on an
//! output paying *someone else's* confidential address, not only our own.

use anyhow::{bail, ensure, Context, Result};
use lwk_wollet::elements::{
    confidential::{Asset, Nonce, Value},
    secp256k1_zkp::{
        Generator, PedersenCommitment, RangeProof, Secp256k1, SecretKey, Verification,
    },
    TxOut,
};

/// Frame magic. Shared with `lrp-core`; changing it forks the format.
pub const MAGIC: &[u8; 4] = b"LRPM";

/// Frame version.
pub const VERSION: u8 = 1;

/// Bytes of frame overhead around the payload: magic + version + len + crc32.
pub const FRAME_OVERHEAD: usize = 4 + 1 + 2 + 4;

/// Bytes Elements reserves at the front of the message: 32-byte asset id followed by
/// the 32-byte asset blinding factor.
pub const PREFIX_LEN: usize = 64;

/// Total rangeproof message capacity, in bytes.
///
/// `secp256k1_rangeproof_sign` rejects any message longer than `128 * (rings - 1)`.
/// With `RANGEPROOF_MIN_PRIV_BITS = 52` — what Elements always signs with, and what
/// [`crate::pset_builder`] therefore has to match — the mantissa is forced to 52,
/// giving `rings = (52 + 1) >> 1 = 26` and a cap of `128 * 25`. Asserted by
/// `capacity_is_exactly_as_derived` rather than taken on trust from the C source.
pub const MESSAGE_CAPACITY: usize = 3200;

/// Bytes available to a manifest's payload, after the Elements prefix and the framing.
pub const MAX_PAYLOAD: usize = MESSAGE_CAPACITY - PREFIX_LEN - FRAME_OVERHEAD;

/// Wrap `payload` in a frame.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= MAX_PAYLOAD,
        "rangeproof payload is {} bytes but only {MAX_PAYLOAD} fit \
         ({MESSAGE_CAPACITY} byte message capacity, less {PREFIX_LEN} reserved by \
         Elements and {FRAME_OVERHEAD} of framing)",
        payload.len()
    );

    let mut out = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    Ok(out)
}

/// Recover a payload from the start of `buf`, which may carry arbitrary trailing
/// padding — a rewind always returns the full capacity, zero-filled.
///
/// `Ok(None)` means `buf` carries no frame at all (the common case: an ordinary
/// output, whose message tail is all zeros). `Err` means a frame is present but
/// malformed, which is worth reporting rather than silently skipping.
pub fn decode_frame(buf: &[u8]) -> Result<Option<Vec<u8>>> {
    if buf.len() < FRAME_OVERHEAD || &buf[..4] != MAGIC {
        return Ok(None);
    }

    let version = buf[4];
    ensure!(
        version == VERSION,
        "unsupported rangeproof frame version {version} (this build understands {VERSION})"
    );

    let len = u16::from_le_bytes([buf[5], buf[6]]) as usize;
    let end = FRAME_OVERHEAD + len;
    ensure!(
        end <= buf.len(),
        "rangeproof frame claims a {len}-byte payload but only {} bytes remain",
        buf.len().saturating_sub(FRAME_OVERHEAD - 4)
    );

    let payload = &buf[7..7 + len];
    let expected = u32::from_le_bytes([buf[end - 4], buf[end - 3], buf[end - 2], buf[end - 1]]);
    let actual = crc32fast::hash(payload);
    ensure!(
        actual == expected,
        "rangeproof frame checksum mismatch: expected {expected:08x}, computed {actual:08x}"
    );

    Ok(Some(payload.to_vec()))
}

/// Build the full rangeproof message for an output: the 64 bytes Elements requires,
/// followed by the framed payload when the manifest asked for one.
///
/// Keeping the prefix byte-identical to what `RangeProofMessage::to_bytes` produces is
/// what lets an ordinary wallet unblind the output as usual — the embed is invisible to
/// anything not looking for it.
pub fn build_message(prefix: [u8; PREFIX_LEN], payload: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut message = Vec::with_capacity(MESSAGE_CAPACITY);
    message.extend_from_slice(&prefix);
    if let Some(payload) = payload {
        message.extend_from_slice(&encode_frame(payload)?);
    }
    Ok(message)
}

/// Pull the confidential commitments out of a `TxOut`, erroring clearly when the
/// output is not a blinded one (a fee or OP_RETURN leg, say).
fn confidential_parts(txout: &TxOut) -> Result<(PedersenCommitment, Generator, &RangeProof)> {
    let value_commitment = match txout.value {
        Value::Confidential(c) => c,
        _ => bail!("output value is not confidential, so it carries no rangeproof message"),
    };
    let asset_generator = match txout.asset {
        Asset::Confidential(g) => g,
        _ => bail!("output asset is not confidential"),
    };
    let proof = txout
        .witness
        .rangeproof
        .as_deref()
        .context("output has no rangeproof")?;
    Ok((value_commitment, asset_generator, proof))
}

/// The ECDH shared secret between the sender's ephemeral key (recorded in the output's
/// nonce) and a blinding key. This is what both blinding and rewinding key off.
fn shared_secret(nonce: &Nonce, blinding_sk: &SecretKey) -> Result<SecretKey> {
    nonce
        .shared_secret(blinding_sk)
        .context("output has no ECDH nonce, so no shared secret can be derived")
}

/// Rewind an output's rangeproof and return the message tail that follows the Elements
/// prefix, padding included.
pub fn rewind_tail<C: Verification>(
    secp: &Secp256k1<C>,
    txout: &TxOut,
    blinding_sk: &SecretKey,
) -> Result<Vec<u8>> {
    let (value_commitment, asset_generator, proof) = confidential_parts(txout)?;
    let secret = shared_secret(&txout.nonce, blinding_sk)?;

    let (opening, _range) = proof
        .rewind(
            secp,
            value_commitment,
            secret,
            txout.script_pubkey.as_bytes(),
            asset_generator,
        )
        .map_err(|e| anyhow::anyhow!("rangeproof rewind failed: {e}"))?;

    ensure!(
        opening.message.len() >= PREFIX_LEN,
        "rewound message is {} bytes, too short to hold the Elements prefix",
        opening.message.len()
    );
    Ok(opening.message[PREFIX_LEN..].to_vec())
}

/// Read an embedded message out of a confidential output, given its blinding key.
///
/// `Ok(None)` means the output rewound cleanly but carries no message.
pub fn extract_message<C: Verification>(
    secp: &Secp256k1<C>,
    txout: &TxOut,
    blinding_sk: &SecretKey,
) -> Result<Option<Vec<u8>>> {
    decode_frame(&rewind_tail(secp, txout, blinding_sk)?)
}

/// Render a payload for a terminal: as a signed nostr event when it is one, as text
/// when it is valid UTF-8, and as hex otherwise.
pub fn describe_payload(payload: &[u8]) -> String {
    if let Some(rendered) = crate::nostr_embed::describe(payload) {
        return rendered;
    }
    match std::str::from_utf8(payload) {
        Ok(text) if text.chars().all(|c| !c.is_control() || c.is_whitespace()) => text.to_string(),
        _ => format!("{} bytes (binary): {}", payload.len(), hex_of(payload)),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let shown = &bytes[..bytes.len().min(64)];
    let mut s = shown.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    if bytes.len() > shown.len() {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    use lwk_wollet::elements::secp256k1_zkp::{Tag, Tweak};
    use lwk_wollet::elements::Script;
    use lwk_wollet::elements::AssetId;

    fn round_trip(payload: &[u8]) {
        let frame = encode_frame(payload).unwrap();
        assert_eq!(frame.len(), FRAME_OVERHEAD + payload.len());
        assert_eq!(decode_frame(&frame).unwrap().as_deref(), Some(payload));
    }

    #[test]
    fn frames_round_trip() {
        round_trip(b"");
        round_trip(b"hello liquid");
        round_trip(&[0u8; 1024]);
        round_trip(&vec![0x5au8; MAX_PAYLOAD]);
    }

    #[test]
    fn tolerates_trailing_padding() {
        // Exactly what a rewind returns: the frame followed by zero padding.
        let mut buf = encode_frame(b"padded").unwrap();
        buf.resize(MESSAGE_CAPACITY - PREFIX_LEN, 0);
        assert_eq!(decode_frame(&buf).unwrap().as_deref(), Some(&b"padded"[..]));
    }

    #[test]
    fn an_ordinary_output_is_not_a_frame() {
        assert!(decode_frame(&[0u8; MESSAGE_CAPACITY - PREFIX_LEN]).unwrap().is_none());
        assert!(decode_frame(&[]).unwrap().is_none());
        assert!(decode_frame(b"LRP").unwrap().is_none());
        assert!(decode_frame(b"NOPE and then some padding").unwrap().is_none());
    }

    #[test]
    fn rejects_corruption_and_bad_headers() {
        let mut frame = encode_frame(b"tamper with me").unwrap();
        frame[8] ^= 0xff;
        assert!(decode_frame(&frame).is_err());

        let mut frame = encode_frame(b"short").unwrap();
        frame[5] = 0xff;
        assert!(decode_frame(&frame).is_err());

        let mut frame = encode_frame(b"from the future").unwrap();
        frame[4] = 99;
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn refuses_a_payload_that_cannot_fit() {
        let err = encode_frame(&vec![0u8; MAX_PAYLOAD + 1]).unwrap_err().to_string();
        assert!(err.contains("only 3125 fit"), "unhelpful message: {err}");
    }

    /// The frame layout is the contract with `lrp-core`; pin the bytes so a refactor
    /// here cannot silently fork it.
    #[test]
    fn frame_layout_matches_lrp_core() {
        assert_eq!(
            encode_frame(b"hi").unwrap(),
            b"LRPM\x01\x02\x00hi\xac\x2a\x93\xd8".to_vec(),
        );
        assert_eq!(MAX_PAYLOAD, 3125);
    }

    // -- Proof-level facts, measured rather than asserted from the C source. ----

    struct Fixture {
        secp: Secp256k1<lwk_wollet::elements::secp256k1_zkp::All>,
        commitment: PedersenCommitment,
        generator: Generator,
        value: u64,
        vbf: Tweak,
        nonce: SecretKey,
        spk: Script,
    }

    fn fixture(value: u64) -> Fixture {
        let secp = Secp256k1::new();
        let generator =
            Generator::new_blinded(&secp, Tag::from([7u8; 32]), Tweak::from_inner([3u8; 32]).unwrap());
        let vbf = Tweak::from_inner([5u8; 32]).unwrap();
        let commitment = PedersenCommitment::new(&secp, value, vbf, generator);
        Fixture {
            secp,
            commitment,
            generator,
            value,
            vbf,
            nonce: SecretKey::from_slice(&[9u8; 32]).unwrap(),
            spk: Script::from(vec![0x00, 0x14, 0xab]),
        }
    }

    fn sign(f: &Fixture, message: &[u8]) -> Result<RangeProof, lwk_wollet::elements::secp256k1_zkp::Error> {
        RangeProof::new(
            &f.secp,
            TxOut::RANGEPROOF_MIN_VALUE,
            f.commitment,
            f.value,
            f.vbf,
            message,
            f.spk.as_bytes(),
            f.nonce,
            TxOut::RANGEPROOF_EXP_SHIFT,
            TxOut::RANGEPROOF_MIN_PRIV_BITS,
            f.generator,
        )
    }

    #[test]
    fn capacity_is_exactly_as_derived() {
        let f = fixture(100_000);
        assert!(sign(&f, &vec![0xab; MESSAGE_CAPACITY]).is_ok());
        assert!(sign(&f, &vec![0xab; MESSAGE_CAPACITY + 1]).is_err());
    }

    /// The whole premise: an embed must not change the transaction's size, or the fee
    /// the builder estimated on the first pass would be wrong on the second.
    #[test]
    fn message_length_does_not_change_proof_size() {
        let f = fixture(100_000);
        let bare = sign(&f, &[0u8; PREFIX_LEN]).unwrap();
        let full = sign(&f, &vec![0xcd; MESSAGE_CAPACITY]).unwrap();
        assert_eq!(bare.serialize().len(), full.serialize().len());
    }

    /// Capacity must not depend on the amount, or a dust-sized output would silently
    /// truncate a message that fits elsewhere.
    #[test]
    fn capacity_is_independent_of_value() {
        for value in [1u64, 1_000, 21_000_000 * 100_000_000] {
            let f = fixture(value);
            assert!(
                sign(&f, &vec![0xab; MESSAGE_CAPACITY]).is_ok(),
                "value {value} did not accept a full-capacity message"
            );
        }
    }

    /// End to end through the public API: blind an output the way `pset_builder` does,
    /// then read the payload back with only the receiver's blinding key.
    #[test]
    fn round_trips_through_a_blinded_output() {
        let secp = Secp256k1::new();
        let asset = AssetId::from_slice(&[0x11u8; 32]).unwrap();
        let abf = AssetBlindingFactor::from_slice(&[0x22u8; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[0x33u8; 32]).unwrap();
        let value = 100_000u64;
        let spk = Script::from(vec![0x00, 0x14, 0xcd]);

        let blinding_sk = SecretKey::from_slice(&[0x44u8; 32]).unwrap();
        let blinding_pk = blinding_sk.public_key(&secp);
        let ephemeral_sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();

        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut prefix = [0u8; PREFIX_LEN];
        prefix[..32].copy_from_slice(asset.into_tag().as_ref());
        prefix[32..].copy_from_slice(abf.into_inner().as_ref());
        let message = build_message(prefix, Some(payload)).unwrap();

        let (nonce, secret) = Nonce::with_ephemeral_sk(&secp, ephemeral_sk, &blinding_pk);
        let asset_gen = Generator::new_blinded(&secp, asset.into_tag(), abf.into_inner());
        let value_comm = Value::new_confidential(&secp, value, asset_gen, vbf);
        let proof = RangeProof::new(
            &secp,
            TxOut::RANGEPROOF_MIN_VALUE,
            value_comm.commitment().unwrap(),
            value,
            vbf.into_inner(),
            &message,
            spk.as_bytes(),
            secret,
            TxOut::RANGEPROOF_EXP_SHIFT,
            TxOut::RANGEPROOF_MIN_PRIV_BITS,
            asset_gen,
        )
        .unwrap();

        let txout = TxOut {
            asset: Asset::Confidential(asset_gen),
            value: value_comm,
            nonce,
            script_pubkey: spk,
            witness: lwk_wollet::elements::TxOutWitness {
                surjection_proof: None,
                rangeproof: Some(Box::new(proof)),
            },
        };

        // The receiver reads the message…
        assert_eq!(
            extract_message(&secp, &txout, &blinding_sk).unwrap().as_deref(),
            Some(&payload[..])
        );
        // …and ordinary unblinding is untouched, which is what keeps the embed invisible.
        let secrets = txout.unblind(&secp, blinding_sk).unwrap();
        assert_eq!(secrets.value, value);
        assert_eq!(secrets.asset, asset);
        assert_eq!(secrets.asset_bf, abf);

        // Anyone else sees an ordinary confidential output and nothing more.
        let stranger = SecretKey::from_slice(&[0x66u8; 32]).unwrap();
        assert!(extract_message(&secp, &txout, &stranger).is_err());
    }
}
