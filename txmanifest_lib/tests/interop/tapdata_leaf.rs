// Pin the `tapdata` extra-leaf encoding against an independent derivation.
//
// A covenant can carry its state in a second taproot leaf: `TapData` over the state's
// bytes, branched with the Simplicity leaf, tweaked onto the NUMS key. Other Simplicity
// toolchains build these by hand-rolling the tagged hashes, so if this engine's encoding
// drifts, every stateful covenant address it computes stops matching theirs.
//
// The engine gets there through `TaprootSpendInfo` over the merkle root it folds itself;
// `expected_spk` below writes the same three tagged hashes out longhand. They must agree.
use std::collections::HashMap;

use lwk_wollet::elements::hashes::{sha256, Hash, HashEngine};
use lwk_wollet::elements::secp256k1_zkp::{Scalar, Secp256k1, XOnlyPublicKey};
use lwk_wollet::ElementsNetwork;
use tx_manifest_lib::context::ExecutionContext;
use tx_manifest_lib::covenant;
use tx_manifest_lib::manifest::Manifest;

/// The engine's covenant internal key (BIP-341 NUMS point).
const NUMS_KEY_BYTES: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

const SIMF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/p2pk/p2pk.simf");

/// SHA256(SHA256(tag) || SHA256(tag) || data).
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// tapdata(state) branched with the Simplicity leaf, tweaked onto NUMS.
fn expected_spk(tapleaf_hash: [u8; 32], state: u64) -> String {
    let data_leaf = tagged_hash(b"TapData", &state.to_be_bytes());
    let (a, b) = if tapleaf_hash <= data_leaf {
        (tapleaf_hash, data_leaf)
    } else {
        (data_leaf, tapleaf_hash)
    };
    let branch = tagged_hash(b"TapBranch/elements", &[a, b].concat());
    let tweak = tagged_hash(b"TapTweak/elements", &[NUMS_KEY_BYTES, branch].concat());

    let secp = Secp256k1::new();
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY_BYTES).expect("NUMS key");
    let (tweaked, _parity) = nums
        .add_tweak(&secp, &Scalar::from_be_bytes(tweak).expect("scalar"))
        .expect("tweak");
    let key: String = tweaked
        .serialize()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    format!("5120{key}")
}

/// One `utxo_type` per state, differing only in the u64 its tapdata leaf carries.
fn manifest(states: &[u64]) -> Manifest {
    let utxo_types: serde_json::Map<String, serde_json::Value> = states
        .iter()
        .map(|state| {
            let ut = serde_json::json!({
                "description": format!("state {state}"),
                "script": {
                    "type": "simplicity",
                    "source": SIMF,
                    "compile_params": { "PUB_KEY": "PUB_KEY" },
                    "extra_leaves": [{
                        "type": "tapdata",
                        "payload": [{ "value": state.to_string(), "type": "u64", "endian": "be" }]
                    }]
                },
                "asset": "lbtc"
            });
            (format!("state_{state}"), ut)
        })
        .collect();
    let raw = serde_json::json!({
        "manifest_version": tx_manifest_lib::manifest::FORMAT_VERSION,
        "protocol": "tapdata-test",
        "description": "One utxo_type per tapdata state.",
        "chain": "liquid",
        "requires": ["simplicity"],
        "utxo_types": utxo_types,
        "actions": {}
    });
    Manifest::from_json_str(&raw.to_string()).expect("parse manifest")
}

#[test]
fn tapdata_state_leaf_matches_a_longhand_derivation() {
    let pub_key = "aa".repeat(32);
    let params = HashMap::from([("PUB_KEY".to_string(), pub_key.clone())]);
    let hints = HashMap::from([("PUB_KEY".to_string(), "pubkey".to_string())]);
    let mut ctx = ExecutionContext::new();
    ctx.set_compile_param("PUB_KEY", &pub_key);

    let simf = std::path::Path::new(SIMF);
    let tapleaf = covenant::compute_tapleaf_hash(simf, &params, &hints, false).expect("tapleaf");

    let states = [0, 1, 2, u64::MAX];
    let manifest = manifest(&states);
    let mut seen = Vec::new();
    for state in states {
        let ut = manifest
            .utxo_type(&format!("state_{state}"))
            .expect("utxo_type");
        let leaves = ut.resolve_extra_leaf_payloads(&ctx).expect("extra leaves");
        assert_eq!(
            leaves,
            vec![state.to_be_bytes().to_vec()],
            "state {state}: the tapdata leaf must be the 8-byte big-endian state"
        );

        let addr = covenant::compute_covenant_address(
            simf,
            &params,
            &hints,
            &leaves,
            ElementsNetwork::LiquidTestnet,
            false,
        )
        .expect("covenant address");
        let spk = format!("{:x}", addr.script_pubkey());
        assert_eq!(
            spk,
            expected_spk(tapleaf, state),
            "state {state}: engine and longhand derivation disagree"
        );
        assert!(!seen.contains(&spk), "state {state} reuses an address");
        seen.push(spk);
    }
}
