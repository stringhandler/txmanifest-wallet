// Reproduce Deadcat's four per-state covenant addresses and cross-check the engine's
// tapdata-state encoding against deadcat-sdk/src/taproot.rs.
//
//   cargo run -p tx-manifest-lib --example deadcat_recon
//
// The engine reaches its address through `TaprootSpendInfo::new_key_spend` over a merkle
// root it folds itself; deadcat reaches it by hand-rolling the three tagged hashes and
// tweaking the NUMS key directly. This example runs the manifest's own utxo_type wiring
// (compile_params + the `tapdata` extra leaf carrying the u64 state, big-endian) through
// the first path and the transcription of deadcat's code through the second, and asserts
// they agree — which is what pins the state-leaf encoding. Test values use repeated bytes
// so the `liquid.asset_id` byte-reversal is a no-op and the two sides are comparable.
use std::collections::HashMap;

use lwk_wollet::ElementsNetwork;
use lwk_wollet::elements::hashes::{Hash, HashEngine, sha256};
use lwk_wollet::elements::secp256k1_zkp::{Scalar, Secp256k1, XOnlyPublicKey};
use tx_manifest_lib::context::ExecutionContext;
use tx_manifest_lib::covenant;
use tx_manifest_lib::manifest::Manifest;

/// deadcat-sdk/src/taproot.rs::NUMS_KEY_BYTES — also the engine's covenant internal key.
const NUMS_KEY_BYTES: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SHA256(SHA256(tag) || SHA256(tag) || data) — deadcat's `tagged_hash`.
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// deadcat's `covenant_script_pubkey`, transcribed: tapdata(state) branched with the
/// Simplicity leaf, tweaked onto NUMS.
fn deadcat_spk(tapleaf_hash: [u8; 32], state: u64) -> String {
    let data_leaf = tagged_hash(b"TapData", &state.to_be_bytes());
    let (a, b) = if tapleaf_hash <= data_leaf {
        (tapleaf_hash, data_leaf)
    } else {
        (data_leaf, tapleaf_hash)
    };
    let mut branch_data = Vec::with_capacity(64);
    branch_data.extend_from_slice(&a);
    branch_data.extend_from_slice(&b);
    let branch = tagged_hash(b"TapBranch/elements", &branch_data);

    let mut tweak_data = Vec::with_capacity(64);
    tweak_data.extend_from_slice(&NUMS_KEY_BYTES);
    tweak_data.extend_from_slice(&branch);
    let tweak = tagged_hash(b"TapTweak/elements", &tweak_data);

    let secp = Secp256k1::new();
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY_BYTES).expect("NUMS key");
    let (tweaked, _parity) = nums
        .add_tweak(&secp, &Scalar::from_be_bytes(tweak).expect("scalar"))
        .expect("tweak");

    format!("5120{}", hex(&tweaked.serialize()))
}

fn main() {
    let dir = std::path::Path::new("examples/deadcat");
    let raw = std::fs::read_to_string(dir.join("txmanifest.json")).expect("read manifest");
    let manifest = Manifest::from_json_str(&raw).expect("parse manifest");

    // Same shape as deadcat-sdk's own ContractParams test fixture.
    let fields: [(&str, &str, &str); 8] = [
        ("ORACLE_PUBLIC_KEY", &"aa".repeat(32), "pubkey"),
        ("COLLATERAL_ASSET_ID", &"bb".repeat(32), "liquid.asset_id"),
        ("YES_TOKEN_ASSET", &"01".repeat(32), "liquid.asset_id"),
        ("NO_TOKEN_ASSET", &"02".repeat(32), "liquid.asset_id"),
        ("YES_REISSUANCE_TOKEN", &"03".repeat(32), "liquid.asset_id"),
        ("NO_REISSUANCE_TOKEN", &"04".repeat(32), "liquid.asset_id"),
        ("COLLATERAL_PER_TOKEN", "100000", "u64"),
        ("EXPIRY_TIME", "1000000", "u32"),
    ];

    let mut params: HashMap<String, String> = HashMap::new();
    let mut hints: HashMap<String, String> = HashMap::new();
    let mut ctx = ExecutionContext::new();
    for (name, value, ty) in &fields {
        params.insert((*name).to_string(), (*value).to_string());
        hints.insert((*name).to_string(), (*ty).to_string());
        ctx.set_compile_param(*name, *value);
    }

    let simf = dir.join("prediction_market.simf");
    // debug_symbols: false — matches deadcat's `template.instantiate(args, false)`.
    let tapleaf = covenant::compute_tapleaf_hash(&simf, &params, &hints, false).expect("tapleaf");

    eprintln!("---- result ----");
    println!("tapleaf_hash = {}", hex(&tapleaf));

    let states: [(&str, u64); 4] = [
        ("market_dormant", 0),
        ("market_unresolved", 1),
        ("market_resolved_yes", 2),
        ("market_resolved_no", 3),
    ];

    let mut seen: Vec<String> = Vec::new();
    for (type_name, state) in states {
        let ut = manifest.utxo_type(type_name).expect("utxo_type");
        let leaves = ut.resolve_extra_leaf_payloads(&ctx).expect("extra leaves");
        assert_eq!(
            leaves,
            vec![state.to_be_bytes().to_vec()],
            "{type_name}: the tapdata leaf must be the 8-byte big-endian state"
        );

        let addr = covenant::compute_covenant_address(
            &simf,
            &params,
            &hints,
            &leaves,
            ElementsNetwork::LiquidTestnet,
            false,
        )
        .expect("covenant address");
        let engine_spk = format!("{:x}", addr.script_pubkey());
        let sdk_spk = deadcat_spk(tapleaf, state);

        println!("state {state} ({type_name})");
        println!("  spk (engine)  = {engine_spk}");
        println!("  spk (deadcat) = {sdk_spk}");
        println!("  address       = {addr}");
        assert_eq!(
            engine_spk, sdk_spk,
            "state {state}: engine and deadcat-sdk disagree on the covenant scriptPubKey"
        );
        assert!(
            !seen.contains(&engine_spk),
            "state {state} collides with an earlier state's address"
        );
        seen.push(engine_spk);
    }

    check_witness_literals(&simf, &params);

    println!("\nOK: four distinct addresses, each matching deadcat-sdk's derivation.");
}

/// Parse every witness literal the manifest writes against the compiled program's own
/// ABI types. `PATH` is a seven-leaf nested `Either` tree and the literals are written by
/// hand, so this is where a mis-nested `Left`/`Right` would otherwise go unnoticed until a
/// spend failed on chain.
fn check_witness_literals(simf: &std::path::Path, params: &HashMap<String, String>) {
    use simplicityhl::parse::ParseFromStr;
    use simplicityhl::str::WitnessName;
    use simplicityhl::value::Value;
    use simplicityhl::{Arguments, CompiledProgram};
    use simplicityhl::ast::ElementsJetHinter;

    let asset_arg = |name: &str| {
        format!(
            r#""{name}": {{ "value": "0x{}", "type": "u256" }}"#,
            params[name]
        )
    };
    let args_json = format!(
        "{{{}, {}, {}, {}, {}, {}, {}, {}}}",
        asset_arg("ORACLE_PUBLIC_KEY"),
        asset_arg("COLLATERAL_ASSET_ID"),
        asset_arg("YES_TOKEN_ASSET"),
        asset_arg("NO_TOKEN_ASSET"),
        asset_arg("YES_REISSUANCE_TOKEN"),
        asset_arg("NO_REISSUANCE_TOKEN"),
        r#""COLLATERAL_PER_TOKEN": { "value": "100000", "type": "u64" }"#,
        r#""EXPIRY_TIME": { "value": "1000000", "type": "u32" }"#,
    );
    let arguments: Arguments = serde_json::from_str(&args_json).expect("arguments");
    let source = std::fs::read_to_string(simf).expect("read simf");
    let compiled = CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
        .expect("compile");
    let abi = compiled.generate_abi_meta().expect("abi");

    eprintln!("---- witness ABI ----");
    for (name, ty) in abi.witness_types.iter() {
        eprintln!("  {name}: {ty}");
    }

    // Every PATH literal the manifest uses, in path order.
    let sig_literal = format!("0x{}", "ab".repeat(64));
    let burn_literal = format!("0x{}", "01".repeat(32));
    let literals: [(&str, &str, &str); 13] = [
        ("PATH", "Left(Left(Left(())))", "path 1 — initial issuance"),
        ("PATH", "Left(Left(Right(())))", "path 2 — subsequent issuance"),
        ("PATH", "Left(Right(Left(())))", "path 3 — oracle resolve"),
        ("PATH", "Left(Right(Right(())))", "path 4 — post-resolution redemption"),
        ("PATH", "Right(Left(Left(())))", "path 5 — expiry redemption"),
        ("PATH", "Right(Left(Right(())))", "path 6 — cancellation"),
        ("PATH", "Right(Right(()))", "path 7 — secondary covenant input"),
        ("STATE", "0", "dormant"),
        ("STATE", "3", "resolved-no"),
        ("ORACLE_OUTCOME_YES", "true", "YES resolve"),
        ("TOKENS_BURNED", "1234", "a redemption amount"),
        (
            "ORACLE_SIGNATURE",
            &sig_literal,
            "a 0x-prefixed 64-byte oracle signature, as ResolveYes/ResolveNo substitute it",
        ),
        (
            "BURN_TOKEN_ASSET",
            &burn_literal,
            "a 0x-prefixed asset id in internal byte order, as RedeemExpired substitutes it",
        ),
    ];

    let mut paths: Vec<Vec<u8>> = Vec::new();
    for (name, literal, note) in literals {
        let wname = WitnessName::parse_from_str(name).expect("witness name");
        let ty = abi
            .witness_types
            .get(&wname)
            .unwrap_or_else(|| panic!("{name} is not a witness of the compiled program"));
        let value = Value::parse_from_str(literal, ty)
            .unwrap_or_else(|e| panic!("{name} = {literal} ({note}) does not parse: {e}"));
        if name == "PATH" {
            let bits = format!("{value:?}").into_bytes();
            assert!(
                !paths.contains(&bits),
                "two PATH literals encode the same branch — {literal} ({note})"
            );
            paths.push(bits);
        }
    }
    println!("witness literals: all 7 PATH branches distinct and well-typed");
}
