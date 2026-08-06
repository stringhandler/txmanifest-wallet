// Check what the deadcat_v3 fork did and did not change.
//
//   cargo run -p tx-manifest-lib --example deadcat_v3_recon
//
// `deadcat_recon` proves examples/deadcat reproduces upstream Deadcat's addresses
// byte-for-byte. This is its complement for v3: every covenant address moved, the four
// OUTPUT blinding witnesses are gone (they are derived as abf+1 / vbf+1 now), and the four
// INPUT ones remain — those still have to prove the spent token is this market's, and pin
// its amount to 1.
use std::collections::HashMap;

use lwk_wollet::ElementsNetwork;
use tx_manifest_lib::context::ExecutionContext;
use tx_manifest_lib::covenant;
use tx_manifest_lib::manifest::Manifest;

/// Removed by the fork: the output factors are now derived, not witnessed.
const REMOVED_WITNESSES: [&str; 4] = [
    "YES_REISSUANCE_OUTPUT_ABF",
    "YES_REISSUANCE_OUTPUT_VBF",
    "NO_REISSUANCE_OUTPUT_ABF",
    "NO_REISSUANCE_OUTPUT_VBF",
];

/// Kept by the fork. Dropping these would let anyone plant a blinded UTXO of their own
/// asset at a covenant address and cycle it through the market's paths.
const KEPT_WITNESSES: [&str; 6] = [
    "YES_REISSUANCE_INPUT_ABF",
    "YES_REISSUANCE_INPUT_VBF",
    "NO_REISSUANCE_INPUT_ABF",
    "NO_REISSUANCE_INPUT_VBF",
    "STATE",
    "PATH",
];

const STATES: [(&str, u64); 4] = [
    ("market_dormant", 0),
    ("market_unresolved", 1),
    ("market_resolved_yes", 2),
    ("market_resolved_no", 3),
];

/// Same fixture as `deadcat_recon`: repeated bytes, so the `liquid.asset_id` reversal is a
/// no-op and the two examples are compared on equal terms.
fn fixture() -> (HashMap<String, String>, HashMap<String, String>, ExecutionContext) {
    let fields: [(&str, String, &str); 8] = [
        ("ORACLE_PUBLIC_KEY", "aa".repeat(32), "pubkey"),
        ("COLLATERAL_ASSET_ID", "bb".repeat(32), "liquid.asset_id"),
        ("YES_TOKEN_ASSET", "01".repeat(32), "liquid.asset_id"),
        ("NO_TOKEN_ASSET", "02".repeat(32), "liquid.asset_id"),
        ("YES_REISSUANCE_TOKEN", "03".repeat(32), "liquid.asset_id"),
        ("NO_REISSUANCE_TOKEN", "04".repeat(32), "liquid.asset_id"),
        ("COLLATERAL_PER_TOKEN", "100000".to_string(), "u64"),
        ("EXPIRY_TIME", "1000000".to_string(), "u32"),
    ];
    let mut params = HashMap::new();
    let mut hints = HashMap::new();
    let mut ctx = ExecutionContext::new();
    for (name, value, ty) in &fields {
        params.insert((*name).to_string(), value.clone());
        hints.insert((*name).to_string(), (*ty).to_string());
        ctx.set_compile_param(*name, value.clone());
    }
    (params, hints, ctx)
}

/// Derive the four per-state scriptPubKeys for one example directory, through that
/// example's own `utxo_type` wiring.
fn addresses(dir: &str) -> Vec<String> {
    let dir = std::path::Path::new(dir);
    let raw = std::fs::read_to_string(dir.join("txmanifest.json")).expect("read manifest");
    let manifest = Manifest::from_json_str(&raw).expect("parse manifest");
    let (params, hints, ctx) = fixture();
    let simf = dir.join("prediction_market.simf");

    STATES
        .iter()
        .map(|(type_name, _)| {
            let ut = manifest.utxo_type(type_name).expect("utxo_type");
            let leaves = ut.resolve_extra_leaf_payloads(&ctx).expect("extra leaves");
            let addr = covenant::compute_covenant_address(
                &simf,
                &params,
                &hints,
                &leaves,
                ElementsNetwork::LiquidTestnet,
                false,
            )
            .expect("covenant address");
            format!("{:x}", addr.script_pubkey())
        })
        .collect()
}

fn main() {
    let v1 = addresses("examples/deadcat");
    let v3 = addresses("examples/deadcat_v3");

    eprintln!("---- result ----");
    for ((type_name, state), (a, b)) in STATES.iter().zip(v1.iter().zip(v3.iter())) {
        println!("state {state} ({type_name})");
        println!("  v1 = {a}");
        println!("  v3 = {b}");
        assert_ne!(
            a, b,
            "state {state}: v3 must NOT share an address with v1. If these ever match, the \
             fork stopped being a fork and tokens could be parked at an address whose \
             program is not the one this example compiles"
        );
    }
    assert_eq!(
        v3.iter().collect::<std::collections::BTreeSet<_>>().len(),
        4,
        "v3's four states must still be four distinct addresses"
    );

    // The point of the fork: the OUTPUT factors are derived, so they stop being witnesses,
    // while the INPUT ones stay — they are what binds the spent token to this market.
    let names = v3_witness_names();
    println!("\nv3 witnesses ({}): {}", names.len(), names.join(", "));
    for gone in REMOVED_WITNESSES {
        assert!(
            !names.iter().any(|n| n == gone),
            "{gone} is still a witness — the output check was not converted to the shifted form"
        );
    }
    for kept in KEPT_WITNESSES {
        assert!(names.iter().any(|n| n == kept), "{kept} must survive the fork");
    }
    for kept in ["ORACLE_SIGNATURE", "TOKENS_BURNED", "PAIRS_BURNED"] {
        assert!(names.iter().any(|n| n == kept), "{kept} must survive the fork");
    }

    println!(
        "\nOK: v3 moved all four addresses, dropped the 4 output blinding witnesses, \
         and kept the 4 input ones."
    );
}

fn v3_witness_names() -> Vec<String> {
    use simplicityhl::ast::ElementsJetHinter;
    use simplicityhl::{Arguments, CompiledProgram};

    let (params, _, _) = fixture();
    let asset_arg =
        |name: &str| format!(r#""{name}": {{ "value": "0x{}", "type": "u256" }}"#, params[name]);
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
    let source = std::fs::read_to_string("examples/deadcat_v3/prediction_market.simf")
        .expect("read v3 simf");
    let abi = CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
        .expect("compile v3")
        .generate_abi_meta()
        .expect("abi");
    abi.witness_types.iter().map(|(n, _)| n.to_string()).collect()
}
