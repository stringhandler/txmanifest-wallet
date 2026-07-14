// Print the covenant tapleaf / scriptPubKey for a .simf compiled with a fixed
// SCRIPT_HASH, to compare CMRs across Simplicity toolchains.
//   cargo run -p tx-manifest-lib --example covaddr -- <path-to-script_auth.simf>
use std::collections::HashMap;

use lwk_wollet::ElementsNetwork;
use tx_manifest_lib::covenant;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let simf = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "examples/lending_v2/script_auth.simf".into()),
    );
    let script_hash = std::env::args().nth(2).unwrap_or_else(|| "00".repeat(32));
    let mut params = HashMap::new();
    params.insert("SCRIPT_HASH".to_string(), script_hash);
    let mut hints = HashMap::new();
    hints.insert("SCRIPT_HASH".to_string(), "bytes32".to_string());

    let tapleaf = covenant::compute_tapleaf_hash(&simf, &params, &hints, true).unwrap();
    let spk_hash =
        covenant::compute_covenant_script_hash(&simf, &params, &hints, ElementsNetwork::LiquidTestnet, true)
            .unwrap();
    let addr =
        covenant::compute_covenant_address(&simf, &params, &hints, &[], ElementsNetwork::LiquidTestnet, true)
            .unwrap();

    eprintln!("---- result ----");
    println!("simf         = {}", simf.display());
    println!("tapleaf_hash = {}", hex(&tapleaf));
    println!("spk          = {:x}", addr.script_pubkey());
    println!("sha256(spk)  = {}", hex(&spk_hash));
}
