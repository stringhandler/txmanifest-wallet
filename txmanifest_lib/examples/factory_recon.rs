// Reproduce the issuance_factory covenant (out[1]) and compare to on-chain.
use std::collections::HashMap;
use lwk_wollet::ElementsNetwork;
use tx_manifest_lib::covenant;

fn main() {
    let d = std::path::Path::new("examples/lending_v3");
    let mut p = HashMap::new();
    let mut h = HashMap::new();
    p.insert("ISSUING_UTXOS_COUNT".to_string(), "2".to_string());
    h.insert("ISSUING_UTXOS_COUNT".to_string(), "u8".to_string());
    p.insert("REISSUANCE_FLAGS".to_string(), "0".to_string());
    h.insert("REISSUANCE_FLAGS".to_string(), "u64".to_string());
    let addr = covenant::compute_covenant_address(&d.join("issuance_factory.simf"), &p, &h, &[], ElementsNetwork::LiquidTestnet, true).unwrap();
    eprintln!("---- result ----");
    println!("factory out[1] spk (repro) = {:x}", addr.script_pubkey());
    println!("factory out[1] spk (chain) = 5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b");
}
