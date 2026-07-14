// De-risk the settlement storage transition (task 08): the lending (collateral) covenant
// address changes between the pending and active states because slot0 (is_active) flips.
// Pending (is_active=0) is anchored on-chain (out[5] of live offer 43ab4efe); the active
// address is the same params with slot0 byte[31]=1 — computed by the same verified machinery.
use std::collections::HashMap;
use lwk_wollet::ElementsNetwork;
use tx_manifest_lib::covenant;

fn add(p: &mut HashMap<String, String>, h: &mut HashMap<String, String>, k: &str, v: &str, t: &str) {
    p.insert(k.to_string(), v.to_string());
    h.insert(k.to_string(), t.to_string());
}
fn hx(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    let net = ElementsNetwork::LiquidTestnet;
    let d = std::path::Path::new("examples/lending_v3");
    let sh = |simf: &str, p: &HashMap<String, String>, h: &HashMap<String, String>| -> String {
        hx(&covenant::compute_covenant_script_hash(&d.join(simf), p, h, net, true).unwrap())
    };

    // Live offer 43ab4efe params (same as lending_recon.rs).
    let collateral = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    let principal  = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";
    let borrower_nft = "78d61185c79f855fac51a87c191b00266f02d28752f50b3d9092ccf6b978181e";
    let lender_nft = "213462821a5cdb96f435f5ea6597e8937359d6fd5a64b6ac8ef4262bc279fcfb";
    let protocol_fee = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";
    let z32 = "00".repeat(32);

    let vault = |is_active: &str, finalized_hash: &str, keeper: &str, keeper_burn: &str, supplier_burn: &str| -> (HashMap<String,String>, HashMap<String,String>) {
        let (mut p, mut h) = (HashMap::new(), HashMap::new());
        add(&mut p, &mut h, "VAULT_ASSET_ID", principal, "liquid.asset_id");
        add(&mut p, &mut h, "KEEPER_AUTH_ASSET_ID", keeper, "liquid.asset_id");
        add(&mut p, &mut h, "SUPPLIER_AUTH_ASSET_ID", borrower_nft, "liquid.asset_id");
        add(&mut p, &mut h, "KEEPER_AUTH_ASSET_AMOUNT", "1", "u64");
        add(&mut p, &mut h, "FINALIZED_VAULT_COV_HASH", finalized_hash, "bytes32");
        add(&mut p, &mut h, "IS_ACTIVE", is_active, "bool");
        add(&mut p, &mut h, "WITH_KEEPER_ASSET_BURN", keeper_burn, "bool");
        add(&mut p, &mut h, "WITH_SUPPLIER_ASSET_BURN", supplier_burn, "bool");
        (p, h)
    };
    let (fp, fh) = vault("false", &z32, lender_nft, "true", "true");
    let f_lender = sh("asset_auth_vault.simf", &fp, &fh);
    let (ap, ah) = vault("true", &f_lender, lender_nft, "true", "true");
    let a_lender = sh("asset_auth_vault.simf", &ap, &ah);
    let (fp2, fh2) = vault("false", &z32, protocol_fee, "false", "true");
    let f_proto = sh("asset_auth_vault.simf", &fp2, &fh2);
    let (ap2, ah2) = vault("true", &f_proto, protocol_fee, "false", "true");
    let a_proto = sh("asset_auth_vault.simf", &ap2, &ah2);
    let (mut pp, mut ph) = (HashMap::new(), HashMap::new());
    add(&mut pp, &mut ph, "ASSET_ID", borrower_nft, "liquid.asset_id");
    add(&mut pp, &mut ph, "ASSET_AMOUNT", "1", "u64");
    add(&mut pp, &mut ph, "WITH_ASSET_BURN", "false", "bool");
    let principal_out = sh("asset_auth.simf", &pp, &ph);

    let (mut p, mut h) = (HashMap::new(), HashMap::new());
    add(&mut p, &mut h, "COLLATERAL_ASSET_ID", collateral, "liquid.asset_id");
    add(&mut p, &mut h, "PRINCIPAL_ASSET_ID", principal, "liquid.asset_id");
    add(&mut p, &mut h, "BORROWER_NFT_ASSET_ID", borrower_nft, "liquid.asset_id");
    add(&mut p, &mut h, "LENDER_NFT_ASSET_ID", lender_nft, "liquid.asset_id");
    add(&mut p, &mut h, "COLLATERAL_AMOUNT", "21000", "u64");
    add(&mut p, &mut h, "PRINCIPAL_AMOUNT", "1000", "u64");
    add(&mut p, &mut h, "PRINCIPAL_INTEREST_RATE", "10000", "u64");
    add(&mut p, &mut h, "LOAN_EXPIRATION_TIME", "2536857", "u32");
    add(&mut p, &mut h, "LENDER_VAULT_COV_HASH", &a_lender, "bytes32");
    add(&mut p, &mut h, "FINALIZED_LENDER_VAULT_COV_HASH", &f_lender, "bytes32");
    add(&mut p, &mut h, "PROTOCOL_FEE_VAULT_COV_HASH", &a_proto, "bytes32");
    add(&mut p, &mut h, "FINALIZED_PROTOCOL_FEE_VAULT_COV_HASH", &f_proto, "bytes32");
    add(&mut p, &mut h, "PRINCIPAL_OUTPUT_SCRIPT_HASH", &principal_out, "bytes32");

    // current_debt = principal + principal*rate/10000 = 2000 (unchanged across accept).
    let mut debt = vec![0u8; 32];
    debt[24..32].copy_from_slice(&2000u64.to_be_bytes());

    // Pending: slot0 = is_active(false) = all zeros; slot1 = current_debt.
    let pending = [vec![0u8; 32], debt.clone()];
    let addr_p = covenant::compute_covenant_address(&d.join("lending.simf"), &p, &h, &pending, net, true).unwrap();

    // Active: slot0 = is_active(true) = value 1 (byte[31]=0x01); slot1 = current_debt.
    let mut slot0_active = vec![0u8; 32];
    slot0_active[31] = 1;
    let active = [slot0_active, debt.clone()];
    let addr_a = covenant::compute_covenant_address(&d.join("lending.simf"), &p, &h, &active, net, true).unwrap();

    eprintln!("---- result ----");
    println!("pending out[5] spk (repro) = {:x}", addr_p.script_pubkey());
    println!("pending out[5] spk (chain) = 51201ae9d30d7a31f1393a289196a4dacc01fac95459540895db448aeca47fbd84e1");
    println!("active  lending spk (repro) = {:x}", addr_a.script_pubkey());
    assert_ne!(addr_p.script_pubkey(), addr_a.script_pubkey(), "active address must differ from pending");
    println!("OK: storage transition flips the covenant address (accept: is_active 0 -> 1)");
}
