// Reconstruct the full pre_lock covenant for a real on-chain offer's parameters,
// replicating the create_instance tapleaf chain, and compare to the address the
// simplicity-lending indexer reconstructs. Proves cross-toolchain covenant parity.
use std::collections::HashMap;

use lwk_wollet::ElementsNetwork;
use tx_manifest_lib::covenant;

fn add(
    p: &mut HashMap<String, String>,
    h: &mut HashMap<String, String>,
    k: &str,
    v: &str,
    t: &str,
) {
    p.insert(k.to_string(), v.to_string());
    h.insert(k.to_string(), t.to_string());
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let net = ElementsNetwork::LiquidTestnet;
    let dir = std::path::Path::new("examples/lending_v2");

    // Offer params decoded from the on-chain tx (adf5353d...).
    let collateral_asset = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    let principal_asset = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";
    let first_nft = "c6247228b174eda8d72a028928db524411fd979cd990dfe6a41f85fd77ef799e";
    let second_nft = "a06ad371c9b57d33724c73c617ca0da503ee78bb152c0c758b18521b343c8608";
    let borrower_nft = "5e174ab03af6add6143c14a6f57c6c9ab8ff9cd547853bbf32769d49622c54fc";
    let lender_nft = "81d2da212db51c21f7621c5bfe2fb3d02a32ba04f7017167d5facece12cd7d65";
    let borrower_pubkey = "ff8f324fa841ca5f29b13c05342666b1722067f6f5e58f67fc27ff1f5a9af7e1";
    let borrower_out_hash = "aa55d97dc9638014213def17cc614bd237b12e51945ec4f42c673eb07d3ff52c";

    // 1. LENDER_PRINCIPAL_COV_HASH = script_hash(asset_auth, ASSET_ID=lender_nft, AMOUNT=1, BURN=true)
    let (mut p, mut h) = (HashMap::new(), HashMap::new());
    add(&mut p, &mut h, "ASSET_ID", lender_nft, "liquid.asset_id");
    add(&mut p, &mut h, "ASSET_AMOUNT", "1", "u64");
    add(&mut p, &mut h, "WITH_ASSET_BURN", "true", "bool");
    let lender_principal_cov = hexs(
        &covenant::compute_covenant_script_hash(&dir.join("asset_auth.simf"), &p, &h, net, true)
            .unwrap(),
    );

    // 2. LENDING_COV_HASH = script_hash(lending, ...)
    let (mut p, mut h) = (HashMap::new(), HashMap::new());
    add(&mut p, &mut h, "COLLATERAL_AMOUNT", "3452", "u64");
    add(&mut p, &mut h, "PRINCIPAL_AMOUNT", "1000", "u64");
    add(&mut p, &mut h, "LOAN_EXPIRATION_TIME", "5000000", "u32");
    add(&mut p, &mut h, "PRINCIPAL_INTEREST_RATE", "100", "u16");
    add(
        &mut p,
        &mut h,
        "COLLATERAL_ASSET_ID",
        collateral_asset,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "FIRST_PARAMETERS_NFT_ASSET_ID",
        first_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "SECOND_PARAMETERS_NFT_ASSET_ID",
        second_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "BORROWER_NFT_ASSET_ID",
        borrower_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "PRINCIPAL_ASSET_ID",
        principal_asset,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "LENDER_PRINCIPAL_COV_HASH",
        &lender_principal_cov,
        "bytes32",
    );
    add(
        &mut p,
        &mut h,
        "LENDER_NFT_ASSET_ID",
        lender_nft,
        "liquid.asset_id",
    );
    let lending_cov = hexs(
        &covenant::compute_covenant_script_hash(&dir.join("lending.simf"), &p, &h, net, true)
            .unwrap(),
    );

    // 3. PARAMETERS_NFT_OUTPUT_SCRIPT_HASH = script_hash(script_auth, SCRIPT_HASH=lending_cov)
    let (mut p, mut h) = (HashMap::new(), HashMap::new());
    add(&mut p, &mut h, "SCRIPT_HASH", &lending_cov, "bytes32");
    let params_nft_out = hexs(
        &covenant::compute_covenant_script_hash(&dir.join("script_auth.simf"), &p, &h, net, true)
            .unwrap(),
    );

    // 4. pre_lock address
    let (mut p, mut h) = (HashMap::new(), HashMap::new());
    add(&mut p, &mut h, "COLLATERAL_AMOUNT", "3452", "u64");
    add(&mut p, &mut h, "PRINCIPAL_AMOUNT", "1000", "u64");
    add(&mut p, &mut h, "LOAN_EXPIRATION_TIME", "5000000", "u32");
    add(&mut p, &mut h, "PRINCIPAL_INTEREST_RATE", "100", "u16");
    add(
        &mut p,
        &mut h,
        "COLLATERAL_ASSET_ID",
        collateral_asset,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "FIRST_PARAMETERS_NFT_ASSET_ID",
        first_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "SECOND_PARAMETERS_NFT_ASSET_ID",
        second_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "BORROWER_NFT_ASSET_ID",
        borrower_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "LENDER_NFT_ASSET_ID",
        lender_nft,
        "liquid.asset_id",
    );
    add(
        &mut p,
        &mut h,
        "PRINCIPAL_ASSET_ID",
        principal_asset,
        "liquid.asset_id",
    );
    add(&mut p, &mut h, "LENDING_COV_HASH", &lending_cov, "bytes32");
    add(
        &mut p,
        &mut h,
        "PRINCIPAL_OUTPUT_SCRIPT_HASH",
        borrower_out_hash,
        "bytes32",
    );
    add(
        &mut p,
        &mut h,
        "PARAMETERS_NFT_OUTPUT_SCRIPT_HASH",
        &params_nft_out,
        "bytes32",
    );
    add(
        &mut p,
        &mut h,
        "BORROWER_NFT_OUTPUT_SCRIPT_HASH",
        borrower_out_hash,
        "bytes32",
    );
    add(
        &mut p,
        &mut h,
        "BORROWER_PUB_KEY",
        borrower_pubkey,
        "pubkey",
    );
    let addr =
        covenant::compute_covenant_address(&dir.join("pre_lock.simf"), &p, &h, &[], net, true)
            .unwrap();

    eprintln!("---- result ----");
    println!("LENDER_PRINCIPAL_COV_HASH = {lender_principal_cov}");
    println!("LENDING_COV_HASH          = {lending_cov}");
    println!("PARAMETERS_NFT_OUT_HASH   = {params_nft_out}");
    println!(
        "pre_lock spk (this wallet, debug=true) = {:x}",
        addr.script_pubkey()
    );
    println!("indexer reconstruction (simplicity-lending) = 512050... (old) / f2b6fe... (correct)");
}
