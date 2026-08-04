// Reproduce the 50-byte lending offer-creation OP_RETURN and compare to on-chain.
// Also proves the baked-in LENDING_PROGRAM_ID constant (f80c6162) really is
// sha256(LF-normalized lending.simf source)[..4] — the derivation is done HERE (authoring
// time), not by the tx-encoder, which now sees only a plain `bytes` constant.
use lwk_wollet::elements::hashes::{sha256, Hash};
use std::collections::HashMap;
use tx_manifest_lib::{context::ExecutionContext, eval};

/// Protocol message-type tag = first 4 bytes of SHA-256 of the LF-normalized source text.
fn program_id(simf_path: &std::path::Path) -> String {
    let src = std::fs::read_to_string(simf_path)
        .unwrap()
        .replace("\r\n", "\n");
    let h = sha256::Hash::hash(src.as_bytes()).to_byte_array();
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let d = std::path::Path::new("examples/lending_v3");
    let lending_program_id = program_id(&d.join("lending.simf"));
    assert_eq!(
        lending_program_id, "f80c6162",
        "LENDING_PROGRAM_ID constant in the manifest must equal sha256(lending.simf source)[..4]"
    );

    let mut ctx = ExecutionContext::new();
    ctx.set_compile_param("LENDING_PROGRAM_ID", &lending_program_id);
    ctx.set_compile_param(
        "PRINCIPAL_ASSET_ID",
        "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
    );
    ctx.set_compile_param("PRINCIPAL_AMOUNT", "1000");
    ctx.set_compile_param("LOAN_EXPIRATION_TIME", "2536857");
    ctx.set_compile_param("PRINCIPAL_INTEREST_RATE", "10000");
    let data = serde_json::json!({ "parts": [
        { "type": "bytes", "value": "instance.LENDING_PROGRAM_ID" },
        { "type": "liquid.asset_id", "value": "instance.PRINCIPAL_ASSET_ID" },
        { "type": "u64", "value": "instance.PRINCIPAL_AMOUNT" },
        { "type": "u32", "value": "instance.LOAN_EXPIRATION_TIME" },
        { "type": "u16", "value": "instance.PRINCIPAL_INTEREST_RATE" }
    ]});
    let bytes = eval::eval_op_return_data(&data, &ctx, &HashMap::new()).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("repro   = {hex} ({} bytes)", bytes.len());
    println!("onchain = f80c6162a5502895799e276b4af246c821423b4ed5ec5e6b4e6df7a861606939d9a2fc38e80300000000000099b526001027");
}
