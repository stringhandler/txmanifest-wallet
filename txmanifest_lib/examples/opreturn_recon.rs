// Reproduce the 50-byte lending offer-creation OP_RETURN and compare to on-chain.
use tx_manifest_lib::{context::ExecutionContext, eval};

fn main() {
    let mut ctx = ExecutionContext::new();
    ctx.set_compile_param("PRINCIPAL_ASSET_ID", "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5");
    ctx.set_compile_param("PRINCIPAL_AMOUNT", "1000");
    ctx.set_compile_param("LOAN_EXPIRATION_TIME", "2536857");
    ctx.set_compile_param("PRINCIPAL_INTEREST_RATE", "10000");
    let data = serde_json::json!({ "parts": [
        { "type": "program_id", "simf": "lending.simf" },
        { "type": "liquid.asset_id", "value": "instance.PRINCIPAL_ASSET_ID" },
        { "type": "u64", "value": "instance.PRINCIPAL_AMOUNT" },
        { "type": "u32", "value": "instance.LOAN_EXPIRATION_TIME" },
        { "type": "u16", "value": "instance.PRINCIPAL_INTEREST_RATE" }
    ]});
    let bytes = eval::eval_op_return_data(&data, &ctx, &std::collections::HashMap::new(),
        std::path::Path::new("examples/lending_v3")).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("repro   = {hex} ({} bytes)", bytes.len());
    println!("onchain = f80c6162a5502895799e276b4af246c821423b4ed5ec5e6b4e6df7a861606939d9a2fc38e80300000000000099b526001027");
}
