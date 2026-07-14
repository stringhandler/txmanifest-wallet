// Reproduce the 13-byte issuance-factory creation OP_RETURN (output index 2) and
// show its decomposition. Layout = IssuanceFactoryCreationMetadata::encode:
//   program_id (4, sha256(issuance_factory.simf source)[..4])
//   issuing_utxos_count (1, u8)
//   reissuance_flags (8, u64 LE)
use tx_manifest_lib::{context::ExecutionContext, eval};

fn main() {
    let mut ctx = ExecutionContext::new();
    ctx.set_compile_param("ISSUING_UTXOS_COUNT", "2");
    ctx.set_compile_param("REISSUANCE_FLAGS", "0");
    let data = serde_json::json!({ "parts": [
        { "type": "program_id", "simf": "issuance_factory.simf" },
        { "type": "u8",  "value": "instance.ISSUING_UTXOS_COUNT" },
        { "type": "u64", "value": "instance.REISSUANCE_FLAGS", "endian": "le" }
    ]});
    let bytes = eval::eval_op_return_data(&data, &ctx, &std::collections::HashMap::new(),
        std::path::Path::new("examples/lending_v3")).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let pid: String = bytes[..4].iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("---- result ----");
    println!("creation op_return = {hex} ({} bytes)", bytes.len());
    println!("  program_id         = {pid}");
    println!("  issuing_utxos_count= {}", bytes[4]);
    println!("  reissuance_flags   = {}", u64::from_le_bytes(bytes[5..13].try_into().unwrap()));
    assert_eq!(bytes.len(), 13, "creation metadata must be 13 bytes");
    assert_eq!(bytes[4], 2, "issuing_utxos_count must be 2");
    assert_eq!(&bytes[5..13], &0u64.to_le_bytes(), "reissuance_flags must be 0");
    println!("OK: layout matches IssuanceFactoryCreationMetadata::encode");
}
