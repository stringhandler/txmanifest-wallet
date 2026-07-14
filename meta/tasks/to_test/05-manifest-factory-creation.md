# Phase 3a — Manifest: model the issuance factory (create + auth NFT)

## Goal
A manifest flow that creates a persistent `issuance_factory` covenant + its auth NFT,
matching what the deployed indexer's factory tracker expects.

## Findings
- Factory asset issued with total amount **2** (`cli/commands/factory/core.rs:16` FACTORY_ASSET_TOTAL_AMOUNT): 1 unit stays in the factory covenant (p2tr), 1 is the wallet-held auth NFT.
- Factory covenant params (`issuance_factory/params.rs`): `issuing_utxos_count: u8`,
  `reissuance_flags: u64` → `param::ISSUING_UTXOS_COUNT`, `param::REISSUANCE_FLAGS`.
  Network is Rust-only (address params), not a covenant arg.
- **Indexer factory tracker is seeded with hardcoded `(issuing_utxos_count=2, reissuance_flags=0)`**
  (`indexer/.../trackers/registry.rs:35`). The manifest factory MUST use these exact
  values, or offers minted from it won't be detected.
- Covenant address: single-leaf (no storage) NUMS-p2tr over CMR of `issuance_factory.simf`.

## Factory-creation tx (from cli/commands/factory/core.rs::create) — CONFIRMED
- in[0]: wallet L-BTC UTXO, **NEW issuance** of the factory asset, amount = 2 (FACTORY_ASSET_TOTAL_AMOUNT), 0 reissuance tokens, random entropy. Wallet-signed (`RequiredSignature::NativeEcdsa`).
- out[0]: factory asset (1) → **wallet p2wpkh** (the auth NFT the owner holds).
- out[1]: factory asset (1) → **issuance_factory covenant** (via `attach_creation` → add_program_output).
- out[2]: **OP_RETURN creation metadata, 13 bytes** (via `attach_creation` → `new_metadata`). This
  was MISSING from the first draft of this layout and is REQUIRED by the indexer (see step 3).
- then fee/change.

### Creation OP_RETURN layout (`IssuanceFactoryCreationMetadata::encode`) — 13 bytes
| field | off | width | order |
|-------|-----|-------|-------|
| program_id | 0 | 4 | `sha256(issuance_factory.simf SOURCE)[..4]` = `dd1e7f89` |
| issuing_utxos_count | 4 | 1 | u8 = `2` |
| reissuance_flags | 5 | 8 | **u64 LE** = `0` |

`CREATION_METADATA_OUTPUT_INDEX = 2` is hardcoded in the reference — the OP_RETURN MUST be at
output index 2. Full payload for (2,0): `dd1e7f89` `02` `0000000000000000`
(VERIFIED reproduced by manifest-wallet, examples/factory_opreturn_recon.rs).

**CRLF gotcha:** `program_id = dd1e7f89` is `sha256` of the **LF-normalized** source. The raw
CRLF file hashes to `7b057fd9`. The engine LF-normalizes before hashing; the deployed build
uses LF sources (confirmed transitively: the on-chain lending op_return matches the engine's
LF-normalized lending program_id — see task 04 / opreturn_recon.rs). Same repo → same policy
→ factory program_id `dd1e7f89` is the one the deployed indexer computes.

Key fact: the `issuance_factory` covenant address depends ONLY on
(ISSUING_UTXOS_COUNT, REISSUANCE_FLAGS) — NOT on the factory asset id. So for (2,0) it is a
FIXED address = `5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b`
(VERIFIED reproduced by manifest-wallet, examples/factory_recon.rs). Different factories
(different asset ids) share this covenant address; they differ by the asset held.

## Steps
1. utxo_type `issuance_factory` (simf `issuance_factory.simf`, compile_params
   ISSUING_UTXOS_COUNT=2 (u8), REISSUANCE_FLAGS=0 (u64)). Covenant addr verified.
2. `CreateFactory` action (constructor): issuance input (wallet lbtc, amount 2) → out[0]
   factory asset (1) to wallet, out[1] factory asset (1) to issuance_factory covenant.
   Store FACTORY_ASSET_ID (on_resolved) in instance.
3. RESOLVED — indexer factory-CREATION detector. `FactoryCreationsTracker::process_creation_tx`
   → `IssuanceFactory::try_from_tx(tx, network)` (contracts/programs/issuance_factory/core.rs).
   It keys on, in order:
   - `tx.output[2]` exists and is null-data (OP_RETURN); decodes to 13-byte metadata whose
     `program_id == sha256(source)[..4]`, else the tx is rejected. **This is why out[2] must
     be the OP_RETURN** (correction to the tx layout above).
   - factory params from the metadata must equal the tracker's seeded `(2, 0)`
     (`verify_factory_parameters`).
   - `validate_creation_outputs`: EXACTLY ONE output with the factory covenant scriptPubKey and
     amount 1 (the program UTXO), and EXACTLY ONE other non-OP_RETURN output carrying the factory
     asset with amount 1 (the auth NFT). Ordering of these two is not fixed by the validator, but
     the CLI emits auth→out[0], program→out[1]; the manifest matches the CLI.
   Then `scan_factory_creation_outputs` re-derives `program_vout`/`auth_vout` to seed the caches
   (`seed_creation_program_utxo`, `seed_creation_auth_utxo`).

## Note on reuse
The factory is created ONCE and reused for many offers (owner holds the auth NFT). The
offer-creation action (task 06) references the factory (spends its covenant UTXO + auth NFT).

## Depends on
- Task 03 (covenant issuance) may or may not be needed here depending on how the factory
  is first funded (initial issuance is a plain wallet issuance).

## Files
- `simplicity-lending/crates/cli/src/commands/factory/core.rs`, `.../programs/issuance_factory/*`.

---
## DONE (2026-07-14) — authored + verified offline, pending on-chain manual test

Authored `examples/lending_v3/txmanifest.json`: class `issuance_factory` with constructor
`CreateFactory` (state `factory_created`), `utxo_type issuance_factory`, and the 4-output tx
(auth NFT → wallet, factory asset → covenant, 13-byte creation OP_RETURN, change).

Engine needed NO new features — task 03 (covenant issuance) and task 04 (structured OP_RETURN
with `program_id`/u8/u64 LE) already cover it. Factory covenant params bind via
`utxo_type.script.compile_params` (ISSUING_UTXOS_COUNT, REISSUANCE_FLAGS) with type hints from
the class fields.

Verified offline:
- `validate` → 0 errors/warnings.
- `examples/factory_recon.rs` → factory covenant out[1] spk == on-chain
  `5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b`.
- `examples/factory_opreturn_recon.rs` (new) → creation OP_RETURN == `dd1e7f89020000000000000000`
  (13 bytes), matching `IssuanceFactoryCreationMetadata::encode` for (2,0).
- Source `issuance_factory.simf` byte-identical to reference (ignoring CRLF); program_id
  `dd1e7f89` cross-checked against reference LF-normalized hash.
- `cargo test` → 30 pass.

Correction applied to this doc: the original tx layout omitted the OP_RETURN; it is REQUIRED at
output index 2. Open question (step 3) resolved.

Remaining (manual, testnet): broadcast `CreateFactory` from a funded wallet and confirm the
deployed indexer registers the factory. See the test-steps doc in `meta/tasks/to_test/`.
Not needed for task 06 authoring, which can proceed against the created instance file.
