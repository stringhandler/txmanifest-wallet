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

## Steps
1. New utxo_type `issuance_factory` (simf `issuance_factory.simf`, compile params
   ISSUING_UTXOS_COUNT=2, REISSUANCE_FLAGS=0).
2. A `CreateFactory` action: issue the factory asset (amount 2), send 1 to the factory
   covenant, 1 to wallet (auth NFT). Store factory asset id + covenant address in instance.
3. Verify the factory covenant address matches what SL computes for the same params.

## Depends on
- Task 03 (covenant issuance) may or may not be needed here depending on how the factory
  is first funded (initial issuance is a plain wallet issuance).

## Files
- `simplicity-lending/crates/cli/src/commands/factory/core.rs`, `.../programs/issuance_factory/*`.
