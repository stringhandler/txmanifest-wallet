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
- in[0]: wallet L-BTC UTXO, **NEW issuance** of the factory asset, amount = 2 (FACTORY_ASSET_TOTAL_AMOUNT), random entropy.
- out[0]: factory asset (1) → **wallet p2wpkh** (the auth NFT the owner holds).
- out[1]: factory asset (1) → **issuance_factory covenant** (via `attach_creation` → add_program_output).
- then fee/change.

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
3. OPEN QUESTION for authoring: confirm the indexer's factory-CREATION detector
   (registry.rs seeds `FactoryCreationsTracker::new((2,0),network)`) — what exact
   output layout/asset it keys on to insert the factory UTXO into its cache. Read
   `indexer/src/indexer/trackers/factories/*` creation path before finalizing the tx.

## Note on reuse
The factory is created ONCE and reused for many offers (owner holds the auth NFT). The
offer-creation action (task 06) references the factory (spends its covenant UTXO + auth NFT).

## Depends on
- Task 03 (covenant issuance) may or may not be needed here depending on how the factory
  is first funded (initial issuance is a plain wallet issuance).

## Files
- `simplicity-lending/crates/cli/src/commands/factory/core.rs`, `.../programs/issuance_factory/*`.
