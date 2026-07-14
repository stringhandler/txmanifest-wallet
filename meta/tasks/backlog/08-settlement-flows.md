# Phase 4a — Manifest: accept / repay / liquidate / claim (new vault model)

## Goal
Model the lifecycle transitions after offer creation, against the new
AssetAuth/AssetAuthVault settlement model.

## Findings (starting points)
- **Accept (activate):** `LendingOffer::attach_acceptance` (`lending/core.rs:171-198`).
  Principal paid to `AssetAuth(borrower_nft)` covenant (`simf/lending.simf:498-499`
  enforces `PRINCIPAL_OUTPUT_SCRIPT_HASH`). Pending→active re-commits the covenant with
  updated storage (`is_active=1`, `get_script_hash_for_storage(true, total_to_repay)`,
  simf:480-494).
- **Repay:** flows to lender / protocol-fee vault covenants (`lending/core.rs:347-481`).
- Storage changes between states → the collateral covenant address changes across the
  lifecycle (must recompute extra_leaves per state).

## Work
- Map each transition's exact tx (inputs/outputs/witnesses/storage) from `lending/core.rs`
  and the tests, then express in the manifest.
- These are lower priority than getting offer creation indexed; do after 05/06/07.

## Acceptance
- Each transition reconstructs/validates against SL for a live offer.

## Files
- `simplicity-lending/crates/contracts/src/programs/lending/core.rs`,
  `crates/contracts/simf/lending.simf`, `crates/contracts/tests/lending/*`.
