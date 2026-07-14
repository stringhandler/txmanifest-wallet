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

---
## MAP + DE-RISK (2026-07-14)

### Witness PATH (lending.simf main, line 544; witness.rs)
`PATH: Either<Either<(), ()>, Either<Either<(u64, u64), u64>, u64>>`
- Accept       = `Left(Left(()))`
- Cancel       = `Left(Right(()))`
- PartialRepay = `Right(Left(Left((current_debt, amount_to_repay))))`
- FullRepay    = `Right(Left(Right(current_debt)))`
- Liquidate    = `Right(Right(current_debt))`
(simplicity_type for the manifest witness on a `lending_collateral` input.)

### Storage per state (lending.simf storage helpers; core.rs storage 23-49)
- slot0 = is_active: 32-byte value, `[31]=0x01` when active, all-zero when pending.
- slot1 = current_debt: u64 BE in `[24..32]` (task 10 encoder).
- The lending covenant ADDRESS changes with storage. **DE-RISKED**: `examples/lending_active_recon.rs`
  reproduces pending out[5] `51201ae9…fbd84e1` AND computes the active-state address
  `51202451da2d…ef3eb77` (same params, slot0 `[31]=1`) via the verified extra_leaves machinery.
  So each transition just recomputes the `lending_collateral` extra_leaves with the new
  (is_active, current_debt).

### Transitions (from lending/core.rs)
- **Accept** (`attach_acceptance` 171-198): spend pending lending covenant (Accept witness) +
  unlock lender NFT from `lender_nft_script_auth` (`attach_lender_nft_unlocking`, ScriptAuth
  witness = pending_offer_input_index) + lender principal input. Outputs: lender NFT →
  active-lender-vault region, principal → `AssetAuth(borrower_nft)` covenant
  (`PRINCIPAL_OUTPUT_SCRIPT_HASH`, simf 498-499), lending covenant re-committed ACTIVE
  (is_active=1, current_debt=total_to_repay). pending→active.
- **Cancel** (`attach_cancellation` 200-227): spend pending lending covenant (Cancel witness) +
  unlock lender NFT from script_auth. Outputs: burn lender NFT (op_return "burn", 1), burn
  borrower NFT (op_return "burn", 1). Plus collateral release + borrower-NFT input (see cancel
  test for full layout). pending→cancelled.
- **Repay** (`attach_partial/full_repayment` 229-310 + `attach_vaults` 347-481): spend active
  lending covenant (Full/Partial witness). Phased by `get_repayment_phase` (NoRepayments /
  RepayingOfferFee / RepayingPrincipal / Repaid): funds flow to lender vault + protocol-fee
  vault covenants via `attach_creation` / `attach_supplying_with_goal`. Full repay burns the
  borrower NFT and releases collateral; partial re-commits the covenant with reduced debt.
  active→repaid (or active→active for partial). **Vault-heavy — the largest remaining piece.**
- **Liquidate** (`attach_liquidation` 312-333): spend active lending covenant (Liquidate witness)
  with input `sequence = ENABLE_LOCKTIME_NO_RBF` + tx `nLockTime = LOAN_EXPIRATION_TIME`; burn
  lender NFT. active→liquidated. **BLOCKED on engine task 12 (absolute nLockTime).**

### Vault covenants (AssetAuthVault) settlement
The lender/protocol-fee vault covenants (already reproduced as hashes in task 07) are spent on
repay/claim via `attach_supplying_with_goal` / vault withdrawal. Their witness + storage model
(active vs finalized `is_active`, keeper/supplier NFT auth) must be mapped from
`asset_auth_vault.simf` + `programs/asset_auth_vault/core.rs` before implementing repay/claim.

### Status / remaining
- DONE: witness map; storage-transition de-risk (active address computes); engine gap filed (task 12).
- DONE (2026-07-14): **AcceptOffer** and **CancelOffer** authored in
  `examples/lending_v3/txmanifest.json` + verified offline (test
  `lending_v3_create_offer_reproduces_live_offer_out5`, 32 pass; `validate` clean):
  - Accept (offer_open→loan_active): in[0] pending covenant (Accept `Left(Left())`), in[1] lender
    NFT from script_auth (INPUT_SCRIPT_INDEX=0), in[2] principal, in[3] fee. out[0] active lending
    covenant `51202451da2d…ef3eb77` (storage is_active=1, verified), out[1] principal
    `AssetAuth(borrower_nft,1,false)` (verified sha256(spk)==PRINCIPAL_OUTPUT_SCRIPT_HASH), out[2]
    lender NFT→wallet. New utxo_types `lending_collateral_active`, `principal_asset_auth`.
  - Cancel (offer_open→cancelled, unilateral): in[0] pending covenant (Cancel `Left(Right())`),
    in[1] lender NFT (script_auth), in[2] borrower NFT (wallet), in[3] fee. out[0] burn lender NFT,
    out[1] burn borrower NFT (covenant-fixed indices), out[2] collateral→wallet. Data-less burns
    (covenant only checks `is_op_return`). Reuses verified pending covenant + script_auth.
- DONE (2026-07-14): **ClaimPrincipal** (borrower withdraws the loan principal), authored + validated:
  - loan_active→loan_active (unilateral). in[0] `principal_asset_auth` covenant (the AssetAuth(borrower_nft)
    from AcceptOffer out[1]; witness INPUT_ASSET_INDEX=1, OUTPUT_ASSET_INDEX=1), in[1] borrower NFT
    (wallet), in[2] fee. out[0] principal→wallet, out[1] borrower NFT preserved→wallet.
  - Mirrors `AssetAuth::attach_unlocking` (unlock_success_flows, no burn). Covenant only checks the
    auth NFT is present at in[1] + re-output at out[1]; principal flows freely. Reuses the verified
    `principal_asset_auth` utxo_type (sha256(spk)==PRINCIPAL_OUTPUT_SCRIPT_HASH), so in[0] is anchored.
- REMAINING (each needs live/broadcast verification — no on-chain anchor for active/repaid states):
  - **Repay** (active→repaid): vault-heavy — needs the AssetAuthVault spend/witness model
    (`asset_auth_vault.simf` + `programs/asset_auth_vault/core.rs`) mapped first; phased by
    `get_repayment_phase`. Largest remaining piece.
  - **Liquidate** (active→liquidated): blocked on engine task 12 (absolute nLockTime).
  - **Vault claim** — lender/protocol withdraw the repaid funds from the AssetAuthVault covenants
    (comes with the Repay/vault-model work). (Borrower principal claim is DONE above.)
  Kept in backlog. On-chain verification of Accept/Cancel/ClaimPrincipal folds into the 05/06 testnet run.
