# Phase 3b — Manifest: offer-creation transaction (factory flow)

## Goal
Build the 3-in / 6-covenant-out offer-creation tx matching `setup.rs::setup_pending_offer`.

## Exact layout to produce
Inputs: [0] factory auth-NFT (wallet), [1] factory covenant (issues borrower NFT via
`IssueAssets{output_index:0}` witness — task 03), [2] collateral wallet UTXO (issues
lender NFT, same entropy as [1]).
Outputs: [0] factory asset→wallet, [1] factory covenant recreated, [2] borrower NFT→wallet,
[3] lender NFT→script_auth covenant (ScriptAuth keyed to the pending offer's own script
hash), [4] OP_RETURN 50B (task 04), [5] lending covenant (collateral, 2 storage slots),
[6] change, [7] fee.

## Storage slots for out[5] (pending)
slot0 = is_active = 0 (32B zero); slot1 = current_debt = principal + interest
(`get_total_amount_to_repay`), u64 BE in bytes [24..32]. Pass as `extra_leaves` on the
lending utxo_type.

## Notes / hazards
- Same issuance entropy for borrower + lender NFT issuances (two inputs).
- Lender NFT goes to a ScriptAuth covenant parameterized by the pending offer's script
  hash (`ScriptAuth::from_simplex_program(pending_offer)`), not a wallet.
- Collateral input must be sized to `collateral_amount`; out[5] amount = collateral_amount.

## Depends on
Tasks 03, 04, 07, and 05 (factory must exist). Verify each covenant address (out[1],
out[3], out[5]) against a live offer before broadcasting.

## Files
- `simplicity-lending/crates/contracts/tests/lending/setup.rs`,
  `.../programs/lending/core.rs` (`attach_creation` 153-169), `.../programs/script_auth/*`.
