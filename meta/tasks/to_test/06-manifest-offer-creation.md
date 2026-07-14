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

## CONFIRMED layout (from setup.rs::setup_pending_offer + lending/core.rs::attach_creation)
Inputs:
- in[0]: factory auth-NFT (wallet, NativeEcdsa). asset = factory asset id.
- in[1]: factory covenant UTXO, `attach_assets_issuance` → issues borrower NFT (amount 1),
  witness `IssueAssets{output_index: 0}` (the auth-NFT output index at call time). (task 03)
- in[2]: collateral wallet UTXO, issues lender NFT (amount 1). NativeEcdsa.
  NOTE: setup reuses one entropy for both NFTs, but that is NOT required — the factory
  covenant checks asset/amount by output index, not entropy. Independent issuances are fine.

Outputs:
- out[0]: factory asset (1) → wallet (added before attach_assets_issuance).
- out[1]: factory asset (1) → factory covenant recreated (`add_program_output`).
- out[2]: borrower NFT (1) → wallet.
- out[3]: lender NFT (1) → `lender_nft_script_auth` covenant
  (`ScriptAuth::from_simplex_program(pending_offer)`; SCRIPT_HASH = sha256(out[5] spk,
  WITH storage)). ← needs **upnext/11**.
- out[4]: OP_RETURN, 50 bytes lending creation metadata. (task 04 — engine ready)
- out[5]: lending (collateral) covenant, 2 storage slots. Address chain = task 07 (DONE);
  slot1 current_debt is dynamic → needs **upnext/10**.
- out[6]/out[7]: change / fee.

## Status (2026-07-14)
- Arg chain for out[5] address: DONE (task 07) — `lending_contract`/`CreateOffer`
  create_instance in `examples/lending_v3/txmanifest.json`; reproduces live out[5] in test
  `lending_v3_create_offer_reproduces_live_offer_out5`.
- OP_RETURN out[4]: engine ready (task 04); reuse the lending 50-byte `parts` form.
- Engine prerequisites now DONE:
  - **done/10** — computed 32-byte storage leaf: `lending_collateral.extra_leaves` +
    `CURRENT_DEBT`; reproduces live out[5] via the manifest utxo_type.
  - **done/11** — sha256 of covenant-with-storage: `LENDING_COV_SCRIPT_HASH` (tapleaf +
    extra_leaves) = sha256(out[5] spk); `lender_nft_script_auth` (out[3]) compiles from it.
- REMAINING (this task): wire `CreateOffer.inputs`/`outputs` (currently `[]`) to the CONFIRMED
  layout below — in[0] auth NFT, in[1] factory covenant issuance (borrower NFT, IssueAssets
  witness), in[2] collateral issuance (lender NFT); out[0..5] + change/fee. Then verify out[1],
  out[3], out[5] against a live offer and broadcast (needs the factory from task 05 + a funded
  wallet). Hazards to handle when wiring: the factory covenant `IssueAssets{output_index:0}`
  witness satisfaction/dry-run, and cross-instance reference to the factory instance's asset id.

## Depends on
Tasks 03, 04, 07 (DONE), 05 (factory must exist), and engine tasks 10, 11. Verify each
covenant address (out[1], out[3], out[5]) against a live offer before broadcasting.

## Files
- `simplicity-lending/crates/contracts/tests/lending/setup.rs`,
  `.../programs/lending/core.rs` (`attach_creation` 153-169), `.../programs/script_auth/*`.

---
## DONE (2026-07-14) — manifest wired + verified offline, pending on-chain manual test

Wired `CreateOffer.inputs`/`outputs` in `examples/lending_v3/txmanifest.json` to the confirmed
3-in / 8-out layout:
- in[0] factory auth NFT (wallet); in[1] issuance_factory covenant, `PATH = Left(0)` IssueAssets
  witness + new-issuance → borrower NFT (on_resolved); in[2] collateral wallet UTXO + new-issuance
  → lender NFT (on_resolved); in[3] fee.
- out[0] auth NFT→wallet; out[1] factory covenant recreated; out[2] borrower NFT→wallet;
  out[3] lender NFT→`lender_nft_script_auth`; out[4] 50-byte lending OP_RETURN; out[5]
  `lending_collateral`; out[6]/out[7] change/fee.
Cross-context factory params resolved by adding `FACTORY_ASSET_ID` (from `$params`) and constant
`ISSUING_UTXOS_COUNT=2`/`REISSUANCE_FLAGS=0` as `lending_contract` fields.

Verified OFFLINE against live offer 43ab4efe (test
`lending_v3_create_offer_reproduces_live_offer_out5`, 32 pass) — every covenant output + the
OP_RETURN reproduce the on-chain bytes:
- out[1] factory covenant = `5120456881785cc7…1bb064b` (fixed (2,0), resolved in the offer context).
- out[3] `lender_nft_script_auth` compiles from `LENDING_COV_SCRIPT_HASH = sha256(out[5] spk) = 2f40d78c…5b19`.
- out[4] OP_RETURN = `f80c6162…1027` (50 bytes).
- out[5] lending covenant = `51201ae9d30d7a…fbd84e1`.
`validate` → 0 errors/0 warnings.

REMAINING (manual, testnet): create the factory (task 05), then run `CreateOffer` from a funded
wallet against the factory instance/state. This exercises what can't be checked offline: factory
covenant `IssueAssets` witness satisfaction + dry-run, same-tx issuance asset-id flow through
`on_resolved`, and locating the factory covenant UTXO from state. See the test-steps doc in
`meta/tasks/to_test/`. Then confirm the deployed indexer lists the offer.
