# Phase 1 — Verify the lending covenant (storage tree) can be reproduced

## Goal
Prove, before building anything, that manifest-wallet can reproduce the **lending
collateral covenant address** (out[5]) of a real deployed offer — the covenant with
2 taproot storage slots. This validates the hardest math (tap tree + tag + arg chain).

## Key findings
- manifest-wallet already folds storage leaves: `compute_covenant_address` does
  `root = build_tapbranch(root, tapdata_hash(payload))` per `extra_leaf_payloads`
  (`txmanifest_lib/src/covenant.rs` ~731-746). For 2 slots the fold
  `TapBranch(TapBranch(CMR, slot0), slot1)` == smplx's `[2,2,1]` tree.
- **Tag mismatch to confirm/fix:** manifest `tapdata_hash` tags `"TapData/elements"`;
  smplx `tap_data_hash` tags `"TapData"` (`smplx-sdk-0.0.5/src/utils.rs:44`:
  `sha256(sha256("TapData") ‖ sha256("TapData") ‖ data)`).
- Storage slots (`lending/core.rs:23-49`): slot0 = is_active (32B, `[31]=bool`);
  slot1 = current_debt (32B, `[24..32]=u64 BE`). Pending: is_active=0,
  current_debt = principal + interest.
- Tap tree build: `smplx-sdk-0.0.5/src/program/core.rs:335-353` +
  `taproot_leaf_depths` (316-333).

## Steps
1. In simplicity-lending (`odev`), add an example that reconstructs a deployed offer via
   `LendingOffer::try_from_tx(tx, protocol_fee_keeper_asset_id, network)` and prints:
   the lending covenant scriptPubKey (= on-chain out[5]), the CMR, both storage slot
   values, and `tap_data_hash(slot)` for each. Anchor tx: `43ab4efe…` (or a fresh one).
2. In manifest-wallet, compute the same covenant address via `compute_covenant_address`
   with `extra_leaf_payloads = [slot0, slot1]` and compare to on-chain out[5].
3. Determine the correct `tapdata_hash` tag empirically (`"TapData"` vs `"TapData/elements"`).

## Acceptance
- manifest-wallet reproduces out[5]'s scriptPubKey for a live offer → `MATCH=true`.
- The correct TapData tag is confirmed and recorded (feeds task 02).

## Notes
- Getting the CMR needs the full lending arg chain (nested AssetAuth/AssetAuthVault
  hashes) — this task may lean on task 07; a shortcut is to read the CMR from the SL
  example and feed it directly to a manual tap-tree calc to isolate the tag first.


---
## DONE (2026-07-14)
Confirmed by reproducing live offer 43ab4efe out[5] byte-exactly:
`51201ae9d30d7a31f1393a289196a4dacc01fac95459540895db448aeca47fbd84e1`.
TapData tag = `"TapData"` (applied in covenant.rs). Full nested arg chain (5 AssetAuth/AssetAuthVault hashes) + 2 storage leaves reproduce. 29 tests still pass.
