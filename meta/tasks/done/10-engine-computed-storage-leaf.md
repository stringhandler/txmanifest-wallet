# Phase 2d — Engine: computed 32-byte taproot storage leaf

## Goal
Let a covenant `utxo_type` carry a taproot storage leaf whose bytes are COMPUTED at
build time (not a static hex literal), so the lending (collateral) covenant out[5] can
be emitted with its dynamic `current_debt` slot.

## Why
The lending covenant address folds 2 storage leaves into the tap tree:
- slot0 = `is_active` = 32 zero bytes (pending) — a static literal, already expressible.
- slot1 = `current_debt` = principal + interest, as **u64 BE in bytes[24..32]** of a 32-byte
  leaf. This is DYNAMIC (depends on PRINCIPAL_AMOUNT, PRINCIPAL_INTEREST_RATE).

Today `UtxoType::resolve_extra_leaf_payloads` (`manifest.rs:512-574`) only supports:
- hex-literal string payload items, and
- `{state_var}` items resolving to a single **u8**.
Neither can place a computed u64 into a 32-byte leaf. `examples/lending_recon.rs` and the
task-07 test build slot1 in Rust; the manifest can't yet.

## Work
Extend the taproot leaf payload mini-language with a computed field item, e.g.
`{ "value": "instance.CURRENT_DEBT", "type": "u64", "width": 32, "endian": "be", "align": "right" }`
(or a dedicated `{ "u64_be_32": "<ref>" }` form). Resolve against instance/compile params like
the OP_RETURN `parts` mini-language (task 04) — ideally share that typed-encoder code.
Add `CURRENT_DEBT` to the lending create_instance:
`PRINCIPAL_AMOUNT + PRINCIPAL_AMOUNT * PRINCIPAL_INTEREST_RATE / 10000`
(= `get_total_amount_to_repay`; interest = `apply_basis_points`).

## Acceptance
- A `utxo_type` extra_leaf can encode a computed 32-byte slot; the lending_v3
  `lending_collateral` output reproduces live offer 43ab4efe out[5] via the MANIFEST
  (currently only reproduced by the covenant.rs-level test).
- Unit test asserting the slot1 bytes for known (principal, rate).

## Files
- `txmanifest_lib/src/manifest.rs` (`resolve_extra_leaf_payloads`, `TaprootLeafSpec`),
  `txmanifest_lib/src/eval.rs` (reuse the typed-encoder from task 04),
  `examples/lending_v3/txmanifest.json` (lending_collateral extra_leaves + CURRENT_DEBT).

## Needed by
- Task 06 (offer creation out[5]).

---
## DONE (2026-07-14)

Added a typed/computed taproot-leaf payload item: `{ "value": <ref>, "type": "u8|u16|u32|u64|
bytes32|bytes", "endian": "le|be"?, "pad_to": <bytes>?, "align": "left|right"? }`
(`eval::encode_leaf_value` / `encode_leaf_bytes`). `resolve_extra_leaf_payloads` now takes
`&ExecutionContext` and dispatches Object items with a `value` key to it (state_var + hex-literal
paths unchanged). All 4 callers pass `&ctx`.

Wired into `examples/lending_v3/txmanifest.json`: `lending_collateral.extra_leaves` = [slot0 zero
literal, slot1 `{value: instance.CURRENT_DEBT, u64, be, pad_to 32, align right}`], and
`CURRENT_DEBT = params.PRINCIPAL_AMOUNT + params.PRINCIPAL_AMOUNT * params.PRINCIPAL_INTEREST_RATE
/ 10000` (integer arithmetic via evalexpr; matches `apply_basis_points`/`get_total_amount_to_repay`).

Verified: test `lending_v3_create_offer_reproduces_live_offer_out5` now drives the REAL
`lending_collateral` utxo_type end-to-end (resolve compile_params + computed leaves) and reproduces
live offer 43ab4efe out[5] `51201ae9…fbd84e1` byte-exactly; plus unit test
`encode_leaf_value_u64_be_padded_to_32`. 32 tests pass.

Caveat: `CURRENT_DEBT` uses i64 arithmetic (evalexpr), so principal*rate must stay < 2^63; the
covenant uses u128 for that multiply. Fine for realistic offers (rate ≤ 65535 bps).
