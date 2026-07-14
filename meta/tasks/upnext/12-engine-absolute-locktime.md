# Phase 4b — Engine: absolute transaction nLockTime

## Goal
Let a manifest action set the spending transaction's absolute `nLockTime`, so covenant
paths gated by `jet::check_lock_height` (CLTV) can be satisfied.

## Why
The lending liquidation path requires `nLockTime >= LOAN_EXPIRATION_TIME`
(`lending.simf` `liquidate_offer` → `jet::check_lock_height(param::LOAN_EXPIRATION_TIME)`),
and the reference builds the input with `Sequence::ENABLE_LOCKTIME_NO_RBF` + a locktime
(`lending/core.rs::attach_liquidation`). The engine currently supports per-input relative
`sequence` (`pset_builder::apply_sequence`) but NOT the tx-level absolute `nLockTime`, so the
liquidation path is not executable. Same pre-existing limitation the v2 example flagged for
`LiquidateAfterExpiry`.

## Work
- Add an action-level `lock_time` (absolute block height or a ref/expr, e.g.
  `"instance.LOAN_EXPIRATION_TIME"`) that sets the PSET global `fallback_locktime` /
  transaction `lock_time`.
- Ensure the liquidation input's `sequence` is set to enable locktime (not `Sequence::MAX`) —
  the existing per-input `sequence` support can express `ENABLE_LOCKTIME_NO_RBF` (0xFFFFFFFE).
- Confirm the dry-run/finalize passes the locktime through to the covenant's `check_lock_height`.

## Acceptance
- A manifest action sets nLockTime; a covenant `check_lock_height` path validates in dry-run.
- Lending `Liquidate` (task 08) becomes executable.

## Files
- `txmanifest_lib/src/pset_builder.rs` (PSET global lock_time),
  `txmanifest_lib/src/lifecycle.rs` (action `lock_time` field + wiring),
  `txmanifest_lib/src/manifest.rs` (Action schema).

## Needed by
- Task 08 (Liquidate transition).
