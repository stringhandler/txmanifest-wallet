# Phase 2a — Engine: fix/parameterize the TapData tag for storage covenants

## Goal
Make manifest-wallet's storage-leaf hashing byte-compatible with smplx-sdk so
storage covenant addresses (e.g. the lending collateral) match the deployed protocol.

## Change
`txmanifest_lib/src/covenant.rs::tapdata_hash` currently uses tag `"TapData/elements"`.
smplx-sdk uses `"TapData"` (`smplx-sdk-0.0.5/src/utils.rs:44`). Confirm via task 01, then:
- Change the tag to `"TapData"`, OR
- Make it configurable if any existing example relies on the old tag (grep for
  `extra_leaves` usage; e.g. last_will). Existing self-contained covenants stay
  self-consistent either way, but check for hardcoded expected addresses in tests.

## Also verify
- `build_tapbranch` tag `"TapBranch/elements"` matches what `TaprootBuilder` uses for
  Elements (it should — elements taproot uses `/elements`-suffixed TapLeaf/TapBranch).
  Only TapData is smplx-custom (unsuffixed).

## Acceptance
- After the change, task 01's reproduction gives `MATCH=true`.
- `cargo test` green (update any hardcoded-address tests).

## Files
- `txmanifest_lib/src/covenant.rs` (`tapdata_hash`, `build_tapbranch`).
