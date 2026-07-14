# Phase 4b — End-to-end verification before broadcast

## Goal
Before broadcasting anything, prove a manifest-built offer would be indexed by the
deployed protocol.

## Method
1. Build the offer-creation PSET/tx from the manifest (use `--export-pset` to avoid
   broadcasting).
2. Run SL's own `odev` detection against it (a check-tool like the earlier
   `check_prelock`, but using `LendingOffer::try_from_tx` +
   `scan_offer_creation_outputs`): confirm it reconstructs the lending covenant and
   matches the collateral output, and that the OP_RETURN/program_id/NFT outputs pass.
3. Only broadcast once the local reconstruction passes and covenant addresses match.
4. After broadcast, confirm the offer appears via
   `https://lending.dev.blockstream.com/api/offers` (and by-borrower-pubkey).

## Reusable diagnostics (already present)
- `simplicity-lending/crates/contracts/examples/check_prelock.rs` — adapt to the new
  `try_from_tx` API.
- `manifest-wallet/txmanifest_lib/examples/{covaddr,prelock_recon}.rs` — adapt to the
  new covenants.

## Acceptance
- Local reconstruction of the manifest offer == `MATCH`/detected.
- Offer visible on the deployed site.

## Note
Deployed indexer occasionally lags/stalls; if a valid offer doesn't appear, confirm the
indexer height advanced past the offer's block before assuming a covenant problem.
