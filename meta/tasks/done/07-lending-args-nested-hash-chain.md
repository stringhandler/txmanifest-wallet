# Phase 3c — Manifest: lending covenant args (nested AssetAuth/AssetAuthVault chain)

## Goal
Compute the lending covenant's compile-time arguments so its CMR (and thus out[5]
address) matches SL. These are a chain of nested covenant script hashes.

## Args (`lending/params.rs::build_arguments` 54-96)
- `principal_output_script_hash` = `AssetAuth(borrower_nft_asset_id).get_script_hash()`
  — the principal is paid to a borrower-NFT-keyed AssetAuth covenant (NOT a wallet hash;
  the old `borrower_output_script_hash` model is gone).
- `lender_vault_cov_hash`, `finalized_lender_vault_cov_hash` = `AssetAuthVault(lender_nft)`
  covenants (two variants).
- `protocol_fee_vault_cov_hash`, `finalized_protocol_fee_vault_cov_hash` =
  `AssetAuthVault(protocol_fee_keeper_asset_id)` covenants.
- plus the plain offer params (asset ids, amounts, expiry, rate).

## Work
- Add utxo_types / tapleaf computes for `asset_auth.simf` and `asset_auth_vault.simf`
  with the right params, wired as nested `compute: tapleaf` fields (like the old
  LENDER_PRINCIPAL_COV_HASH chain), feeding the lending covenant's compile params.
- Confirm `asset_auth` / `asset_auth_vault` param names + types from
  `programs/{asset_auth,asset_auth_vault}/params.rs`.

## Acceptance
- lending covenant CMR + address reproduced for a live offer (`MATCH=true`), combined
  with the storage leaves (task 01/02).

## Files
- `simplicity-lending/crates/contracts/src/programs/{asset_auth,asset_auth_vault,lending}/params.rs`,
  `crates/contracts/simf/{asset_auth,asset_auth_vault,lending}.simf`.

---
## DONE (2026-07-14)

Authored the nested cov-hash chain as `create_instance` compute:tapleaf fields in
`examples/lending_v3/txmanifest.json` (class `lending_contract`, method `CreateOffer`) plus
the `lending_collateral` utxo_type. Verified OFFLINE against live offer 43ab4efe.

Confirmed arg structure (from `lending/params.rs::build_arguments`,
`asset_auth{,_vault}/params.rs`):
- **PRINCIPAL_INTEREST_RATE is `u64` in v3** (build_arguments casts the u16 OfferParameters
  field to u64) — a CMR-relevant change from v2's u16. LOAN_EXPIRATION_TIME stays u32.
- Both vault variants use `asset_auth_vault.simf`; Active vs Finalized differ only by
  `IS_ACTIVE` and `FINALIZED_VAULT_COV_HASH` (Finalized = all-zero; Active = the finalized
  variant's script hash). Chain per side: finalized → active(finalized_hash).
- lender vault: keeper=lender_nft, keeper_burn=true, supplier_burn=true.
  protocol-fee vault: keeper=protocol_fee_keeper, keeper_burn=**false**, supplier_burn=true.
  Both: vault=principal, supplier=borrower_nft, keeper_min=1.
- principal_output_script_hash = `AssetAuth(borrower_nft, 1, with_asset_burn=false)` — v3
  replaces v2's wallet `borrower_output_script_hash`.
- `get_script_hash()` == the manifest `compute: tapleaf` (= sha256(single-leaf p2tr spk)).

The engine already had everything: nested/topological create_instance computes (proven in
v2), tapleaf compute, and the bytes32 zero via a param default (`ZERO_HASH`, referenced by the
finalized-vault computes).

**Verification** (`cargo test lending_v3_create_offer_reproduces_live_offer_out5`, 31 pass):
drives the ACTUAL manifest file's `CreateOffer.create_instance` with offer 43ab4efe's resolved
values → the 5 nested hashes match `examples/lending_recon.rs`, and folding the 2 pending
storage leaves reproduces out[5] `51201ae9d30d…fbd84e1` byte-exactly. Acceptance MATCH=true.

Blocks removed for task 06's arg chain. Task 06 (full tx assembly) still needs two engine
extensions — see upnext/10 (computed 32-byte storage leaf) and upnext/11 (script_auth over a
covenant-with-storage).
