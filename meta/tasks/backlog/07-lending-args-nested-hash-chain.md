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
