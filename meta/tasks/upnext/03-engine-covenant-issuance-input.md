# Phase 2b — Engine: allow asset issuance on a covenant-sourced input

## Goal
Support an input that BOTH spends a Simplicity covenant (with a witness) AND carries a
new-asset issuance. The offer-creation tx's input 1 spends the factory covenant and
issues the borrower NFT from that covenant's outpoint.

## Reference behaviour
`issuance_factory/core.rs::attach_assets_issuance` (83-113):
- witness branch `IssueAssets { output_index }` (= the auth-NFT output index, out[0]).
- `add_program_issuance_input_with_signature(ft, program_utxo, IssuanceInput::new_issuance(1, 0, entropy), witness, RequiredSignature::None)`.
- then recreates the factory covenant output.
The borrower NFT asset id = `AssetId::from_entropy(f(input1.outpoint, entropy))` — same
entropy as the lender NFT (issued on input 2, a wallet input), different outpoint.

## Engine work
Today: covenant inputs (`utxo_source: {utxo_type}` + `witnesses`) and issuance inputs
(`utxo_source: "wallet"` + `issuance: {kind:new}`) are separate paths.
- Allow `issuance` on a covenant-sourced input.
- In the PSET builder / covenant finalize path, attach the issuance (asset entropy,
  amount, blinded flag) to that covenant input.
- Compute/track the issued asset id from the covenant input's outpoint (feed
  `on_resolved.set` so downstream fields get the asset id), same as wallet issuance.
- Entropy: the reference uses `get_random_seed()` (random). Random is fine for
  indexability (indexer reads asset ids positionally), but both NFTs share ONE entropy
  value across two issuance inputs — the manifest must reuse the same entropy for the
  borrower-NFT (covenant input) and lender-NFT (wallet input) issuances.

## Acceptance
- A manifest input can declare a covenant utxo_type + witnesses + issuance, and the
  built PSET issues the asset from that covenant input's outpoint.
- Asset id resolves and is usable in later outputs/fields.

## Files
- `txmanifest_lib/src/pset_builder.rs`, `txmanifest_lib/src/lifecycle.rs` (input
  resolution + issuance attrs), `txmanifest_lib/src/covenant.rs` (finalize path).
