# Phase 2e — Engine: script-hash of a covenant WITH storage leaves

## Goal
Provide a compute that yields `sha256(scriptPubKey)` of a covenant compiled WITH its
taproot storage leaves, so the offer's `lender_nft_script_auth` covenant (out[3]) can be
keyed to the pending lending covenant's real script hash.

## Why
out[3] locks the lender NFT in a ScriptAuth keyed by
`ScriptAuth::from_simplex_program(pending_offer)` → `SCRIPT_HASH = pending_offer.get_script_hash()`,
which is `sha256(spk)` of the lending covenant **including its 2 storage slots** (the pending
offer's actual address, = sha256(out[5] spk)).

The manifest's `compute: tapleaf` calls `compute_covenant_script_hash`
(`covenant.rs:65-75`) which passes `extra_leaf_payloads = &[]` — i.e. it hashes the
STORAGE-LESS covenant. That produces the wrong SCRIPT_HASH for out[3].

## Work
Options (pick one):
1. Add a `compute: script_hash_with_leaves` (or a flag on tapleaf) that takes the same
   `extra_leaves`/storage spec as the utxo_type and computes `sha256(spk)` with the leaves
   folded in — reuse task-10's computed-leaf resolver.
2. Or expose the lending_collateral utxo_type's own computed scriptPubKey hash as an
   instance field (`LENDING_COV_SCRIPT_HASH`) that the `lender_nft_script_auth` utxo_type
   already references in its compile_params (see the manifest — the wiring is in place).

## Acceptance
- `LENDING_COV_SCRIPT_HASH` = sha256(out[5] spk) for live offer 43ab4efe; the
  `lender_nft_script_auth` covenant address (out[3]) reproduces that offer's out[3].
- Verified against the live offer's out[3] scriptPubKey.

## Files
- `txmanifest_lib/src/covenant.rs` (`compute_covenant_script_hash` variant),
  `txmanifest_lib/src/lifecycle.rs` (compute wiring),
  `examples/lending_v3/txmanifest.json` (`LENDING_COV_SCRIPT_HASH` field).

## Needed by
- Task 06 (offer creation out[3]).

---
## DONE (2026-07-14)

Went with a hybrid of options 1+2. Extended the `create_instance` `Tapleaf` compute with an
optional `extra_leaves` list; when present the value is
`sha256(spk WITH those leaves)` via new `covenant::compute_covenant_script_hash_with_leaves`
(the storage-less path is unchanged). Leaf value-refs resolve against the in-progress
create_instance fields (new `resolve_create_instance_leaves`, reusing task-10's
`encode_leaf_bytes`), so a leaf can reference sibling computed fields like `CURRENT_DEBT`;
topological retry defers until they are ready.

Wired into `examples/lending_v3/txmanifest.json`: `LENDING_COV_SCRIPT_HASH` = tapleaf over
lending.simf (all 13 params) + the 2 storage `extra_leaves`. The `lender_nft_script_auth`
utxo_type already maps `SCRIPT_HASH ← LENDING_COV_SCRIPT_HASH`.

Verified (test `lending_v3_create_offer_reproduces_live_offer_out5`, 32 pass):
`LENDING_COV_SCRIPT_HASH == sha256(out[5] spk) == 2f40d78c…5b19` for live offer 43ab4efe, and
the out[3] `lender_nft_script_auth` covenant compiles from it. Full match against the live
offer's on-chain out[3] scriptPubKey is deferred to task 06 (needs the live tx / a broadcast).
