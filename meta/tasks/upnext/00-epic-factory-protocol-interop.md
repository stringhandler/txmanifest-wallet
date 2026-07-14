# EPIC: lending_v2 interop with the redesigned "issuance factory" protocol

## Goal
Make `examples/lending_v2` produce offer-creation transactions that the **deployed**
simplicity-lending indexer/site (`lending.dev.blockstream.com`) recognizes and lists —
i.e. byte-compatible covenant addresses + OP_RETURN + output layout for the
**issuance-factory** protocol on the `odev` branch of `e:\projects\simplicity-lending`.

## Why this epic exists
The previous lending_v2 matched an OLD local checkout of simplicity-lending. The
deployed site runs a redesigned protocol (~66 commits newer): `pre_lock.simf` is gone,
replaced by `issuance_factory.simf` + `asset_auth_vault.simf` and a "factory" flow.
Verified: a real working offer tx `43ab4efe05a698e63594a8406f1da6306bea70bd065e1ae42fc87a3d4cf1de74`
has 3 inputs, collateral covenant at out[5], 50-byte OP_RETURN at out[4].

## Deployed offer-creation tx layout (ground truth to reproduce)
Builder: `simplicity-lending/crates/contracts/tests/lending/setup.rs::setup_pending_offer`.

| idx | input | output |
|-----|-------|--------|
| 0 | factory auth-NFT (wallet p2wpkh) | factory asset (1) → wallet |
| 1 | **factory covenant (p2tr), issues borrower NFT** (`IssueAssets` witness) | factory covenant recreated |
| 2 | collateral wallet UTXO, **issues lender NFT** | borrower NFT (1) → wallet |
| 3 | — | lender NFT (1) → script_auth covenant |
| 4 | — | **OP_RETURN, 50 bytes** |
| 5 | — | **lending covenant (collateral) with 2 storage slots** |
| 6/7 | — | change / fee |

## Indexer detection (must all hold)
`indexer/src/indexer/trackers/{registry,factories/core,offers_creation/core,offers/tx_outputs}.rs`:
1. tx spends a tracked factory program UTXO and recreates it (factory params hardcoded `(2, 0, network)`).
2. does not spend an existing tracked offer UTXO.
3. ≥7 outputs; output[4] = OP_RETURN null-data, 50 bytes, first 4 bytes == lending `program_id`.
4. an output = reconstructed lending covenant by (asset, amount, scriptPubKey) — the collateral.
5. distinct borrower-NFT (amt 1) and lender-NFT (amt 1) outputs.

## Toolchain (must match)
`smplx-sdk 0.0.5` (crates.io), `simplicityhl 0.5.0`, `simplicity-lang 0.7.0`,
`simplicity-sys 0.6.2`. Covenants compiled with `include_debug_symbols = true` (unchanged).
NUMS key `50929b74…803ac0`, leaf version `0xbe`. All still match manifest-wallet.

## Phases (see other task files)
1. Verify storage-covenant reproduction (de-risk the tap tree). — upnext/01
2. Engine: tapdata tag, covenant-issuance input, OP_RETURN LE fields. — upnext/02-04
3. Manifest: factory creation, offer creation, nested-hash args. — backlog/05-07
4. Settlement flows + end-to-end verify. — backlog/08-09

## Definition of done
A freshly-built lending_v2 offer, reconstructed locally with the `odev` code, returns
`MATCH=true` (covenant addresses identical), and once broadcast appears on the deployed site.
