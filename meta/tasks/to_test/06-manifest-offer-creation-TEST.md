# Manual test — offer creation (task 06)

Goal: mint a pending lending offer from an existing factory on Liquid testnet and confirm
the deployed simplicity-lending indexer lists it.

## Offline checks (no wallet — already green)

```sh
cargo run --bin tx-manifest-wallet -- validate examples/lending_v3/txmanifest.json   # 0 errors/warnings
cargo test lending_v3_create_offer_reproduces_live_offer_out5                        # out[1]/out[3]/out[4]/out[5] reproduce live offer 43ab4efe
```

## Prerequisites
1. Task 05 factory created on testnet (`lending_v3.instance.json` with a `FACTORY_ASSET_ID`,
   and a state file recording the factory covenant UTXO). See `05-manifest-factory-creation-TEST.md`.
2. Wallet funded with: L-BTC for collateral (COLLATERAL_ASSET_ID) + fees, and holding the
   factory auth NFT.

## On-chain

```sh
cargo run -- sync --wallet wallet.json
cargo run -- prepare examples/lending_v3/txmanifest.json CreateOffer --wallet wallet.json

# CreateOffer is a constructor — pass the FACTORY instance/state so it can find + spend the
# factory covenant UTXO and its auth NFT. Provide offer terms via --params.
cargo run -- run examples/lending_v3/txmanifest.json CreateOffer \
    --wallet wallet.json \
    --instance lending_v3.instance.json \
    --state lending_v3.state.json \
    --params offer-params.json
```

`offer-params.json` (example — the live-offer values):
```json
{
  "FACTORY_ASSET_ID": "<factory asset id from the factory instance>",
  "COLLATERAL_ASSET_ID": "<L-BTC testnet policy asset>",
  "PRINCIPAL_ASSET_ID": "<loan asset id>",
  "PROTOCOL_FEE_KEEPER_ASSET_ID": "<deployed indexer's configured keeper asset>",
  "COLLATERAL_AMOUNT": "21000",
  "PRINCIPAL_AMOUNT": "1000",
  "PRINCIPAL_INTEREST_RATE": "10000",
  "LOAN_EXPIRATION_TIME": "2536857"
}
```

## What to verify
1. The run prints covenant outputs whose scriptPubKeys match:
   - out[1] factory: `5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b`
   - out[5] lending: recompute per offer (for the live-offer params it is
     `51201ae9d30d7a31f1393a289196a4dacc01fac95459540895db448aeca47fbd84e1`).
2. The dry-run satisfies the factory covenant `IssueAssets` (PATH::Left(0)) witness (in[1]).
3. Broadcast tx has 8 outputs; out[4] is a 50-byte OP_RETURN starting the lending program_id
   `f80c6162`.
4. The deployed indexer/site lists the offer. If not, first suspects:
   - protocol_fee_keeper asset id mismatch (out[5] covenant differs);
   - out[4] OP_RETURN not at index 4 / wrong program_id;
   - borrower/lender NFT positions;
   - factory params != (2,0).

## Blocking issues to watch (first real dry-run of these paths)
- Factory covenant `IssueAssets` witness satisfaction (never dry-run from the manifest before).
- Same-tx issuance asset-id flow: BORROWER_NFT (covenant input in[1]) + LENDER_NFT (wallet input
  in[2]) must resolve via `on_resolved` before out[3]/out[5]/OP_RETURN are built.
- Locating the factory covenant UTXO from `--state` (cross-instance: offer references the factory).

## On success
Move `06-manifest-offer-creation.md` to `meta/tasks/done/`. Then tasks 08 (settlement) and 09
(end-to-end verify) follow.
