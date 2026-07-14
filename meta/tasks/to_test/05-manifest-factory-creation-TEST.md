# Manual test — factory creation (task 05)

Goal: broadcast a `CreateFactory` tx on Liquid testnet and confirm the deployed
simplicity-lending indexer registers the factory.

## Offline checks (no wallet — already green, re-run to confirm)

```sh
cargo run --bin tx-manifest-wallet -- validate examples/lending_v3/txmanifest.json
cargo run --example factory_recon           # out[1] spk == 5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b
cargo run --example factory_opreturn_recon  # op_return == dd1e7f89020000000000000000 (13 bytes)
```

## On-chain (needs a funded Liquid testnet wallet)

```sh
# 1. Wallet + L-BTC funds
cargo run -- create-wallet --out wallet.json
cargo run -- info --wallet wallet.json      # send some testnet L-BTC to the receive address
cargo run -- sync --wallet wallet.json

# 2. Make sure there is a spendable L-BTC UTXO for the issuance input
cargo run -- prepare examples/lending_v3/txmanifest.json CreateFactory --wallet wallet.json

# 3. Create the factory (constructor — writes lending_v3.instance.json)
cargo run -- run examples/lending_v3/txmanifest.json CreateFactory --wallet wallet.json
```

## What to verify

1. The run prints a covenant output whose scriptPubKey is
   `5120456881785cc7d561caaa059e02f1a2823066bd860423996bea3e92c621bb064b` (out[1]).
2. `lending_v3.instance.json` is written with a `FACTORY_ASSET_ID` set.
3. On a testnet explorer, the broadcast tx has:
   - out[0]: factory asset, amount 1, to your wallet address (auth NFT)
   - out[1]: factory asset, amount 1, to the covenant address above
   - out[2]: OP_RETURN, 13 bytes, starting `dd1e7f89`
4. The deployed site/indexer (`lending.dev.blockstream.com`) registers the factory
   (owner holds the auth NFT). If it does NOT appear, first suspects:
   - out[2] not exactly at index 2, or program_id != `dd1e7f89` (CRLF/source drift);
   - covenant address differs (debug-symbols flag, params != (2,0));
   - more or fewer than one amount-1 program output / one amount-1 auth output.

## On success
Move `05-manifest-factory-creation.md` to `meta/tasks/done/`. Task 06 (offer creation)
can be authored against the resulting `lending_v3.instance.json` before this passes.
