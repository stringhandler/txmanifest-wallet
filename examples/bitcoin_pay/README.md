# bitcoin_pay

The smallest manifest that runs on Bitcoin, and a worked example of what `requires: []`
buys you: no covenant, no Simplicity, nothing a stock node lacks.

Two actions:

- **`Pay`** — spend one wallet UTXO to an address, returning the remainder as change.
- **`Sweep`** — send the whole of one UTXO, less the fee. Exercises the `fee` keyword,
  which is resolved from the built transaction's size rather than guessed.

Everything else here is Elements-only, so this is also the reference for what a
Bitcoin-targeted manifest may and may not say. `validate` will tell you if you stray:
an `asset` other than the policy one, an issuance input, or a blinded output is rejected
against `chain: "bitcoin"` with the field named.

## Running it

Needs a Bitcoin node. `contrib/regtest` builds one with Simplicity active — overkill for
these two actions, which need none of it, but it is the node that is already there.

```sh
docker build -t simplicity-regtest contrib/regtest
docker run -d --name simplicity-regtest -p 18443:18443 simplicity-regtest \
  -regtest -server -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
  -rpcuser=tx -rpcpassword=manifest -fallbackfee=0.0001 -txindex=1
```

`config.json` in this directory points at that node. Pass it with `--config`, which keeps
your real wallet config — living in the platform data directory, not the current one —
entirely out of it:

```sh
cargo run -p tx-manifest-wallet -- --config examples/bitcoin_pay/config.json config
```

That prints the file it resolved, which is worth checking once: without `--config` the
wallet reads `~/Library/Application Support/tx-manifest-wallet/config.json` (or the
platform equivalent), and a `config.json` sitting next to a manifest is *not* picked up on
its own. Set `TX_MANIFEST_DATA_DIR` instead if you want the config and the persisted wallet
state to move together.

Create a wallet and find out where to send funds:

```sh
CFG="--config examples/bitcoin_pay/config.json"
cargo run -p tx-manifest-wallet -- $CFG create-wallet --out /tmp/txm-regtest/wallet.json
cargo run -p tx-manifest-wallet -- $CFG info --wallet /tmp/txm-regtest/wallet.json
```

There is no `--regtest` flag and none is needed: `create-wallet` takes the network from
the config, and records it by name — the file will say `bitcoin-regtest`.

The same mnemonic works across regtest, signet and testnet, which all use SLIP-44 coin type
`1'`. It does **not** carry to mainnet, which uses `0'` and so derives entirely different
addresses.

Fund it by mining. **201 blocks, not 101**: a block reward needs 100 confirmations before
it can be spent, so 101 leaves you one mature coin and a hundred the wallet correctly
refuses. It says so when it skips them.

```sh
docker exec simplicity-regtest bitcoin-cli -regtest -rpcuser=tx -rpcpassword=manifest \
  generatetoaddress 201 <receive-address-from-info>
```

Then run an action. `params.json` here pays to a fixed address; change `dest` to anything
valid for the network — a mainnet address is refused rather than silently accepted.

```sh
cargo run -p tx-manifest-wallet -- $CFG run examples/bitcoin_pay/txmanifest.json Pay \
  --wallet /tmp/txm-regtest/wallet.json \
  --data-dir /tmp/txm-regtest \
  --params examples/bitcoin_pay/params.json
```

It prompts before broadcasting. To inspect the transaction first instead, add
`--export-pset signed.json` — that writes `{txid, tx_hex}` and sends nothing:

```sh
docker exec simplicity-regtest bitcoin-cli -regtest -rpcuser=tx -rpcpassword=manifest \
  testmempoolaccept "[\"$(jq -r .tx_hex signed.json)\"]"
```

## What you should see

`Pay` builds two outputs and `Sweep` one, both at the requested fee rate:

```
Pay    PSBT constructed (1 inputs, 2 outputs, fee 308 sat).   vsize 154 -> 2.00 sat/vB
Sweep  Estimated network fee: 222 sat (resolves `fee`)
       PSBT constructed (1 inputs, 1 outputs, fee 222 sat).   vsize 111 -> 2.00 sat/vB
```

## Known cosmetic wrinkles

Output lines read `150000 sat lbtc`. The asset label is Elements vocabulary the shared
assembly still speaks on both chains; on Bitcoin there is one asset and it is BTC.
`create-wallet` likewise prints `Network : testnet`, which is the wallet file's own
mainnet/testnet flag rather than the chain — `info` shows the real one.
