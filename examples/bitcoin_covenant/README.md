# bitcoin_covenant

A Simplicity covenant on **Bitcoin**: coins locked under a program the node itself
executes, then spent by satisfying it.

The program is `p2pk.simf` — byte-identical to the one in `examples/p2pk`, which runs on
Liquid. Nothing about the source is Bitcoin-specific:

```
fn main() {
    let sig: Signature = witness::SIGNATURE;
    jet::bip_0340_verify((param::PUB_KEY, jet::sig_all_hash()), sig);
}
```

It nonetheless produces a **different address on each chain**, for four independent
reasons: a jet's CMR depends on its position in its jet set, and all three taproot tags
(`TapLeaf`, `TapBranch`, `TapTweak`) are domain-separated with an `/elements` suffix. The
same source, the same key, two addresses that have nothing to do with each other.

Two actions:

- **`Lock`** — pay into the covenant. An ordinary payment as far as the chain is concerned;
  the covenant is just a P2TR output.
- **`Unlock`** — spend it. The engine builds the transaction, computes `sig_all_hash` from
  it, signs with the wallet key, and assembles the four-item Simplicity tapscript witness
  `[witness, program, CMR, control block]`. The node then *runs the program*.

## Requirements

A node that executes Simplicity. No public network has activated it, so this needs
`contrib/regtest`:

```sh
docker build -t simplicity-regtest contrib/regtest
docker run -d --name simplicity-regtest -p 18443:18443 simplicity-regtest \
  -regtest -server -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
  -rpcuser=tx -rpcpassword=manifest -fallbackfee=0.0001 -txindex=1
```

`config.json` here sets `simplicity_activated: true`. Without it the run is refused before
anything is derived — the wallet will not build a covenant address for a node that cannot
spend it:

```
Error: network 'bitcoin-regtest' cannot provide what this manifest requires (simplicity)
```

## Running it

Fund a wallet with the faucet, then put its **Wallet Signing Key** into `params.json` as
`PUB_KEY` — that is the key the covenant will demand, so it has
to be one this wallet can produce:

```sh
CFG="--config examples/bitcoin_covenant/config.json"
W=/tmp/txm-regtest/wallet.json

./contrib/regtest/faucet.sh --config examples/bitcoin_covenant/config.json --wallet $W
cargo run -p tx-manifest-wallet -- $CFG info --wallet $W   # copy "Wallet Signing Key"
```

Lock:

```sh
cargo run -p tx-manifest-wallet -- $CFG \
  run examples/bitcoin_covenant/txmanifest.json Lock \
  --wallet $W --params examples/bitcoin_covenant/params.json
```

`Lock` writes a state file recording the covenant it created, so `Unlock` can find it —
pass the one `Lock` wrote:

```sh
cargo run -p tx-manifest-wallet -- $CFG \
  run examples/bitcoin_covenant/txmanifest.json Lock \
  --wallet $W --params examples/bitcoin_covenant/params.json \
  --state-out /tmp/cov.state.json

./contrib/regtest/mine.sh

cargo run -p tx-manifest-wallet -- $CFG \
  run examples/bitcoin_covenant/txmanifest.json Unlock \
  --wallet $W --params examples/bitcoin_covenant/params.json \
  --state /tmp/cov.state.json --state-out /tmp/cov.state.2.json
```

State is written only on broadcast. With `--export-pset` nothing is relayed, so there is no
covenant yet to record — name the outpoint yourself in that case:

```sh
--input vault_in=<lock txid>:0
```

You should see:

```
· Covenant input 'vault_in' — satisfying… OK
```

and the node accept a 142-vbyte transaction whose witness is four items: 64 bytes of
Simplicity witness, a 53-byte program, the 32-byte CMR, and a 33-byte control block.

## Limits worth knowing

- **A pinned covenant input needs its `amount_sat` supplied.** `--input id=txid:vout` alone
  leaves it zero, and `vault_in.amount_sat - fee` then goes negative. The state file carries
  the amount, so this only bites when naming an outpoint by hand — use `--inputs-file`
  there, until the Bitcoin path looks the value up on chain.
- **No environment pruning.** SimplicityHL's `satisfy_with_env` is typed to `ElementsEnv`,
  so the Bitcoin path satisfies unpruned and a program with branches carries its dead ones
  into the witness. Fine for `p2pk`, which has none.
- **Roughly 27 of 428 jets have their FFI wired** in `rust-simplicity`. `p2pk` uses
  `bip_0340_verify` and `sig_all_hash`, both of which do. Most richer covenants do not yet.
- Output lines say `sat lbtc`. The asset label is Elements vocabulary the shared assembly
  still speaks; on Bitcoin there is one asset and it is BTC.
