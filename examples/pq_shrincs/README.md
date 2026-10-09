# SHRINCS: a post-quantum signature on Bitcoin

Coins locked to a [SHRINCS](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier)
public key, spendable only with a SHRINCS signature by that key over the spending
transaction. SHRINCS is a hash-based signature scheme, so its security doesn't rest on
discrete logs. A Simplicity program on the Simplicity signet verifies the signature.

The program is upstream's verifier plus a small wrapper,
[`src/shrincs_spend.simf`](src/shrincs_spend.simf). The wrapper takes the public key from
`param::PK`, so it is part of the address, and the message from `jet::sig_all_hash()`, so
the signature covers this transaction. The spender supplies only the signature.

> **Experimental.** Two limits apply beyond the wallet's usual warning.
> - These outputs are Taproot with an unspendable internal key. Someone who can compute
>   discrete logs could still spend them through the key path, so this shows what a
>   post-quantum spend costs; it doesn't make coins quantum-safe.
> - Signatures are stateful. Each one uses the next of a key's 207 leaf indexes, and
>   reusing an index lets anyone forge. Keep the key's state file with its seed, and never
>   copy or restore an old one.

## Files

- `shrincs_spend.simf`: the program the manifest pins. `build.sh` flattens it from
  `src/shrincs_spend.simf` and the vendored verifier in
  [`contrib/shrincs-simplicity-verifier`](../../contrib/shrincs-simplicity-verifier).
  Don't edit it directly.
- `lock.params.json`, `spend.params.json`: templates to fill in.

## Spending takes two runs

The wallet doesn't sign SHRINCS itself yet. The signature comes from
[`contrib/shrincs-signer`](../../contrib/shrincs-signer), and it has to cover the
transaction, which doesn't exist until the wallet builds it. So `Spend` runs twice:

1. With `--print-sighash`: build the transaction, print its `sig_all_hash`, stop.
2. With the signature: build the same transaction again, and broadcast it.

Both runs must build the *same* transaction, or the signature won't verify. Use the same
state file and the same params, apart from `SIG` and `OTHER_ROOT`. The manifest helps:
the destination is a fixed address, and the fee comes from a fixed `fee_rate`.

## Run it

Use a funded signet wallet; see [`bitcoin_covenant`](../bitcoin_covenant) for creating and
funding one.

```sh
CFG="--config examples/bitcoin_covenant/config.json"
W=/path/to/signet/wallet.json
M=examples/pq_shrincs
SIGNER=contrib/shrincs-signer/bin/shrincs-signer
KEY=~/.shrincs/key        # the seed and its state file live here; keep them together

# 1. Build the signer, and make a key.
make -C contrib/shrincs-signer
mkdir -p ~/.shrincs
$SIGNER new --seed $KEY.seed --state $KEY.q
$SIGNER pubkey --seed $KEY.seed          # prints PK

# 2. Lock coins to it. Put PK in a copy of lock.params.json.
cp $M/lock.params.json /tmp/pq.lock.json   # then set "PK"
cargo run -p tx-manifest-wallet -- $CFG run $M/txmanifest.json Lock \
  --wallet $W --params /tmp/pq.lock.json --state-out /tmp/pq.state.json

# 3. Print the sighash. Put PK and a destination address in a copy of spend.params.json
#    (`info --wallet $W` shows one of yours). Leave SIG and OTHER_ROOT as placeholders.
cp $M/spend.params.json /tmp/pq.spend.json   # then set "PK" and "dest"
cargo run -p tx-manifest-wallet -- $CFG run $M/txmanifest.json Spend \
  --wallet $W --params /tmp/pq.spend.json --state /tmp/pq.state.json --print-sighash
#    → prints:  vault_in  <sighash>

# 4. Sign it, and put the signature into the params.
$SIGNER sign --seed $KEY.seed --state $KEY.q --msg <sighash> > /tmp/pq.sig.json
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); p.update(json.load(open(sys.argv[2]))); json.dump(p,open(sys.argv[3],"w"),indent=2)' \
  /tmp/pq.spend.json /tmp/pq.sig.json /tmp/pq.spend.signed.json

# 5. Spend.
cargo run -p tx-manifest-wallet -- $CFG run $M/txmanifest.json Spend \
  --wallet $W --params /tmp/pq.spend.signed.json --state /tmp/pq.state.json \
  --state-out /tmp/pq.state.2.json
```

Expect a witness of about 18.8 KB, about 14.7 KB of it cost padding, and around 4,800 vB.
`spend.params.json` sets `fee_rate` to 15 because the wallet's fee estimate assumes about
1 KB of witness for a covenant input. 15 on that estimate comes to roughly 1.1 sat/vB on
the real transaction.

If step 5 reports that the program failed, the transaction differs from the one step 3
printed. Run step 3 again: the printed hash should not change. Then sign the new hash;
each attempt uses another leaf index.

`txmanifest_lib/tests/shrincs_verifier.rs` (`signed_spend_of_a_shrincs_locked_coin`)
runs the same spend offline with a test key.
