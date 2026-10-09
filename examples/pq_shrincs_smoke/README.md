# SHRINCS smoke test (anyone-can-spend)

Runs the [SHRINCS](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier)
post-quantum signature verifier on the Simplicity signet. SHRINCS is a hash-based scheme.
The verifier is upstream's own example, unmodified, and the spend uses upstream's own
stateful signature.

**This is a smoke test, not a pattern to copy.** Upstream's example takes the public key
and the message as witness data. So the program checks that *some* valid SHRINCS
signature was supplied, for any key and any message. Anyone who sees the spend could have
made it, and the coin it locks is anyone-can-spend. Lock only a few thousand sats.

What it shows:
- the signet node runs a SHRINCS verification;
- it relays the spend, whose witness is about 18.8 KB, about 14.6 KB of it cost padding;
- the padding meets the node's rules.

`examples/pq_shrincs` is the version that pins the key and signs the transaction.

## Files

- `shrincs_main.simf`: the verifier, flattened by `build.sh` from
  [`contrib/shrincs-simplicity-verifier`](../../contrib/shrincs-simplicity-verifier).
  Don't edit it; rerun `build.sh` and `tx-manifest-wallet pin`.
- `lock.params.json`: lock 20,000 sat at 0.1 sat/vB.
- `spend.params.json`: spend at `fee_rate` 15. The wallet's fee estimate assumes about
  1 KB of witness for a covenant input, and this one is about 18.8 KB. 15 sat/vB on that
  estimate comes to about 5,300 sat, roughly 1.1 sat/vB on the real transaction of about
  4,790 vB.

## Run it

Use a funded signet wallet; see [`bitcoin_covenant`](../bitcoin_covenant) for creating
and funding one.

```sh
CFG="--config examples/bitcoin_covenant/config.json"
W=/path/to/signet/wallet.json
M=examples/pq_shrincs_smoke
cargo run -p tx-manifest-wallet -- $CFG sync --wallet $W
cargo run -p tx-manifest-wallet -- $CFG run $M/txmanifest.json Lock \
  --wallet $W --params $M/lock.params.json --state-out /tmp/shrincs-smoke.state.json
cargo run -p tx-manifest-wallet -- $CFG run $M/txmanifest.json Spend \
  --wallet $W --params $M/spend.params.json \
  --state /tmp/shrincs-smoke.state.json --state-out /tmp/shrincs-smoke.state.2.json
```

The spend should print `cost padding: 14623 bytes`.
