# Simplicity regtest

A local Bitcoin regtest with Simplicity active, for exercising the Bitcoin path without a
faucet and without waiting on a public network that has not activated the soft fork.

Built from [`delta1/bitcoin@simplicity-inquisition`](https://github.com/delta1/bitcoin/tree/simplicity-inquisition),
which is the implementation proposed in BINANA 2026-0003.

## Build and run

```sh
docker build -t simplicity-regtest contrib/regtest
docker run -d --name simplicity-regtest -p 18443:18443 simplicity-regtest \
  -regtest -server -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
  -rpcuser=tx -rpcpassword=manifest -fallbackfee=0.0001 -txindex=1
```

Confirm the rules are on. `SIMPLICITY` appears in `script_flags`, not in `deployments` —
it is enabled for the chain rather than being deployed through BIP9:

```sh
docker exec simplicity-regtest bitcoin-cli -regtest -rpcuser=tx -rpcpassword=manifest \
  getdeploymentinfo | head -20
```

```
"script_flags": [ "ANYPREVOUT", "CHECKSIGFROMSTACK", "CHECKTEMPLATEVERIFY",
                  "INTERNALKEY", "NULLDUMMY", "OP_CAT", "P2SH", "SIMPLICITY",
                  "TAPROOT", "TEMPLATEHASH", "WITNESS" ]
```

## Point the wallet at it

```json
{
  "default_network": "bitcoin-regtest",
  "bitcoin_backend": "rpc",
  "bitcoin_rpc_url": "http://127.0.0.1:18443",
  "bitcoin_rpc_auth": "tx:manifest",
  "simplicity_activated": true
}
```

The node backend rather than Esplora: an Esplora instance for a four-block chain means an
indexer and an API server alongside the node, and `scantxoutset` finds our coins with no
wallet, no import and no rescan.

## Funding

Coinbase output needs 100 confirmations before it can be spent, so mine 101 blocks to an
address the wallet derives — `bitcoin-cli generatetoaddress 101 <address>`. The image is
built without wallet support, which is fine: `generatetoaddress` and `scantxoutset` are
node RPCs.

## What works against this today

Plain payments. Covenant spending needs a SimplicityHL build with the Bitcoin jet hinter,
which this crate does not yet pin — the node will execute Simplicity, but the wallet cannot
yet compile a program for it. See `covenant::jet_hinter`.
