# oracle_demo

Burn L-BTC for a stablecoin at the **current** BTC/USD price, on Liquid.

A Simplicity program can check that an oracle signed a price, but not that the price is
current: nothing on chain says what time it is now. Without that check, a user could
present an old statement from when the price was higher, and mint more than their L-BTC is
worth. This example closes the gap with a challenge window instead of an oracle-side
expiry mechanism:

1. **RequestMint**: the user presents a signed price statement. The covenant checks the
   signature, locks the L-BTC and reserves the tUSDT it buys at that price.
2. **Challenge**: until the request is finalized, anyone holding a *newer* statement whose
   price differs by more than a tolerance can cancel it. The L-BTC is refunded and the
   tUSDT goes back to the treasury.
3. **Finalize**: once the window has passed (5 blocks, about 5 minutes, by default),
   anyone can complete the request. The tUSDT goes to the user and the L-BTC is burned.

A stale request is safe to submit only if nobody is watching. A watcher needs nothing but
the latest statement and a fee, so one honest watcher is enough.

## Oracle statements

Statements use [Mycelia Signal](https://github.com/jonathanbulkeley/Mycelia-Signal-Sovereign-Oracle/blob/main/docs/DEMO.md)'s
format, signed with secp256k1 ECDSA over the sha256 of a canonical string:

```json
{
  "domain": "BTCUSD",
  "canonical": "v1|PRICE|BTCUSD|84231.50|USD|2|binance,bitstamp,coinbase,kraken,okx|median|1741514400|482910",
  "signature": "MEQCICzgChRNZZFqQ4VF1/TluMyqneOcwBfPnSviptH2X9QgAiA/GR4IyZIIALG76QjUwiqcdUKfVm69Y0+bqvzhiWyNqw==",
  "pubkey": "02917e9826b0e7a61f695a5bb1a37714d1d742da025f4127c48892f3e4dbce8ba0",
  "signing_scheme": "secp256k1_ecdsa"
}
```

The statements here are fake. [`fake_oracle.py`](fake_oracle.py) signs them with a local
test key, [`data/example_oracle_key.json`](data/example_oracle_key.json), which is public: anyone can sign
"oracle" statements with it. Use it on testnet only. The same goes for the cold key below.

The covenant verifies the string itself. It cannot split a string, so the witness carries
the variable fields already separated (price digits, sources, method, timestamp, nonce),
and the program hashes them back together between the fixed parts (`v1|PRICE|BTCUSD|`,
`.`, `|USD|2|` and the separators). Number fields must be all digits and text fields may
not contain `|`. A signed string can therefore only be read one way, and a witness can't
move a field boundary to make some other number read as the timestamp. The ECDSA check is
`lib/secp256k1/ecdsa.simf`, a proposed addition to
[simplicityhl-std](https://github.com/BlockstreamResearch/simplicityhl-std) that is not
yet upstream. It is copied into the program because the wallet compiles each program from
a single file.

## Which oracle keys count

The service doesn't fix an oracle key. It fixes a **cold key**, `COLD_PUBKEY`, which
certifies oracle keys: a BIP340 signature saying "this oracle key may sign statements
timestamped from `valid_from` to `valid_until`". Each statement is presented with the
certificate for the key that signed it, and the covenant checks both signatures and that
the statement's timestamp is in range. Request and challenge statements can come from
different certified keys.

```json
{
  "oracle_pubkey": "02917e9826b0e7a61f695a5bb1a37714d1d742da025f4127c48892f3e4dbce8ba0",
  "valid_from": 1741500000,
  "valid_until": 1744092000,
  "cold_pubkey": "b895fcd559365049a2602890e406a3114ffe7b482beddc09686ecd2586cfbcd3",
  "signature": "…",
  "scheme": "bip340",
  "tag": "oracle-demo/oracle-cert/v1"
}
```

The cold key signs `tagged_hash("oracle-demo/oracle-cert/v1", pubkey ‖ valid_from ‖
valid_until)`, the key in its 33-byte compressed form and the times as 8-byte big-endian
integers. The tag keeps any other signature by the cold key from passing for a
certificate.

- **A new or rotated oracle needs a new certificate, not a new deployment.** The oracle
  takes no part: the cold key certifies whatever key the oracle already publishes.
- **The cold key can be a committee.** A MuSig2 or FROST aggregate key signs like any
  other BIP340 key, so `M`-of-`N` approval needs no change to the program.
- **Revocation is expiry.** Nothing on chain can say a certificate was withdrawn, so keep
  certificates short-lived, with the next one issued before the last expires.
- **The range is checked against the statement's timestamp, not the chain's time**, which
  a program can't read. An expired certificate still covers its own old statements, which
  is harmless: they are stale, so any current statement can challenge them.

## How it works

One program, [`oracle_mint.simf`](oracle_mint.simf), holds two kinds of address, told apart
by a tapdata leaf beside the program leaf:

| State | Tapdata leaf | Holds |
|-------|--------------|-------|
| treasury | `0x00` | the tUSDT supply |
| pending | `0x01 ‖ price ‖ timestamp ‖ L-BTC amount ‖ recipient` | one request: its L-BTC and its reserved tUSDT, two UTXOs at one address |

| Action | Spends | Creates | The covenant checks |
|--------|--------|---------|---------------------|
| `RequestMint` | treasury (input 0), wallet L-BTC | pending L-BTC, pending tUSDT, treasury change | the statement and its certificate; that the tUSDT is `L-BTC × price` and both outputs pay the request's pending address |
| `Finalize` | pending L-BTC (input 0), pending tUSDT (input 1) | tUSDT to the recipient, L-BTC burned | that input 0 is at least `WINDOW_BLOCKS` old, through its own `nSequence` |
| `Challenge` | pending L-BTC (input 0), pending tUSDT (input 1) | L-BTC refund, tUSDT to the treasury | a newer certified statement, whose price differs from the request's by more than `TOLERANCE_BPS` |

The tUSDT input of a pending pair only checks that it sits beside its L-BTC at input 0,
which checks the whole transaction. That shortcut is refused at the treasury address,
because otherwise a second treasury UTXO could be spent alongside a request with nothing
checking where its tUSDT went.

Both assets have 8 decimal places, so a request for `A` satoshis at `P` cents buys
`A × P / 100` tUSDT base units, rounded down.

tUSDT is issued by a separate manifest, [`issue_usdt/`](issue_usdt), because the service's
addresses depend on the asset id. The id only exists once the issuing transaction has
chosen its input.

## Files

| File | What it is |
|------|------------|
| [`txmanifest.json`](txmanifest.json) | The mint service: `CreateTreasury`, `RequestMint`, `Finalize`, `Challenge`. |
| [`oracle_mint.simf`](oracle_mint.simf) | The covenant. |
| [`issue_usdt/txmanifest.json`](issue_usdt/txmanifest.json) | Issues the tUSDT supply: `IssueUSDT`. |
| [`fake_oracle.py`](fake_oracle.py) | Signs statements, certifies oracle keys with the cold key, verifies both, and turns them into `--params` files. Needs `pip install ecdsa`. |
| [`data/`](data) | The test oracle and cold keys, the oracle's certificate, and the signed statements the tests use. |

## Running it on Liquid testnet

You need a funded Liquid testnet wallet (see the [quick start](../../README.md#quick-start-liquid-testnet)).
Each request below burns 5,000 sat. `run` asks for a fee rate and confirms before each
broadcast; after each one, wait for it to confirm and `sync` before the next.

```sh
W=wallet.json
TXM=tx-manifest-wallet
cd examples/oracle_demo
```

**1. Certify the oracle, issue tUSDT and start the service.** `certify` signs a 30-day
certificate for the oracle key with the cold key. `IssueUSDT` writes
`issue_usdt/txmanifest.instance.1.json`; its `USD_ASSET` is the new asset id.
`CreateTreasury` asks for it, for the amount to lock (`SUPPLY`; lock all of it, by default
100000000000000), and for `COLD_PUBKEY`, which `fake_oracle.py cold-keygen` printed when
the key was made: `b895fcd559365049a2602890e406a3114ffe7b482beddc09686ecd2586cfbcd3` for
the committed one. The window and tolerance have defaults.

```sh
python3 fake_oracle.py certify --valid-from $(( $(date +%s) - 7200 )) --out cert.json
$TXM run issue_usdt/txmanifest.json IssueUSDT --wallet $W
$TXM sync --wallet $W
$TXM run txmanifest.json CreateTreasury --wallet $W
```

`CreateTreasury` writes `txmanifest.instance.1.json` and `txmanifest.state.1.json`. Every
later action takes the instance and the newest state file, and writes the next state file.

**2. An honest mint.** Sign a statement at the current price, request, wait out the window,
finalize. `--recipient` is the address that receives the tUSDT, or the refund. Use one
from `$TXM info --wallet $W`.

```sh
python3 fake_oracle.py sign --price 84231.50 --out now.json
python3 fake_oracle.py request-params now.json --cert cert.json --lbtc-amount 5000 --recipient <address> --out request.json

$TXM run txmanifest.json RequestMint --wallet $W --params request.json \
  --instance txmanifest.instance.1.json --state txmanifest.state.1.json

# Finalize before 5 blocks have passed and the node refuses it: non-BIP68-final.
$TXM run txmanifest.json Finalize --wallet $W --params request.json \
  --instance txmanifest.instance.1.json --state txmanifest.state.2.json
```

**3. A stale price, challenged.** Request with a statement from an hour ago, when the price
was higher, then challenge it with a current one. The challenge needs no wait, and any
wallet can send it.

```sh
python3 fake_oracle.py sign --price 95000.00 --timestamp $(( $(date +%s) - 3600 )) --out stale.json
python3 fake_oracle.py request-params stale.json --cert cert.json --lbtc-amount 5000 --recipient <address> --out stale-request.json
$TXM run txmanifest.json RequestMint --wallet $W --params stale-request.json \
  --instance txmanifest.instance.1.json --state txmanifest.state.3.json

python3 fake_oracle.py sign --price 84231.50 --out now.json
python3 fake_oracle.py challenge-params stale-request.json now.json --cert cert.json --out challenge.json
$TXM run txmanifest.json Challenge --wallet $W --params challenge.json \
  --instance txmanifest.instance.1.json --state txmanifest.state.4.json
```

A challenge with a statement within the tolerance (0.5% by default), or one no newer than
the request's, fails the covenant's dry run and is never broadcast.

## Limitations

- **A request can be challenged until it is finalized, not only during the window.** A
  program can't require that a height has *not* been reached. If the price moves past the
  tolerance after the window but before `Finalize`, an honest request can still be
  cancelled. The user loses only fees, and finalizing promptly avoids it.
- **A leaked oracle key can date statements in the future.** Its certificate lets it sign
  any timestamp up to `valid_until`, and a request at a timestamp no honest statement has
  reached yet can't be challenged until one does, by which time it may be finalized.
  Short certificates narrow this; they don't close it.
- **The cold key is trusted completely.** Whoever holds it can certify their own oracle.
  It is used rarely and can be a committee, but there is no check beyond its signature.
- **One statement per request.** There is no quorum of oracles and no reward for a
  challenger.
- **Requests run one at a time per state file.** When a state file holds several pending
  requests, the wallet takes the first one it finds; pass `--input` to choose another.
- **Only `BTCUSD` with two decimals.** The program fixes `v1|PRICE|BTCUSD|…|USD|2|`, and
  the price must be printed with exactly two fraction digits.
- **Budget padding.** Checking a statement costs more execution budget than the
  statement's bytes buy, so `RequestMint` and `Challenge` pad the witness with zero words
  (`BUDGET_PAD`). Liquid doesn't relay the annex that would otherwise pad it. If `run`
  reports that the program's cost exceeds its budget, add more zeros.

## Tests

`cargo test -p tx-manifest-lib --test oracle_demo` runs every spending path on the
Simplicity interpreter against transactions it builds, with the statements in `data/`.
It covers forged prices, a `|` hidden in a text field, a finalize before the window, a
challenge within the tolerance or with an older statement, a second treasury UTXO spent
alongside a request, and the execution budget of each path. For certificates: a statement
outside its certificate's range, a certificate from another key, for another oracle, or
with its range altered, and a challenge from an oracle certified after the request. The
statements in `data/` carry the certificate `fake_oracle.py` made, so the program checks the
script's BIP340 signer.
