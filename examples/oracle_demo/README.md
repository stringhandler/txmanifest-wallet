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
"oracle" statements with it. Use it on testnet only.

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

## How it works

One program, [`oracle_mint.simf`](oracle_mint.simf), holds two kinds of address, told apart
by a tapdata leaf beside the program leaf:

| State | Tapdata leaf | Holds |
|-------|--------------|-------|
| treasury | `0x00` | the tUSDT supply |
| pending | `0x01 ‖ price ‖ timestamp ‖ L-BTC amount ‖ recipient` | one request: its L-BTC and its reserved tUSDT, two UTXOs at one address |

| Action | Spends | Creates | The covenant checks |
|--------|--------|---------|---------------------|
| `RequestMint` | treasury (input 0), wallet L-BTC | pending L-BTC, pending tUSDT, treasury change | the statement's signature; that the tUSDT is `L-BTC × price` and both outputs pay the request's pending address |
| `Finalize` | pending L-BTC (input 0), pending tUSDT (input 1) | tUSDT to the recipient, L-BTC burned | that input 0 is at least `WINDOW_BLOCKS` old, through its own `nSequence` |
| `Challenge` | pending L-BTC (input 0), pending tUSDT (input 1) | L-BTC refund, tUSDT to the treasury | a newer statement, whose price differs from the request's by more than `TOLERANCE_BPS` |

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
| [`fake_oracle.py`](fake_oracle.py) | Signs statements, verifies them, and turns them into `--params` files. Needs `pip install ecdsa`. |
| [`data/`](data) | The test oracle key and the signed statements the tests use. |

## Running it on Liquid testnet

You need a funded Liquid testnet wallet (see the [quick start](../../README.md#quick-start-liquid-testnet)).
Each request below burns 5,000 sat. `run` asks for a fee rate and confirms before each
broadcast; after each one, wait for it to confirm and `sync` before the next.

```sh
W=wallet.json
TXM=tx-manifest-wallet
cd examples/oracle_demo
```

**1. Issue tUSDT and start the service.** `IssueUSDT` writes
`issue_usdt/txmanifest.instance.1.json`; its `USD_ASSET` is the new asset id.
`CreateTreasury` asks for it, for the amount to lock (`SUPPLY`; lock all of it, by default
100000000000000), and for the oracle key, which `fake_oracle.py keygen` printed when the key
was made. For the committed key, the prefix is `2` and the x-coordinate is
`917e9826b0e7a61f695a5bb1a37714d1d742da025f4127c48892f3e4dbce8ba0`. The window and
tolerance have defaults.

```sh
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
python3 fake_oracle.py request-params now.json --lbtc-amount 5000 --recipient <address> --out request.json

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
python3 fake_oracle.py request-params stale.json --lbtc-amount 5000 --recipient <address> --out stale-request.json
$TXM run txmanifest.json RequestMint --wallet $W --params stale-request.json \
  --instance txmanifest.instance.1.json --state txmanifest.state.3.json

python3 fake_oracle.py sign --price 84231.50 --out now.json
python3 fake_oracle.py challenge-params stale-request.json now.json --out challenge.json
$TXM run txmanifest.json Challenge --wallet $W --params challenge.json \
  --instance txmanifest.instance.1.json --state txmanifest.state.4.json
```

A challenge with a statement within the tolerance (0.5% by default), or one no newer than
the request's, fails the covenant's dry run and is never broadcast.

### A run on Liquid testnet

| Step | Transaction |
|------|-------------|
| `IssueUSDT` | [`67ed381d…a72c`](https://liquid.network/testnet/tx/67ed381d6ff6566b73d209141a68c586f56e2b8942106903a8736c9ec251a72c) |
| `CreateTreasury` | [`6043ee78…c1d1`](https://liquid.network/testnet/tx/6043ee78ab30fe90957f5a5d8112211a606f8d06e74c6b08477605e5b29ac1d1) |
| `RequestMint` at 84231.50 | [`4b3d45d9…24b7`](https://liquid.network/testnet/tx/4b3d45d955b3dd3174a305f6e178b9bd10342ba1a030720fff0c3248111824b7) |
| `Finalize`: 4.211575 tUSDT paid, 5,000 sat burned | [`69c2c404…0786`](https://liquid.network/testnet/tx/69c2c404d0c1a0e11d752d01154d1c6fdc6900cdc77ad59e0d76542316cc0786) |
| `RequestMint` at a stale 95000.00 | [`513edff5…f74b`](https://liquid.network/testnet/tx/513edff5ac5d07a42dc9e84015e5b7a33a8dbab0f602ad72072f4a2d5cfef74b) |
| `Challenge` at 84231.50: 5,000 sat refunded, 4.75 tUSDT back to the treasury | [`f6eaad84…bcfa`](https://liquid.network/testnet/tx/f6eaad84c2a4e71f871ec50fc07245bcb9a18ef5352e45aa445cba51cfb7bcfa) |

## Limitations

- **A request can be challenged until it is finalized, not only during the window.** A
  program can't require that a height has *not* been reached. If the price moves past the
  tolerance after the window but before `Finalize`, an honest request can still be
  cancelled. The user loses only fees, and finalizing promptly avoids it.
- **One oracle, fixed at deployment.** The key is a compile param. There is no quorum of
  statements, no committee-attested key, and no reward for a challenger.
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
alongside a request, and the execution budget of each path.
