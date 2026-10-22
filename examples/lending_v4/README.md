# lending_v4

[lending_v3](../lending_v3)'s issuance-factory lending protocol, plus liquidation at the
**current** price, through a challenge window.

lending_v3 liquidates only once a loan expires. Before then, a lender can't act on a
falling price: a program can check that an oracle signed a price, but not that the price
is current, so a lender could present a stale low price to seize collateral the loan
still covers. lending_v4 lets the lender start a liquidation with a signed statement, and
gives anyone with a newer statement time to stop it:

1. **StartLiquidation** (the lender, showing the lender NFT): a certified statement at
   which the debt is more than `LIQUIDATION_LTV_BPS` of the collateral's value. The loan
   moves to a pending state that records the statement's timestamp and price.
2. **CancelLiquidation** (anyone): a certified statement newer than the claim, at which the
   loan isn't liquidatable. The loan goes back to active.
3. **FinishLiquidation** (the lender): once `WINDOW_BLOCKS` have passed, the lender NFT is
   burned and the collateral released, as on expiry.

While a liquidation is pending, the borrower can still repay in full
(**RepayDuringLiquidation**), so a borrower racing to repay always wins.

This is a new protocol version. It does not interoperate with lending_v3 or with the
deployed simplicity-lending indexer: every covenant address is different. lending_v3's
indexer constants (the program-id tags, the protocol-fee keeper) are kept only as they
were.

## The liquidation threshold

`LIQUIDATION_LTV_BPS` defaults to 8000: a loan may be liquidated once the debt is more than
80% of the collateral's value, that is, once the collateral is worth less than 125% of the
debt. That is in line with common practice for bitcoin-backed loans, which typically
liquidate somewhere around 75–85% loan-to-value, and leaves room for the price to move
during the window.

The collateral is valued as `COLLATERAL_AMOUNT * price / 100` principal base units, which
assumes satoshis of collateral against a dollar asset with 8 decimal places: L-BTC against
tUSDT from [`oracle_demo/issue_usdt`](../oracle_demo/issue_usdt).

## How it works

Statements, certificates and the check that a statement isn't dated in the future are
[oracle_demo](../oracle_demo)'s, copied into [`lending.simf`](lending.simf) because the
wallet compiles each program from a single file. The ECDSA, parsing and certificate code
is unchanged from there.

The loan's state lives in storage slot 0, as in lending_v3, with one new value:

| State | Slot 0 (32 bytes) |
|-------|-------------------|
| offer | `0` |
| active | `1` |
| liquidation pending | `claim timestamp ‖ claim price ‖ 0 ‖ 2`, 8 bytes each, big-endian |

Offer and active are encoded exactly as in lending_v3, so their addresses are derived the
same way. Every pending claim has its own address.

The new paths sit behind a separate witness, `LIQUIDATION`. When it is `None`, the program
runs lending_v3's paths unchanged, selected by `PATH` as before.

| Action | Spends | Creates | The covenant checks |
|--------|--------|---------|---------------------|
| `StartLiquidation` | active loan (input 0), lender NFT (input 1) | pending loan (output 0), lender NFT back (output 1) | the statement and certificate; that it isn't dated more than `MAX_FUTURE_SECONDS` ahead (the lock time); that the loan is liquidatable at its price |
| `CancelLiquidation` | pending loan (input 0) | active loan (output 0) | a newer certified statement at which it isn't |
| `FinishLiquidation` | pending loan (input 0), lender NFT (input 1) | the NFT burned (output 0), the collateral to the lender | that input 0 is at least `WINDOW_BLOCKS` old |
| `RepayDuringLiquidation` | borrower NFT, pending loan (input 1), the repayment | as `RepayLoan` | as `RepayLoan`, from the pending state |

## Running it on Liquid testnet

You need a funded Liquid testnet wallet holding some tUSDT to lend; see
[oracle_demo](../oracle_demo) for issuing it. Here one wallet plays borrower, lender and
watcher. `run` asks for every param, so put them in the `--params` files; the liquidation
actions need a `fee_rate` of at least 0.15 sat/vB (see Limitations). After each broadcast,
wait for it to confirm and `sync` before the next.

```sh
W=wallet.json
TXM=tx-manifest-wallet
ORACLE=../oracle_demo/fake_oracle.py
cd examples/lending_v4
```

**1. A loan.** `CreateFactory` mints the factory. `CreateOffer` locks the collateral and
takes the loan terms, including the four new ones: `COLD_PUBKEY` (by default
oracle_demo's example cold key), `MAX_FUTURE_SECONDS`, `LIQUIDATION_LTV_BPS` and
`WINDOW_BLOCKS`. Pass it the factory's state file. `AcceptOffer` lends the principal.

```sh
$TXM run txmanifest.json CreateFactory --wallet $W --params factory.json
$TXM run txmanifest.json CreateOffer --wallet $W --params offer.json --state txmanifest.state.1.json
$TXM run txmanifest.json AcceptOffer --wallet $W --params fee.json \
  --instance txmanifest.instance.2.json --state txmanifest.state.2.json
```

**2. A crash, contested.** The lender starts a liquidation at $60,000. The price recovers,
and a watcher cancels it with a newer statement. `--claim` records the statement's price
and timestamp as the claim; `--merge` carries the claim into the cancel.

```sh
python3 $ORACLE certify --valid-from $(( $(date +%s) - 7200 )) --out cert.json
python3 $ORACLE sign --price 60000.00 --out crash.json
python3 $ORACLE statement-params crash.json --cert cert.json --claim --out start.json
$TXM run txmanifest.json StartLiquidation --wallet $W --params start.json \
  --instance txmanifest.instance.2.json --state txmanifest.state.3.json

python3 $ORACLE sign --price 84231.50 --out recovered.json
python3 $ORACLE statement-params recovered.json --cert cert.json --merge start.json --out cancel.json
$TXM run txmanifest.json CancelLiquidation --wallet $W --params cancel.json \
  --instance txmanifest.instance.2.json --state txmanifest.state.4.json
```

**3. A crash, uncontested.** Start again at a newer low price, wait out the window, and
finish. Finish takes the start's params file, for the claim.

```sh
python3 $ORACLE sign --price 59000.00 --out crash2.json
python3 $ORACLE statement-params crash2.json --cert cert.json --claim --out start2.json
$TXM run txmanifest.json StartLiquidation --wallet $W --params start2.json \
  --instance txmanifest.instance.2.json --state txmanifest.state.5.json

# Finish before 5 blocks have passed and the node refuses it: non-BIP68-final.
$TXM run txmanifest.json FinishLiquidation --wallet $W --params start2.json \
  --instance txmanifest.instance.2.json --state txmanifest.state.6.json
```

### A run on Liquid testnet

A loan of 1.5 tUSDT against 3,000 sat at 1%, a debt of 151,500,000 base units: liquidatable
below $63,125.00.

| Step | Transaction |
|------|-------------|
| `CreateFactory` | [`45dafde2…45f6`](https://liquid.network/testnet/tx/45dafde2fdd627a2251fdf61ba758bdc5d47e1e7047e1a637c07570dd9f745f6) |
| `CreateOffer` | [`7fa41183…52ed`](https://liquid.network/testnet/tx/7fa41183e28130a19eb64f18605211bebfd77bbe655337f712b909167fe352ed) |
| `AcceptOffer` | [`88ed904d…579f`](https://liquid.network/testnet/tx/88ed904ddca2a64f8a718ddb43ebd445f060c93ce2cf7409dd8df586a4a4579f) |
| `StartLiquidation` at 60000.00 | [`6ceb7f96…75e7`](https://liquid.network/testnet/tx/6ceb7f96e8f6f75f340aac7f2f82adf492f843885f390557534a121cf61f75e7) |
| `CancelLiquidation` at 84231.50 | [`74948e4f…29bb`](https://liquid.network/testnet/tx/74948e4f5f8fc15f1de44a1d2a7d9c0044ac923b1bf7b37e63552aedb72f29bb) |
| `StartLiquidation` at 59000.00 | [`8259dd1a…1b9d`](https://liquid.network/testnet/tx/8259dd1aaee8e81bfff44f19e21f43ae56e294269d1688acba4a69e440961b9d) |
| `FinishLiquidation`: lender NFT burned, 3,000 sat to the lender | [`73cd23e7…293f`](https://liquid.network/testnet/tx/73cd23e7399ab9b80c862fb9078a1273efbedf2ceb19d3158bf16d1bf481293f) |

## Limitations

- **A pending liquidation can be cancelled until it is finished**, not only during the
  window: a program can't require that a height has *not* been reached.
- **A cancelled liquidation can be started again with the same statement.** The active
  state doesn't remember the cancelling statement, so the lender can replay the old low
  price; each attempt can be cancelled again, at the cost of fees on both sides.
  Recording the cancelling statement's timestamp in the active state would close it.
- **Only BTC against a dollar asset with 8 decimals**, as above. Other pairs need a
  different valuation.
- **One statement per action.** No quorum of oracles, no bond, no reward for a canceller.
- **Fees.** The wallet's fee estimate assumes a smaller covenant witness than this
  program's, so at the minimum 0.1 sat/vB a liquidation is refused (`min relay fee not
  met`). Use 0.15.
- **The debt is fixed per instance**, as in lending_v3, so partial repayments aren't
  tracked into the liquidation state.

## Tests

`cargo test -p tx-manifest-lib --test lending_v4` runs the new paths on the Simplicity
interpreter: a start on either side of the threshold, without the lender NFT, at the wrong
claim or ahead of its lock time; a cancel with a newer good price, a still-low price or an
older statement; a finish before and after the window and without burning the NFT;
repayment while pending, and lending_v3's repayment still working only on an active loan;
and each path's execution budget.
