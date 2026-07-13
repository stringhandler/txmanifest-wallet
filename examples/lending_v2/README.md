# lending_v2 — interoperable P2P lending

A transaction manifest for the **simplicity-lending** protocol
([BlockstreamResearch/simplicity-lending](https://github.com/BlockstreamResearch/simplicity-lending),
covenants from the `smplx-sdk` crate) that is **wire-compatible** with that
reference implementation.

Unlike the standalone [`../lending`](../lending) example — which models the same
covenants but makes its own choices about where funds and NFTs land — this `v2`
manifest reproduces simplicity-lending's **exact on-chain transaction layout**.
An offer created here produces byte-identical covenant addresses, OP_RETURN
discovery data, and output structure, so it can be listed by the reference
**indexer**, shown in the reference **web app**, and activated / settled by the
reference **CLI** — and vice-versa.

The `.simf` covenant sources here are identical to simplicity-lending's
(`crates/contracts/simf/*`); interop comes from matching how the transactions
around them are built.

## What makes it interoperable

Verified against `smplx-sdk` 0.0.3 / `simplicity-lang` 0.7.0:

| Concern | Match |
|---|---|
| Covenant taproot internal key | BIP341 NUMS `50929b74…803ac0` (both sides) |
| Simplicity leaf version | `0xbe`, leaf script = program **CMR** |
| **Debug symbols** | this manifest sets **`"compile_debug_symbols": true`** — `assert!`/`panic!` embed source info into `fail`-node commitments, so this flag changes the CMR. simplicity-lending/`smplx-sdk` compiles with debug **on**, so covenants must too. Compiling debug-**off** (the engine default) yields different covenant addresses and silently-unindexable offers. It's a per-manifest field (not hardcoded) because debug symbols are transitional and the reference may drop them later. |
| `*_script_hash` params & `output_script_hash` jet | plain `sha256(scriptPubKey)` |
| Asset IDs in covenant params / OP_RETURN | Elements-internal byte order (reverse of display hex) |
| Parameter NFT bit-packing | single `AMOUNTS_DECIMALS` (default **0**, lossless < 2²⁵) for both collateral & principal; decimals are read per-offer from the NFT, so any value interoperates |
| Borrower payout | explicit v0 **P2WPKH** wallet address; `sha256(spk)` committed as `PRINCIPAL_OUTPUT_SCRIPT_HASH` **and** `BORROWER_NFT_OUTPUT_SCRIPT_HASH` |
| Creation OP_RETURN | `borrower_pubkey (32) ‖ principal_asset_id (32, internal)` = 64 bytes |
| NFT ordering | first-params, second-params, borrower, lender |

### Differences from the standalone `lending` example

- **No `p2pk.simf`, no claim step.** The principal is paid straight to the
  borrower's ordinary wallet address. There is no separate `ClaimLoanFunds`.
- **Borrower NFT lives in the borrower's wallet** during the active loan (paid to
  the same wallet address on activation), and is spent on `RepayLoan` with an
  ordinary signature — not parked in a ScriptAuth covenant.
- **The borrower payout script hash is committed into the covenant.** This is the
  `borrower_output_script_hash` simplicity-lending bakes via
  `hash_script(signer.get_address().script_pubkey())`.

## Engine support this example relies on

Four additions to `tx-manifest-lib` back this manifest:

1. **`wallet_script_hash` / `wallet_address` param sources.** A constructor param
   with `"source": {"type": "wallet_script_hash"}` resolves to
   `sha256(explicit index-0 P2WPKH scriptPubKey)`; `wallet_address` resolves to
   the matching explicit address string. (See `wallet::committed_output`.)
2. **OP_RETURN `data` payloads.** An `op_return` output may carry
   `"data": "concat(ref, …)"`; asset-id references are byte-reversed to internal
   order. Data-less `OP_RETURN` (used for NFT burns) is still the default.
3. **`from_address` input pin.** A wallet input may carry
   `"from_address": "<ref>"` to constrain coin selection to UTXOs whose
   scriptPubKey equals that address's. This guarantees `LockCollateral`'s
   collateral input is spent from the committed borrower address — the exact thing
   the indexer reconstructs `borrower_output_script_hash` from.
4. **`compile_debug_symbols` manifest field.** A top-level manifest flag threaded
   into every covenant compilation, so a manifest can match the debug-symbol setting
   of the protocol it targets without hardcoding it in the engine (default `false`).

## Lifecycle

```
IssueUtilityNFTs ──▶ LockCollateral ──▶ SetupLending ──▶ RepayLoan ──▶ ClaimPrincipalWithInterest
   (nfts_issued)      (offer_open)       (loan_active)     (repaid)         (settled)
                          │                   │
                          │ CancelOffer       │ LiquidateAfterExpiry
                          ▼                   ▼
                      (cancelled)         (liquidated)
```

## Usage

```sh
# 1. Wallet + funds (Liquid testnet). Fund the wallet's index-0 receive address —
#    collateral must be spent from it so a third-party lender can reconstruct the offer.
cargo run -- create-wallet --out wallet.json
cargo run -- info    --wallet wallet.json     # send L-BTC + your principal asset to the receive address
cargo run -- sync    --wallet wallet.json

# 2. Issue the four utility NFTs (constructor — writes lending_v2.instance.json).
#    Also stages a dedicated COLLATERAL_AMOUNT UTXO at the borrower's committed
#    address, so the wallet needs a collateral-asset UTXO >= COLLATERAL_AMOUNT here.
cargo run -- prepare examples/lending_v2/txmanifest.json Prepare --wallet wallet.json
cargo run -- run examples/lending_v2/txmanifest.json IssueUtilityNFTs \
    --wallet wallet.json --params params.json

# 3. Open the offer on-chain
cargo run -- run examples/lending_v2/txmanifest.json LockCollateral \
    --wallet wallet.json --instance lending_v2.instance.json

# 4. A lender activates (this wallet, or the simplicity-lending CLI on the same offer)
cargo run -- run examples/lending_v2/txmanifest.json SetupLending \
    --wallet wallet.json --instance lending_v2.instance.json --state lending_v2.state.json

# 5a. Borrower repays and reclaims collateral …
cargo run -- run examples/lending_v2/txmanifest.json RepayLoan \
    --wallet wallet.json --instance lending_v2.instance.json --state lending_v2.state.json
#     … then the lender withdraws principal + interest
cargo run -- run examples/lending_v2/txmanifest.json ClaimPrincipalWithInterest \
    --wallet wallet.json --instance lending_v2.instance.json --state lending_v2.state.json

# 5b. …or, after expiry, the lender liquidates (see caveat below)
cargo run -- run examples/lending_v2/txmanifest.json LiquidateAfterExpiry \
    --wallet wallet.json --instance lending_v2.instance.json --state lending_v2.state.json
```

`params.json` (amounts must be exact multiples of `10^AMOUNTS_DECIMALS`):

```json
{
  "AMOUNTS_DECIMALS": "1",
  "COLLATERAL_ASSET_ID": "<collateral asset id, display hex>",
  "COLLATERAL_AMOUNT": "1000",
  "PRINCIPAL_ASSET_ID": "<principal asset id, display hex>",
  "PRINCIPAL_AMOUNT": "5000",
  "PRINCIPAL_INTEREST_RATE": "500",
  "LOAN_EXPIRATION_TIME": "2375600"
}
```

`BORROWER_PUB_KEY`, `BORROWER_ADDRESS`, and `BORROWER_OUTPUT_SCRIPT_HASH` are
filled from the wallet automatically — do not put them in `params.json`.

## Interop notes & caveats

- **Collateral placement is handled automatically.** The indexer (and
  simplicity-lending's `create-lending`) recover the borrower payout script from
  the collateral input's previous output, so the collateral **must** be spent from
  the exact address whose hash the covenant commits to. To guarantee this without
  manual UTXO juggling: `IssueUtilityNFTs` mints a dedicated, exact-`COLLATERAL_AMOUNT`
  collateral UTXO at `BORROWER_ADDRESS` (output `collateral_at_borrower`), and
  `LockCollateral` pins its collateral input to that address (`from_address`). So
  the borrower only needs a collateral-asset UTXO of at least `COLLATERAL_AMOUNT` in
  the wallet when running `IssueUtilityNFTs`; the manifest places it correctly from
  there. **If an offer isn't showing up in the indexer, the first thing to check is
  that `LockCollateral`'s input 0 was spent from `BORROWER_ADDRESS`** — a mismatch
  here makes the reconstructed pre_lock covenant differ from `output[0]`, and the
  indexer silently skips the transaction.
- **Explicit (unblinded) outputs.** The principal and borrower-NFT outputs are
  non-confidential because the covenant introspects their asset and amount. The
  wallet tracks them via its explicit-UTXO set.
- **Amounts must round-trip through the Parameter NFTs.** The collateral and
  principal amounts are bit-packed as `amount / 10^AMOUNTS_DECIMALS`. The covenant
  bakes in the *full* amount but decodes it back from the NFT, so the packed value
  must reconstruct exactly — i.e. each amount must be an exact multiple of
  `10^AMOUNTS_DECIMALS`, and `amount / 10^AMOUNTS_DECIMALS` must be < 2²⁵
  (33,554,432). **`AMOUNTS_DECIMALS` defaults to 0**, which is lossless for any
  amount below 33,554,432 — use that unless you need larger amounts. If you raise
  it, a non-divisible amount (e.g. `3452` with `AMOUNTS_DECIMALS=1` → stored as
  `345`, decoded as `3450`) is **silently truncated**: the covenant compiled with
  `3452` no longer matches the NFT's `3450`, so the offer is **neither indexable
  nor spendable**. This is the #1 cause of an offer that broadcasts fine but never
  appears on the indexer.
- **Parameter bounds.** `LOAN_EXPIRATION_TIME` < 2²⁷, interest rate ≤ 65535 bps.
- **`LiquidateAfterExpiry` needs transaction `nLockTime`.** The covenant's
  `check_lock_height` requires the spending tx's `nLockTime ≥ LOAN_EXPIRATION_TIME`.
  `tx-manifest-lib` does not yet set an absolute transaction locktime, so this
  path is not fully executable from this wallet today (it is a pre-existing engine
  limitation, shared with the standalone `lending` example). Repayment, the
  cooperative happy path, is unaffected.
