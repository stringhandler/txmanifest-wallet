# deadcat — binary prediction market

A port of [Deadcat.Live](https://github.com/Resolvr-io/deadcat)'s prediction-market
covenant to a transaction manifest. `prediction_market.simf` is a **verbatim** copy of
`src-tauri/crates/deadcat-sdk/contract/prediction_market.simf`; the upstream SDK drives it
from Rust (`src/pset/*.rs`), this manifest declares the same seven spending paths.

## What the protocol does

A market has two outcome tokens, YES and NO. Anyone may deposit collateral and mint
**matched pairs**: one YES and one NO per `2 × COLLATERAL_PER_TOKEN` satoshis. The pair
always costs what it can pay out, so the market is fully collateralised at all times and
needs no issuer — the covenant is the counterparty.

Settlement is where the design earns its keep. Rather than checking the oracle's signature
at redemption time, the oracle's outcome is **committed on-chain** as a state transition.
An oracle that signs both YES and NO cannot start a race to drain the pool: the first
attestation to confirm moves the market to a resolved state, and there is no path back or
sideways. The cost is serialisation — every spend touches the same collateral UTXO — which
upstream expects a batching swap service to absorb.

After a resolve, each winning token draws `2 × COLLATERAL_PER_TOKEN` (the whole pair's
backing, the loser's stake included), so the pool drains exactly. If the oracle never
attests, `EXPIRY_TIME` opens a symmetric escape hatch: both sides redeem at
`1 × COLLATERAL_PER_TOKEN` and everyone gets their deposit back.

## State lives in the address

There is no state variable. The market's state is a **tapdata leaf** in the covenant's tap
tree — 8 bytes, big-endian — branched with the Simplicity leaf and tweaked onto the NUMS
key. Four states, four addresses:

| State | Name | Holds |
|-------|------|-------|
| 0 | dormant | the two reissuance tokens, no collateral |
| 1 | unresolved | both reissuance tokens + one consolidated collateral UTXO |
| 2 | resolved-YES | same three UTXOs; YES redeems |
| 3 | resolved-NO | same three UTXOs; NO redeems |

`main()` takes the state as a witness and then proves it: it recomputes the address for the
claimed state and asserts the input is really being spent from there. Lying about the state
is not detected, it is impossible.

That is what the `extra_leaves` block on each `utxo_type` encodes:

```json
{ "type": "tapdata", "payload": [ { "value": "1", "type": "u64", "endian": "be" } ] }
```

`examples/deadcat` is verified against upstream by
[`txmanifest_lib/examples/deadcat_recon.rs`](../../txmanifest_lib/examples/deadcat_recon.rs):

```sh
cargo run -p tx-manifest-lib --example deadcat_recon
```

It compiles the covenant through the manifest's own `utxo_type` wiring, derives all four
addresses, and compares each against a transcription of deadcat-sdk's `taproot.rs`
(hand-rolled tagged hashes + `add_tweak`, an independent code path). It also parses every
witness literal this manifest writes against the compiled program's ABI — the seven `PATH`
branches are a nested `Either` tree written by hand, and a mis-nested `Left`/`Right` would
otherwise surface only as a failed spend.

## Actions

| Action | Path | Transition |
|--------|------|-----------|
| `IssueReissuanceTokens` | — (plain Elements tx) | mints the two reissuance tokens to your wallet, writes the instance |
| `CreateMarket` | — (plain Elements tx) | moves both tokens into state 0 |
| `PrepareInitialIssuance` | — (funding tx) | cuts an exactly-sized collateral UTXO |
| `InitialIssuance` | 1 | 0 → 1 |
| `MintPairs` | 2 | 1 → 1 |
| `ResolveYes` / `ResolveNo` | 3 | 1 → 2 / 1 → 3 |
| `RedeemYes` / `RedeemNo` | 4 | 2 → 2 / 3 → 3 |
| `RedeemExpired` | 5 | 1 → 1, at or after `EXPIRY_TIME` |
| `CancelPairs` | 6 (partial) | 1 → 1 |
| `CancelAll` | 6 (full) | 1 → 0 |

Path 7 has no action of its own: it is the witness every *secondary* covenant input carries
(`Right(Right(()))`). It proves only that the input comes from the same address as input 0
and delegates every transaction-level check to input 0's path — which is why the reissuance
tokens and the collateral can be spent together in one transaction.

### Why bootstrapping takes two transactions

There is a dependency cycle. `CreateMarket` pays its outputs to the state-0 covenant
address; that address is a function of all four asset ids; those ids are functions of the
outpoints being spent. The engine snapshots compile params *before* it resolves any input,
so one action cannot both mint an asset and pay it to an address derived from that asset.

`IssueReissuanceTokens` breaks the cycle by paying only to the wallet. It is also the
**constructor** — it writes the instance file — and that is not an arbitrary choice: the
asset ids exist only for the length of that run unless something records them. You cannot
recover them afterwards from what lands in the wallet, because the reissuance token id and
the outcome asset id are sibling hashes of the same entropy (`SHA256(entropy ‖ 0x00)` and
`SHA256(entropy ‖ 0x01)`) — holding one tells you nothing about the other. So
`create_instance` reads all four straight off the inputs that created them:

```json
"create_instance": { "fields": {
  "YES_TOKEN_ASSET":      "$inputs.yes_defining_in.issued_asset",
  "YES_REISSUANCE_TOKEN": "$inputs.yes_defining_in.reissuance_token"
}}
```

`CreateMarket` consequently takes **no params at all** — everything comes from the instance.

Two things about that spelling are worth knowing. `$inputs.<id>.<field>` is a *string*
lookup; a bare expression goes through the arithmetic evaluator, which returns a `u64` and
rejects a 32-byte id outright. And it is `issued_asset`, **not** `asset`: on an input
carrying an issuance those are different values — `asset` is the asset of the UTXO being
spent, which here is L-BTC. Writing `asset` would put L-BTC's id into `YES_TOKEN_ASSET`,
and nothing downstream would object, because it is a perfectly well-formed asset id.

Upstream Deadcat does both in one transaction (`pset/creation.rs`) because it computes the
ids in Rust before building anything. The two-transaction bootstrap costs one extra fee and
one extra confirmation and lands the market in exactly the same on-chain state; the covenant
cannot tell the difference, since it only ever sees the tokens sitting at the state-0
address.

### No YES or NO tokens exist until InitialIssuance

`IssueReissuanceTokens` mints `asset_amount_sat: 0` — zero units of the outcome assets, and
one unit each of their **reissuance tokens**. So after it confirms your wallet holds two
1-unit token UTXOs and nothing named YES or NO. That is correct, and it has to be: a token
minted in this transaction would be backed by no collateral, and after a resolve its holder
could redeem `2 × COLLATERAL_PER_TOKEN` out of collateral belonging to someone else. Supply
can only be created by a covenant-validated issuance, which is exactly what the reissuance
token — locked at a covenant address by `CreateMarket` — enforces.

### Everything else

`ResolveYes` / `ResolveNo` and `RedeemYes` / `RedeemNo` are pairs of actions rather than one
action with a runtime outcome, because the outcome *is* the destination: state 2 and state 3
are different addresses, and the engine has no conditional destination.

`RedeemYes` / `RedeemNo` / `RedeemExpired` / `CancelPairs` model the **partial** form
(collateral remains). Draining the pool to zero uses a different output layout — the burn
becomes output 0 and there is no collateral output — and would need its own action.
`CancelAll` is the one full-drain form that is modelled, because it is the only one that
also cycles the reissuance tokens back to dormant.

## Fee-output placement

The covenant checks the fee output at a **fixed index** on the issuance and resolve paths
(5 and 3), and at `num_outputs - 1` elsewhere. The engine appends declared outputs, then any
change, then the fee — so on those two paths the manifest declares **no change output**, and
the fee absorbs the L-BTC surplus. Practical consequence: size the collateral input exactly
(`prepare` will split one for you), because surplus on those paths is paid to miners rather
than returned.

`ResolveYes` / `ResolveNo` additionally have `num_outputs == 4` enforced, so a change output
there is not merely misplaced — it invalidates the spend.

## What is not executable yet

This manifest is a faithful, validated model of the protocol; it is **not** a working
Deadcat client today. Five things stand between the two, four of them engine gaps:

1. **Confidential reissuance tokens.** The covenant verifies the reissuance-token
   inputs and outputs as Pedersen commitments, taking the asset and value blinding factors
   as witnesses (`verify_token_commitment`). This requires those UTXOs to be *blinded*, and
   the engine builds every covenant output explicit — `pset_builder` warns and falls back
   when `confidential: true` is set. `unwrap_left` on an explicit asset commitment fails, so
   this is not a degradation, it is a hard stop for the issuance, resolve and full-cancel
   paths. It also means the eight `*_ABF` / `*_VBF` witnesses have no manifest spelling:
   they are per-UTXO secrets, and a witness `value` can only reference values the engine
   already holds.

   In practice it surfaces on `InitialIssuance` as `Execution reached a pruned branch`,
   with `no_reissuance_in` (path 7, script-hash comparison only) finalizing while
   `yes_reissuance_in` (path 1, commitment arithmetic) fails.

   **[`examples/deadcat_v2`](../deadcat_v2/README.md) is the same protocol with these
   tokens read explicitly**, and it runs. It is a fork — different CMR, different
   addresses, not Deadcat-compatible — which is why this unmodified port stays: it is what
   `deadcat_recon` checks against upstream.
2. **Reissuance from a confidential input.** Relatedly, `apply_reissuance` sets the
   issuance blinding nonce to a fixed marker (`[0…0, 1]`) rather than the input's real asset
   blinding factor, which is correct only for explicit reissuance-token UTXOs.
3. **Burn outputs must be zero-length scripts.** `ensure_output_is_op_return` compares
   against `sha256("")` — the hash of an *empty* scriptPubKey, which in Elements is the fee
   marker, not an `OP_RETURN`. The engine's `{"type": "burn"}` destination emits a one-byte
   `OP_RETURN` (`0x6a`), whose hash does not match. Every burn leg here is written as
   `{"type": "burn"}` and marked in its `description`; a zero-length-script burn destination
   would close the gap.
4. **Absolute nLockTime**, for `RedeemExpired` only. It calls
   `jet::check_lock_height(EXPIRY_TIME)` and the engine cannot set a transaction nLockTime —
   the same limitation the `dex` example's `Refund` hits, tracked in
   `meta/tasks/upnext/12-engine-absolute-locktime.md`. The *pre*-expiry paths are fine: they
   assert `lock_time < EXPIRY_TIME`, which the default locktime of 0 satisfies.
5. Nothing is hand-carried any more. The two issuance entropies used to be, because a
   reissuance cannot recover its entropy from anything on chain — the reissuance token UTXO
   holds no trace of the outpoint that created the asset. The constructor now captures them
   as instance fields, and each reissuance input names the one it needs:

   ```json
   "issuance": { "kind": "reissue", "asset_amount_sat": "params.PAIRS",
                 "entropy": "instance.YES_ISSUANCE_ENTROPY",
                 "issued_asset": "instance.YES_TOKEN_ASSET" }
   ```

   `issued_asset` is a check, not an input: the engine re-derives the asset id from the
   entropy and refuses to build if they disagree. Worth having, because an entropy is
   opaque — and the byte order a block explorer prints is the **reverse** of the one used
   here, so a value copied from one is well-formed, builds, broadcasts, and reissues the
   wrong asset.

Witness values *do* interpolate — `"value": "params.TOKENS_BURNED"` is substituted before
the SimplicityHL parser sees it — but they are parsed as raw literals with no type hint, so
`RedeemExpired`'s `BURN_TOKEN_ASSET` must be pasted `0x`-prefixed and byte-**reversed**
(internal order), unlike a `liquid.asset_id` compile param, which the engine reverses for
you. `ORACLE_SIGNATURE` likewise wants a `0x`-prefixed 64-byte value.

## Deadcat's other covenant

`maker_order.simf` — the limit-order book behind the app's trade tab — is deliberately not
modelled. It uses the **maker's own key** as the taproot internal key, while this engine
hardcodes the NUMS key (`covenant.rs::NUMS_KEY_BYTES`), so no address it derived would be
correct. Its `MAKER_RECEIVE_SPK_HASH` is also a per-order tweaked key
(`sha256("deadcat/order_uid" ‖ …)` → tweak → `P_order`), which no `compute` form expresses.

## Try it

```sh
cargo run -- validate examples/deadcat/txmanifest.json
cargo run -- describe examples/deadcat/txmanifest.json
cargo run -p tx-manifest-lib --example deadcat_recon

# Bootstrap, on a funded testnet wallet:
cargo run -- run examples/deadcat/txmanifest.json IssueReissuanceTokens --wallet wallet.json
cargo run -- run examples/deadcat/txmanifest.json CreateMarket --wallet wallet.json
```

The first run writes `txmanifest.instance.1.json` with all eight fields. Pass it to the
second with `--instance`; `CreateMarket` prompts for nothing.
