# deadcat_v2 — explicit reissuance tokens

> **Superseded — this fork does not work.** Elements' reissuance branch rebuilds the spent
> token's asset tag from the blinding nonce and byte-compares it against the input's asset
> *commitment* (`confidential_validation.cpp`). An explicit asset starts `0x01`, a generator
> starts `0x0a`/`0x0b`, so no nonce can ever make an explicit reissuance token validate.
> Unblinding the tokens is therefore impossible, not merely inadvisable, and Deadcat's
> design doc §13 was literal. See [`deadcat_v3`](../deadcat_v3/README.md) for the fork that
> works. Kept as the record of what was tried and why it failed.

Same protocol as [`examples/deadcat`](../deadcat/README.md), one forked covenant. Read that
README first — the state model, the seven spending paths, the fee-index rules and the
bootstrap flow are all identical and are documented there. This file only covers the delta.

## What changed and why

`examples/deadcat` is a faithful port, and it cannot be executed. Its issuance, resolve and
full-cancel paths verify the two reissuance tokens as **Pedersen commitments**:

```rust
let asset_commitment: (u1, u256) = unwrap_left::<u256>(unwrap(jet::input_asset(index)));
```

`unwrap_left` demands a *confidential* asset commitment, so the token UTXOs must be blinded.
The engine emits every covenant output explicit (an output asking for `confidential: true`
at a `utxo_type` destination is rejected), so the Right branch is taken, and since that
branch was pruned during witness satisfaction you get:

```
Execution reached a pruned branch: 744339c859e7ff6f8d33f9afa73734e1c908684feedc8c4d0a6112d3bf361317
```

The symptom is diagnostic: on `InitialIssuance`, `no_reissuance_in` finalizes fine — it runs
path 7, which only compares script hashes — while `yes_reissuance_in` fails, because path 1
is the one doing commitment arithmetic.

v2 reads those tokens explicitly instead:

```rust
fn verify_input_reissuance_token(index: u32, expected_token: u256) {
    ensure_input_asset_with_amount_eq(index, expected_token, reissuance_token_amount());
}
```

**The amount check is not weakened.** Upstream's value-commitment step computes
`asset_gen + vbf*G`, which is a Pedersen commitment to value exactly 1 — so `eq_64(amount, 1)`
asserts precisely the same fact, in the clear.

Everything else is untouched: same states, same paths, same amounts, same output layouts,
same `BUDGET_PAD_*` witnesses.

## Consequences

- **All four covenant addresses move.** Dropping `hash_to_curve`, `generate`, `gej_ge_add`,
  `gej_normalize` and `fe_square_root` changes the CMR. A v2 market is not interoperable
  with a Deadcat market, and tokens parked at a v1 address cannot be spent by this program.
  If you were mid-bootstrap on `examples/deadcat`, start again here — those UTXOs are
  stranded.
- **The witness surface shrinks from 19 to 11.** The eight `*_ABF` / `*_VBF` witnesses are
  gone, which also removes the one thing in this protocol that a manifest had no way to
  express: per-UTXO blinding secrets.
- **Privacy is unchanged in practice.** The reissuance tokens are 1-unit capability markers
  sitting at a covenant address whose script is public; blinding them hid nothing an
  observer could not infer from the address.

Both properties are pinned by
[`txmanifest_lib/examples/deadcat_v2_recon.rs`](../../txmanifest_lib/examples/deadcat_v2_recon.rs):

```sh
cargo run -p tx-manifest-lib --example deadcat_v2_recon   # v2 forked: addresses moved, witnesses dropped
cargo run -p tx-manifest-lib --example deadcat_recon      # v1 faithful: addresses match upstream
```

The first asserts every v2 address *differs* from the matching v1 address — if they ever
collide, the fork silently stopped being a fork. The second still proves `examples/deadcat`
reproduces upstream Deadcat byte-for-byte, which is why the unmodified port is kept.

## The open question

This fork is also the cheap experiment for the thing that actually blocks v1: **will Elements
accept a reissuance whose reissuance-token input is explicit?**

A reissuance needs a non-null `assetBlindingNonce` — null means "new issuance" — and the true
asset blinding factor of an explicit UTXO is zero. `pset_builder::apply_reissuance` therefore
fakes it with the minimal non-zero scalar `[0…0, 1]`. Consensus is expected to check only
null-vs-non-null and then match the input's asset against the entropy-derived token id, which
works fine in the clear. But no example in this repo has ever broadcast a reissuance, so that
path is untested, and reasoning will not settle it.

If v2's `InitialIssuance` confirms on testnet, explicit reissuance works and the engine never
needs confidential covenant outputs for this protocol. If it is rejected, Deadcat's blinded
design is forced and the engine gap is the only way through.

## Try it

```sh
cargo run -- validate examples/deadcat_v2/txmanifest.json
cargo run -p tx-manifest-lib --example deadcat_v2_recon

# Bootstrap from scratch — v1 instance/state files do not carry over.
cargo run -- run examples/deadcat_v2/txmanifest.json IssueReissuanceTokens --wallet wallet.json
cargo run -- run examples/deadcat_v2/txmanifest.json CreateMarket --wallet wallet.json
cargo run -- run examples/deadcat_v2/txmanifest.json InitialIssuance --wallet wallet.json
```
