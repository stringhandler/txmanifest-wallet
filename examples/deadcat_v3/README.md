# deadcat_v3 — derivable blinding factors

Same protocol as [`examples/deadcat`](../deadcat/README.md); read that first for the state
model, the seven paths and the bootstrap flow. This file covers only the fork.

**This is the runnable one.** `deadcat` is the faithful port and cannot execute here;
[`deadcat_v2`](../deadcat_v2/README.md) tried unblinding the tokens and is a dead end.

## Why the tokens must stay blinded

`deadcat_v2` made the reissuance tokens explicit so the covenant could read them directly.
That cannot work, and the reason is in Elements' own consensus code
(`src/confidential_validation.cpp`, reissuance branch):

```cpp
secp256k1_generator_generate_blinded(ctx, &gen, assetTokenID.begin(),
                                     issuance.assetBlindingNonce.begin());
...
if (memcmp(asset.vchCommitment.data(), derived_generator, 33)) return false;
```

A reissuance rebuilds the spent token's asset tag from the blinding nonce and byte-compares
it against the input's asset field. An explicit asset is 33 bytes starting `0x01`; a
serialized generator starts `0x0a`/`0x0b`. The comparison can never succeed **for any nonce
value**, so an explicit reissuance token is unreissuable. Deadcat's design doc §13 —
"Reissuance tokens remain confidential per Elements protocol requirements" — is literal.

Note the corollary: `assetBlindingNonce` **is** the abf of the token UTXO being spent, the
same scalar the covenant takes as `*_REISSUANCE_INPUT_ABF`. One value, two consumers.

## What v3 changes

**The output factors are derived, not witnessed.** Each recreated token advances both
blinding factors by exactly one. Since the value is 1, that is a pure translation of the
commitments:

```
A_out = A_in + G          C_out = C_in + 2G
```

so `verify_output_is_shifted_token` checks the outputs by point arithmetic against the
inputs. The four `*_OUTPUT_ABF` / `*_OUTPUT_VBF` witnesses disappear — 19 witnesses become
15 — and two of the four `hash_to_curve` + scalar-mult pairs go with them.

The four **input** factors stay. They are what proves the spent UTXO is *this market's*
token and holds exactly 1 unit; without them anyone could pay a blinded UTXO of their own
asset to a covenant address and cycle it through the market's paths. Elements' own check
does not substitute: it only proves the input matches the entropy stated in the same
attacker-supplied witness.

**The factors become recoverable from the chain.** The Simplicity witness is public, so the
next spender reads `abf_in`/`vbf_in` off the previous spend and adds one. Nothing has to be
persisted — no state fields, no hooks. The first pair has no prior witness to read and is
the documented constant **`abf = vbf = 1`**, established by `CreateMarket`.

The cost is traceability: the factors are public, so anyone can open the commitments. That
is accepted here. The asset ids are compile params and the covenant addresses are public, so
blinding was never buying confidentiality — only reissuability.

**The fee moved to `num_outputs - 1`** on the issuance and resolve paths, and resolve no
longer demands exactly four outputs. This is what lets those actions declare an L-BTC change
output. It is also load-bearing for the rule above: with both token outputs' factors fixed,
the value-balance identity

```
a₀+v₀ + b₀+w₀ + F·f+g  ==  (a₀+1)+(v₀+1) + (b₀+1)+(w₀+1) + (C·c + z)
```

has no solution unless some output is free to absorb the residue `z`. Without the change
output the +1 rule is unsatisfiable.

Relaxing the output count is safe: outputs 0–2 stay pinned by index to asset, amount and
script, so the only value that can reach a trailing output is the spender's own fee input.
Upstream's `num_outputs == 4` only prevented a second UTXO landing at the state address *in
this transaction* — anyone can pay one there at any time regardless, so it bought little.

## Verify

```sh
cargo run -- validate examples/deadcat_v3/txmanifest.json
cargo run -p tx-manifest-lib --example deadcat_v3_recon
```

The recon compiles v3, derives all four addresses, and asserts each **differs** from the
matching `deadcat` address — if they ever collide the fork silently stopped being a fork —
then checks the four output witnesses are gone and the four input ones survive.

## Still needed before this runs

The engine has to blind covenant outputs, and `blind_last` cannot be told "use `abf_in + 1`
for output 0" — it picks abfs itself. That needs a hand-written blinding pass: choose the
abfs, blind all but one output, solve the last vbf. `pset_builder::apply_reissuance` also
still writes the placeholder nonce `[0…0, 1]`; it must write the real abf of the token UTXO,
which under this fork is a derivable constant rather than a stored secret.
