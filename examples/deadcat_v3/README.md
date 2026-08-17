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

## Witness declarations

Every covenant input names all fifteen witnesses the program declares — `validate` compares
the manifest's witness map against the `.simf` and errors on either half of a mismatch.
Three kinds of entry appear:

- **Real values** — `STATE`, `PATH`, and whatever the chosen path reads.
- **`BUDGET_PAD_A`–`D`** — declared with the explicit value `0`. `main()` does read them, and
  asserts A == B and C == D, so they are not "unused"; their *value* is simply irrelevant.
  They exist to pad the serialized witness so the execution budget
  (`witness_stack_bytes + 50 WU`) covers the program's cost, and a `u256` costs 256 bits
  whatever it holds.
- **`"unused"`** — the witnesses on branches this path never takes. `ORACLE_SIGNATURE` on an
  issuance, `TOKENS_BURNED` on a resolve. The engine supplies the zero the pruned branch
  wants, but the manifest still has to say so.

## Verify

```sh
cargo run -- validate examples/deadcat_v3/txmanifest.json
cargo run -p tx-manifest-lib --example deadcat_v3_recon
```

`validate` currently reports **five errors**, and they are the gap this fork has not closed
rather than a defect in the manifest: the primary input of `InitialIssuance`, `MintPairs`,
`ResolveYes`, `ResolveNo` and `CancelAll` runs a path that calls
`verify_input_reissuance_token`, so it genuinely reads `YES_/NO_REISSUANCE_INPUT_ABF/VBF` —
and no value for them exists yet. Marking them `"unused"` would validate green and then fail
on chain, which is the failure the check exists to prevent. They stay undeclared until the
blinding work below lands; the first pair is the documented constant `abf = vbf = 1`.

The recon compiles v3, derives all four addresses, and asserts each **differs** from the
matching `deadcat` address — if they ever collide the fork silently stopped being a fork —
then checks the four output witnesses are gone and the four input ones survive.

## Pinning the factors

`blind_last` cannot be told "use this abf for output 0" — it picks every factor itself. So
an output may now name its own, and the engine runs a hand-written blinding pass instead:

```json
"blinding": { "asset_bf": "1", "value_bf": "1" }
```

Either half may be given; either may be a decimal, a `0x` scalar, or a `params.X` /
`instance.X` reference. The pass blinds every pinned output with the stated factors and
solves the last *unpinned* `value_bf` so the transaction balances — which is why the rule
above matters in code and not just in the argument: pin every `value_bf` and the build
fails with that error rather than producing a transaction a node rejects.

`IssueReissuanceTokens` pins both tokens at the constant pair, so the chain now starts from
a value the next spender can reproduce. Its `lbtc_change` output is the one left free.

## Still needed before this runs

**Confidential covenant outputs.** `utxo_type.confidential` is still ignored — the builder
warns and pays explicit — so `CreateMarket` cannot yet park a *blinded* token at the state-0
address, and pinning factors on a covenant output is rejected rather than silently dropped.
That is the step that moves the constant to where the covenant actually reads it: the abf
`InitialIssuance` spends is the abf `CreateMarket` wrote, not the one the wallet held.

**The reissuance nonce.** `pset_builder::apply_reissuance` still writes the placeholder
`[0…0, 1]`. Under this fork that value happens to be right for the first reissuance — the
convention makes the first abf exactly 1 — but it must read the spent token's real abf, or
every later spend in the `+1` chain writes the wrong nonce.

**The four input witnesses.** `YES_/NO_REISSUANCE_INPUT_ABF/VBF` are the previous spend's
factors. `InitialIssuance` can state the constant once the two items above land; the later
paths need them read off the prior witness and incremented, which nothing does yet.
