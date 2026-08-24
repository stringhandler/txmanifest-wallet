# tx-manifest

A declarative engine and wallet CLI for executing **transaction manifests** on
[Liquid](https://liquid.net/) / Elements — JSON files that describe a protocol's
UTXO types, actions, and lifecycle, backed by [SimplicityHL](https://github.com/BlockstreamResearch/SimplicityHL)
covenants.

You write a manifest (`txmanifest.json`) that declares *what* a transaction does —
its inputs, outputs, covenant scripts, compile-time parameters, and validations —
and the wallet figures out *how*: it resolves UTXOs, computes covenant addresses
and tapleaf hashes, builds and signs the PSET, dry-runs the Simplicity programs,
and broadcasts. No bespoke wallet code per protocol.

## Workspace layout

This is a Cargo workspace with two crates:

| Crate | Kind | Purpose |
|-------|------|---------|
| [`tx-manifest-core`](txmanifest_core) | library | Canonical form, registry id, the id-stability rules, and publisher signatures. Depends on nothing that executes a manifest — 55 crates, against 296 for the wallet — so a registry or an air-gapped signer can build it alone. |
| [`tx-manifest-lib`](txmanifest_lib) | library | The manifest model, lifecycle engine, covenant compilation/dry-run, parameter resolution, PSET building, and wallet primitives. |
| [`tx-manifest-wallet`](txmanifest_wallet) | binary | The `tx-manifest-wallet` CLI that drives the library interactively. |
| [`tx-manifest-sign`](txmanifest_sign) | binary | The `tx-manifest-sign` CLI: hash, sign and verify a manifest. Cannot build, sign or broadcast a transaction, and needs no network. |

```
manifest-wallet/
├── Cargo.toml              # workspace
├── txmanifest_core/        # publish-side crate — no wallet, no covenant runtime
│   └── src/
│       ├── canonical.rs    # canonical form + registry id (tagged SHA-256)
│       ├── checks.rs       # rules that keep an id unambiguous (integers, NFC)
│       ├── signature.rs    # the `signatures` block: sign, verify, attach
│       └── report.rs       # the finding vocabulary both crates share
├── txmanifest_lib/         # library crate
│   └── src/
│       ├── manifest.rs     # manifest schema (deserialized from txmanifest.json)
│       ├── lifecycle.rs    # interactive action execution engine
│       ├── covenant.rs     # SimplicityHL covenant compile / address / dry-run / finalize
│       ├── eval.rs         # expression evaluator (amounts, formulas, references)
│       ├── prepare.rs      # UTXO pre-funding / splitting
│       ├── pset_builder.rs # PSET construction
│       ├── validate.rs     # static manifest schema checks
│       ├── describe.rs     # interactive manifest explorer
│       ├── wallet.rs       # key management & signing
│       └── …               # config, context, params, instance, state, prompt
├── txmanifest_wallet/      # wallet CLI crate
├── txmanifest_sign/        # signing CLI crate
└── examples/               # sample manifests + .simf programs
    ├── p2pk/               # "hello world" — pay-to-public-key via Simplicity
    ├── lending/            # P2P collateralised lending protocol
    ├── dex/                # keyless atomic swap offers (Mosaik's Tessera covenant)
    ├── deadcat/            # binary prediction market with on-chain oracle resolution
    ├── deadcat_v2/         # …unblinded tokens — a documented dead end
    ├── deadcat_v3/         # …derivable blinding factors; the runnable fork
    └── last_will/          # time-locked inheritance
```

## How a manifest works

A manifest is a JSON document describing a protocol. The key sections:

- **`utxo_types`** — covenant output types, each referencing a `.simf` SimplicityHL
  program and its compile parameters.
- **`actions`** / **`classes`** — the operations a user can perform. Each declares
  `params`, `args`, `inputs`, `outputs`, `validations`, and lifecycle hooks.
- **`params`** — values baked into covenant programs at compile time. Derived params
  can be auto-computed (arithmetic expressions, tapleaf hashes, or — with the
  `simplicity_eval` feature — standalone function calls). A `utxo_type`'s
  `script.compile_params` then wires these onto the `.simf`'s own parameter names.

See [`examples/p2pk/txmanifest.json`](examples/p2pk/txmanifest.json) for a minimal
example, or [`examples/lending/txmanifest.json`](examples/lending/txmanifest.json)
for a full multi-action covenant protocol.

## Building

```sh
cargo build            # whole workspace
cargo test             # run the test suite
```

The `simplicityhl` dependency is a git reference. Covenant **dry-runs, address
derivation, and witness building** work against upstream
`BlockstreamResearch/SimplicityHL` (master). The standalone `compile_function` /
expression-eval code paths are gated behind a feature.

### The `simplicity_eval` feature

```sh
cargo build --features tx-manifest-wallet/simplicity_eval
```

This enables manifest features that depend on custom SimplicityHL APIs not yet in
master (`TemplateProgram::compile_function`, `CompiledFunction`, `eval_expression`) —
namely the `simf_fn` compute hook and `on_input_resolved` SimplicityHL hooks.

> ⚠️ **The default `simplicityhl` dependency points at upstream master, which does
> not have these APIs, so `--features simplicity_eval` will _not_ compile as-is.**
> To use it you must repoint the `simplicityhl` dependency in
> [`txmanifest_lib/Cargo.toml`](txmanifest_lib/Cargo.toml) at a branch that provides
> them (e.g. a fork that is a superset of master). With the feature off — the
> default — these specific hooks fail at runtime with a clear message and everything
> else works normally.

## Usage

The CLI is `tx-manifest-wallet`. During development, run it via `cargo run --`.

```sh
# Create a wallet (defaults to Liquid testnet)
cargo run -- create-wallet --out wallet.json

# Fund it, then check it
cargo run -- info --wallet wallet.json
cargo run -- sync --wallet wallet.json

# Inspect / validate a manifest
cargo run -- describe examples/p2pk/txmanifest.json
cargo run -- validate examples/p2pk/txmanifest.json

# The manifest's registry id — the hash a signature commits to
cargo run -- manifest-id examples/p2pk/txmanifest.json

# Ensure the wallet has the UTXOs an action needs (splits a funding tx if required)
cargo run -- prepare examples/p2pk/txmanifest.json Pay --wallet wallet.json

# Execute an action interactively
cargo run -- run examples/p2pk/txmanifest.json Pay --wallet wallet.json
```

### Publishing a manifest

A manifest is published under its **registry id**: a tagged SHA-256 of its canonical
form. The id ignores `$comment`, `$schema`, key order and whitespace, and covers
everything a signer reads — `ui.label`, `ui.role`, `ui_help`. Reindenting a file or
rewriting a developer note keeps the id, and any signature over it, intact.

```sh
# The id, and the exact bytes it is computed over. (`--canonical` is the preimage,
# not the digest: the id is a *tagged* hash, so plain sha256 of it will not match.)
cargo run -p tx-manifest-sign -- id examples/p2pk/txmanifest.json
cargo run -p tx-manifest-sign -- id examples/p2pk/txmanifest.json --canonical > preimage.json

# Sign it. The input is untouched; the signature lands in a new file.
cargo run -p tx-manifest-sign -- sign examples/p2pk/txmanifest.json --key publisher.key
#   → examples/p2pk/txmanifest.signed.json

# Air-gapped: print what to sign, then fold the result back in
cargo run -p tx-manifest-sign -- digest examples/p2pk/txmanifest.json
cargo run -p tx-manifest-sign -- attach examples/p2pk/txmanifest.json \
    --public-key <64 hex> --signature <128 hex>

# Ask the only question worth asking — did *this* key sign?
cargo run -p tx-manifest-sign -- verify examples/p2pk/txmanifest.signed.json \
    --require <64 hex>
```

**The signature does not make the manifest trustworthy.** It says the file is what the
holder of key K published; K itself comes with the file, so anyone can add their own
entry. Trust in K has to come from elsewhere — a registry, a pinned key. `verify` prints
keys rather than a verdict for that reason, and `--require` fails closed. A wallet that
renders "✓ Signed" from a key the file supplied has reintroduced the exact problem clear
signing exists to solve.

Signed files are **not** checked into this repo, and `.gitignore` keeps them out. A
signature is over the id, so any later edit leaves it behind — well-formed, verifying
nothing, and still reading as an endorsement to anything that does not check. `validate`
treats a stale signature as an error for the same reason.

### Commands

| Command | Description |
|---------|-------------|
| `run <manifest> <action>` | Walk through a manifest action interactively (resolve inputs → build → sign → broadcast). |
| `prepare <manifest> <action>` | Ensure the wallet holds the UTXOs the action needs; broadcasts a split tx if not. |
| `validate <manifest>` | Static schema/sanity checks on a manifest, plus the rules that keep its registry id unambiguous (integer-only numbers, NFC strings). |
| `describe <manifest>` | Interactively explore a manifest's classes and actions. |
| `manifest-id <manifest>` | Registry id: a tagged SHA-256 over the manifest's canonical form. `--canonical` prints the exact bytes hashed. |
| `create-wallet` | Generate a new wallet JSON file. |
| `info` | Show wallet fingerprint, xpub, oracle key, and a receive address. |
| `sync` | Sync wallet state against an Esplora server and show balance. |
| `get-balance` | Show last-synced balance (no network call). |
| `split` | Split a wallet asset into N equal UTXOs. |
| `config` | Show or update configuration (`default_network`, `default_esplora`). |

Run `cargo run -- <command> --help` for full flag details.

#### `tx-manifest-sign`

| Command | Description |
|---------|-------------|
| `id <manifest>` | Registry id; `--canonical` prints the exact preimage bytes. |
| `digest <manifest>` | The 32 bytes a publisher signs — `tagged("txmanifest/signature/v1", id)`, not the id itself. |
| `sign <manifest> --key <file>` | Sign and write `<name>.signed.json`. The key is read from a file, never an argument. |
| `attach <manifest> --public-key … --signature …` | Fold in a signature made elsewhere; refuses one that does not verify. |
| `verify <manifest> [--require <pubkey>]` | List the keys that signed. With `--require`, exit non-zero unless that key is among them. |

### Configuration

Config lives in a platform data directory and defaults to **Liquid testnet**
(`https://blockstream.info/liquidtestnet/api`). Switch networks with:

```sh
cargo run -- config default_network mainnet
```

## Notes

- This project was renamed from `compose` to `tx-manifest`. Manifest files are
  conventionally named `txmanifest.json` and carry a `manifest_version` naming the
  format version they are written against; the current format is `0.2.0`, and a
  file declaring anything else is refused at parse time.
- Targets Liquid/Elements. Covenant enforcement is fully on-chain via Simplicity —
  no trusted backend.

## Security & status

This is **experimental software** built on Simplicity, which is itself early-stage.
It has **not** been audited. The wallet manages private keys and signs transactions.

- Use it on **Liquid testnet** (the default) — do not use it with real funds.
- Never commit wallet files. `wallet*.json`, `*_wallet.json`, `oracle.json`, and
  `*.state.json` / `*.instance.json` are gitignored; keep your keys out of version
  control regardless.
- No warranty — see the license.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
