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
| [`tx-manifest-lib`](txmanifest_lib) | library | The manifest model, lifecycle engine, covenant compilation/dry-run, parameter resolution, PSET building, and wallet primitives. |
| [`tx-manifest-wallet`](txmanifest_wallet) | binary | The `tx-manifest-wallet` CLI that drives the library interactively. |

```
manifest-wallet/
├── Cargo.toml              # workspace
├── txmanifest_lib/         # library crate
│   └── src/
│       ├── manifest.rs     # manifest schema (deserialized from txmanifest.json)
│       ├── lifecycle.rs    # interactive action execution engine
│       ├── covenant.rs     # SimplicityHL covenant compile / address / dry-run / finalize
│       ├── eval.rs         # expression evaluator (amounts, formulas, references)
│       ├── prepare.rs      # UTXO pre-funding / splitting
│       ├── pset_builder.rs # PSET construction
│       ├── rangeproof.rs   # messages embedded in a confidential output's rangeproof
│       ├── nostr_embed.rs  # signing a nostr event for such a message
│       ├── validate.rs     # static manifest schema checks
│       ├── describe.rs     # interactive manifest explorer
│       ├── wallet.rs       # key management & signing
│       └── …               # config, context, params, instance, state, prompt
├── txmanifest_wallet/      # CLI crate
└── examples/               # sample manifests + .simf programs
    ├── p2pk/               # "hello world" — pay-to-public-key via Simplicity
    ├── lending/            # P2P collateralised lending protocol
    ├── dex/                # keyless atomic swap offers (Mosaik's Tessera covenant)
    ├── deadcat/            # binary prediction market with on-chain oracle resolution
    ├── deadcat_v2/         # …unblinded tokens — a documented dead end
    ├── deadcat_v3/         # …derivable blinding factors; the runnable fork
    ├── last_will/          # time-locked inheritance
    └── rangeproof_message/ # messages (and signed nostr events) inside rangeproofs
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

### Messages inside rangeproofs

Elements signs every confidential output's value rangeproof over an author-supplied
message, uses only the first 64 bytes of it (asset id ‖ asset blinding factor), and
discards the rest. Those spare bytes are recovered verbatim by a rewind, are readable
only by the holder of the output's blinding key, and — because `min_bits = 52` fixes
the ring count — cost nothing: **≈3125 bytes per output, at no change in transaction
size or fee.**

Any confidential output may carry one, via `rangeproof_embed`:

```jsonc
// plain text; params.X / instance.X references are resolved first
"rangeproof_embed": "hello from inside a rangeproof"
"rangeproof_embed": { "message": "params.note" }

// raw bytes, in the same dialect as an OP_RETURN `data` field
"rangeproof_embed": { "data": { "parts": [ { "type": "u64", "value": "params.seq" } ] } }

// a nostr event, signed at build time with a key this wallet derives
"rangeproof_embed": { "nostr": {
  "kind": 1,
  "content": "params.content",
  "tags": [["t", "liquid"]],
  "sign_with": "wallet"          // or "oracle", or a BIP32 path
} }
```

For the nostr form the engine fills in `pubkey`, `id` and `sig`, so what lands on chain
is a complete NIP-01 event a relay will accept. The manifest never carries a secret:
`sign_with` names a wallet key, and the resulting nostr identity is that key's x-only
pubkey — the one `info` prints. Signing at the authoring end is what makes a bridge that
republishes these events a transport rather than an authority.

Read them back with `read-messages` (wallet-owned outputs only — the blinding key is the
gate). The frame is byte-compatible with
[`liquidrangeproof`](https://github.com/stringhandler/liquidrangeproof) and the
`liquid-nostr-bridge` relay, so outputs written here can be read by those tools.

A message only exists on a *confidential* output. `validate` rejects one on a change,
OP_RETURN, burn, fee or `script_hash` destination, or on an output that sets
`"confidential": false`, rather than silently dropping it. See
[`examples/rangeproof_message/txmanifest.json`](examples/rangeproof_message/txmanifest.json).

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

# Ensure the wallet has the UTXOs an action needs (splits a funding tx if required)
cargo run -- prepare examples/p2pk/txmanifest.json Pay --wallet wallet.json

# Execute an action interactively
cargo run -- run examples/p2pk/txmanifest.json Pay --wallet wallet.json
```

### Commands

| Command | Description |
|---------|-------------|
| `run <manifest> <action>` | Walk through a manifest action interactively (resolve inputs → build → sign → broadcast). |
| `prepare <manifest> <action>` | Ensure the wallet holds the UTXOs the action needs; broadcasts a split tx if not. |
| `validate <manifest>` | Static schema/sanity checks on a manifest. |
| `describe <manifest>` | Interactively explore a manifest's classes and actions. |
| `create-wallet` | Generate a new wallet JSON file. |
| `info` | Show wallet fingerprint, xpub, oracle key, and a receive address. |
| `sync` | Sync wallet state against an Esplora server and show balance. |
| `get-balance` | Show last-synced balance (no network call). |
| `read-messages` | Read messages embedded in the rangeproofs of the wallet's confidential outputs. |
| `split` | Split a wallet asset into N equal UTXOs. |
| `config` | Show or update configuration (`default_network`, `default_esplora`). |

Run `cargo run -- <command> --help` for full flag details.

### Configuration

Config lives in a platform data directory and defaults to **Liquid testnet**
(`https://blockstream.info/liquidtestnet/api`). Switch networks with:

```sh
cargo run -- config default_network mainnet
```

## Notes

- This project was renamed from `compose` to `tx-manifest`. Manifest files are
  conventionally named `txmanifest.json`. The manifest version field is
  `manifest_version`, though the legacy `compose_version` key is still accepted as
  an alias so older files keep parsing.
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
