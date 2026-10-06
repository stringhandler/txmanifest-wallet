# tx-manifest

A wallet that runs **transaction manifests**: JSON files describing a protocol's
transactions — what each action spends, what it creates, and which
[SimplicityHL](https://github.com/BlockstreamResearch/SimplicityHL) covenants guard the
outputs. Write the manifest once; the wallet selects UTXOs, derives covenant addresses,
builds and signs the transaction, dry-runs the covenant programs, and broadcasts. No
protocol-specific wallet code.

Runs on **Liquid** (and other Elements networks) and **Bitcoin** (mainnet, testnet,
signet, regtest; covenants only where Simplicity is active).

> **Experimental and unaudited.** The wallet holds private keys and signs transactions.
> Use testnets. Do not use it with funds you care about.

## Install

Download a binary for your platform from the
[releases page](https://github.com/stringhandler/txmanifest-wallet/releases), or build
from source (Rust stable):

```sh
cargo install --locked --git https://github.com/stringhandler/txmanifest-wallet tx-manifest-wallet
```

## Quick start (Liquid testnet)

The default network is Liquid testnet, so this needs no configuration.

```sh
# 1. Create a wallet, then print a receive address
tx-manifest-wallet create-wallet --out wallet.json
tx-manifest-wallet info --wallet wallet.json

# 2. Fund that address from a Liquid testnet faucet (e.g. https://liquidtestnet.com/faucet),
#    then sync
tx-manifest-wallet sync --wallet wallet.json

# 3. Check a manifest, then run one of its actions
tx-manifest-wallet validate examples/p2pk/txmanifest.json
tx-manifest-wallet run examples/p2pk/txmanifest.json Pay --wallet wallet.json
```

`run` walks through the action: it prompts for any parameters you did not pass with
`--params`, picks inputs from the wallet, shows the transaction, and asks before
broadcasting. Pass `--export-pset out.json` to write the signed transaction instead of
sending it.

For Bitcoin, start with [`examples/bitcoin_pay`](examples/bitcoin_pay) (plain payments)
and [`examples/bitcoin_covenant`](examples/bitcoin_covenant) (a Simplicity covenant on the
Simplicity signet or a local regtest).

## Examples

[`examples/`](examples) has a list of every example, from a one-key covenant to a
lending protocol that interoperates with the reference implementation. Each one passes
`validate`.

## Writing a manifest

A manifest declares:

- **`chain`** and **`requires`** — the ledger it targets and what the wallet must
  support (e.g. `"simplicity"`).
- **`utxo_types`** — covenant output types, each pointing at a `.simf` program.
- **`actions`** — the operations a user performs, each with `params`, `inputs`,
  `outputs` and `validations`.

The full format is defined by the JSON Schema in
[`schema/txmanifest.schema.json`](schema/txmanifest.schema.json); point your editor at it
with `"$schema"` for completion and inline errors. `manifest_version` must be `"0.3.0"`.
[`examples/p2pk`](examples/p2pk/txmanifest.json) is the smallest complete manifest.

Check a manifest with `validate` (offline structure checks) and `capabilities` (what a
wallet needs to run it; `--supports` turns it into a CI check for other wallet
implementations).

## Commands

| Command | What it does |
|---------|--------------|
| `run <manifest> <action>` | Run an action: resolve inputs, build, sign, broadcast. |
| `validate <manifest>` | Check a manifest without touching the network. |
| `capabilities <manifest>` | Report what a wallet must support to run a manifest. |
| `describe <manifest>` | Browse a manifest's actions interactively. |
| `prepare <manifest> <action>` | Split wallet funds so an action has the UTXOs it needs (Liquid). |
| `create-wallet` | Create a wallet file. |
| `info` | Show the wallet's keys and a receive address. |
| `sync` | Fetch the wallet's UTXOs and show the balance. |
| `get-balance` | Show the last synced balance, offline. |
| `split` | Split one asset into N equal UTXOs (Liquid). |
| `config` | Show or change configuration. |

`tx-manifest-wallet <command> --help` lists every flag.

## Configuration

The config file is chosen in this order:

1. `--config <file>`
2. a `config.json` in the same directory as the wallet file
3. `config.json` in the data directory (the platform data directory, or
   `$TX_MANIFEST_DATA_DIR` if set)

`tx-manifest-wallet config` prints the active settings, and `config <key> <value>` changes
one. The wallet file records its network; a config naming a different one is an error
rather than a silent switch.

**Files `run` writes.** After a broadcast, `run` records the contract's on-chain state in a
numbered file next to the manifest (`txmanifest.state.1.json`, `.2`, …) and, for actions
that create a contract, an instance file. Pass the latest one back with `--state` /
`--instance` to continue the contract. Use `--state-out` / `--instance-out` to choose
where they go.

## Building from source

```sh
cargo build
cargo test
```

The `simplicityhl` dependency is a fork that adds Bitcoin support; see
[`txmanifest_lib/Cargo.toml`](txmanifest_lib/Cargo.toml).
[`contrib/regtest`](contrib/regtest) builds a local Bitcoin node with Simplicity active.
CI runs `cargo fmt --check` and `cargo clippy -- -D warnings`.

Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional terms or
conditions.
