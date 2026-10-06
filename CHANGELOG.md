# Changelog

User-facing changes to the `tx-manifest-wallet` CLI and the manifest format.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/). No changelog was kept before 0.2.0.

## [Unreleased]

### Added

- Release binaries for macOS (Apple Silicon).

## [0.3.0] - 2026-10-06

### Breaking

- `manifest_version` must be `"0.3.0"`.
- A manifest with covenant `utxo_types` must declare `"requires": ["simplicity"]`.
- `chain` accepts only `elements`, `bitcoin`, `liquid` or `btc`; `cross-chain` is refused.

### Added

- Bitcoin support: `"chain": "bitcoin"` manifests run on Bitcoin mainnet, testnet, signet and regtest.
- Simplicity covenants on Bitcoin can be locked and spent — see `examples/bitcoin_covenant`.
- The Simplicity signet works out of the box via its public Esplora (`examples/bitcoin_covenant/config.json`).
- `requires` manifest field, including namespaced capabilities (`ns::name`).
- `capabilities` command: what a wallet needs to run a manifest; `--supports` makes it a CI check.
- Config keys: `bitcoin_backend` (`esplora`/`rpc`), `bitcoin_rpc_url`, `bitcoin_rpc_cookie`, `bitcoin_rpc_auth`, `simplicity_activated`, `extra_capabilities`, `bitcoin_checkpoint`.
- `--config <file>` flag and `TX_MANIFEST_DATA_DIR` environment variable.
- A `config.json` next to the wallet file is used automatically.
- Bitcoin runs show the transaction (outputs, fee, net effect) and ask before broadcasting.
- `contrib/regtest`: a Simplicity-enabled regtest node with `faucet.sh` and `mine.sh`.

### Changed

- The wallet's network decides the chain; a config or `--network` naming a different network is an error.
- A config file that fails to parse is an error rather than silently ignored.
- Failed builds and broadcasts exit non-zero.
- `sync`, `get-balance`, `info` and `config` handle Bitcoin wallets; `prepare` and `split` refuse them.
- Simplicity covenants are refused on Bitcoin mainnet, and elsewhere only run where the node or a checkpoint confirms Simplicity is active.
- RPC credentials are only sent to localhost or over https, and `bitcoin_rpc_cookie` must be a Bitcoin Core cookie file.
- `validate` checks `requires` against what a manifest uses, and its fields against its `chain`.

### Known issues

- `examples/deadcat` and `examples/deadcat_v2` fail `validate`.
- Bitcoin covenants whose programs need cost padding fail to spend.
- Bitcoin covenants using `check_lock_height` (absolute timelocks) cannot be spent.
- On Bitcoin, sizing an output with `fee` while change is allowed fails to build.

## [0.2.2] - 2026-09-09

- Re-tag of 0.2.1; no changes (the binaries report 0.2.1).

## [0.2.1] - 2026-09-09

- `validate` errors on an action with nowhere for an L-BTC surplus to go: no `"change"` output, `allow_change: "none"`, and no output sized with `fee`.

## [0.2.0] - 2026-08-20

### Breaking

- `manifest_version` must be `"0.2.0"`, and is now enforced when a manifest is loaded.
- `utxo_type.confidential` is removed; set `confidential` on each output instead.

### Added

- `blinding` (`asset_bf` / `value_bf`) on outputs and inputs, to pin or declare blinding factors.
- `confidential: true` on covenant outputs, and confidential covenant inputs.
- `allow_change` on actions: `none`, `lbtc_only` or `any`.
- `params` on `utxo_type` and `args` at each use site.
- `script_hash` param compute, deriving `sha256(scriptPubKey)` from an address.
- Pinned outpoints read their amount and asset from the chain.
- `simplicity_hl.unstable_features`, for SimplicityHL `imports` and `enums`.

### Changed

- A reissuance uses the spent token's asset blinding factor as its `issuance_blinding_nonce`.
- Pinning an output's `asset_bf` to the factor an input of the same asset already carries is refused.
