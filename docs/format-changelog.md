# Manifest format changelog

Changes to the txmanifest **format**: the fields a `txmanifest.json` may contain, what they
mean, and the rules a valid manifest follows. This is for manifest authors and for
anyone implementing the format in a wallet. Changes to the `tx-manifest-wallet` CLI are in
the [app changelog](../CHANGELOG.md).

A manifest declares the format it's written against in `manifest_version`. While the major
version is `0`, a different minor version is a different, incompatible format. A patch
version only adds things, so a newer reader accepts an older patch's manifests (a `0.3.1`
reader reads `0.3.0`). Not the reverse: an older reader rejects fields it doesn't know,
rather than ignoring them. The format's
history before `0.2.0` was not recorded.

The JSON Schema for the current version is
[`schema/txmanifest.schema.json`](../schema/txmanifest.schema.json).

## [0.3.1] - unreleased

Additive, with two tightened rules (below): a `0.3.0` manifest is a valid `0.3.1` manifest
unless it uses a Simplicity program without declaring `simplicity`, or a hook without
declaring `hooks`.

### Added

- **Program pinning** ([decision 0001](decisions/0001-program-pinning.md)). A manifest can
  pin each Simplicity program by a content hash and a compiler-version requirement, so its
  manifest id covers the programs it runs:
  - `source_hash` beside a `utxo_types` script's `source`, and `simf_hash` beside a
    `tapleaf` / `simf_fn` compute's `simf`. Hashes are self-describing,
    `"sha256:<lowercase hex>"`, over the file's exact bytes.
  - A top-level `programs` table of `{ source, hash, simplicity_hl_version, description }`.
    A script or compute names an entry with `"program": "<name>"` instead of giving
    `source` / `simf`.
  - `simplicity_hl_version` on a reference or a `programs` entry, and
    `simplicity_hl.version` for the whole manifest: semver requirements in the syntax of
    SimplicityHL's `simc` directive (`"0.7.1"` means `^0.7.1`). Priority: the reference or
    entry, then the manifest-wide value, then the file's own `simc` directive. The manifest
    can narrow the directive but not widen it.
- **`hooks` capability** ([decision 0002](decisions/0002-hooks-capability.md)): hooks
  (`on_resolved`, `on_pre_broadcast`, `on_post_broadcast`) are an optional part of the
  format. A wallet may not implement them, and refuses manifests that require them.
- **Pinned and unpinned manifests.** A program is pinned when it has a hash and a
  compiler-version requirement; a manifest is pinned when all its programs are. Wallets
  must refuse unpinned manifests and programs that don't match their hash. Tools may
  accept them for development.

### Rules

- A `tapleaf` / `simf_fn` compute gives exactly one of `simf` and `program`; a
  `utxo_types` script gives at most one of `source` and `program`.
- Every reference to one file must agree on its hash and compiler requirement. A
  reference that gives neither inherits them from the others.
- A `program` must name an entry in `programs`.

### Changed

- `"requires": ["simplicity"]` is required by any use of a Simplicity program, not only by
  covenant `utxo_types`: also a `tapleaf` or `simf_fn` compute, or a `programs` entry.
  Each of these needs a compiler, and `requires` is how a wallet without one knows to
  refuse the manifest before trying it. A manifest that relied on the narrower rule was
  already unrunnable by such a wallet; it now fails validation instead.
- A manifest that sets a value in any hook must declare `"requires": ["hooks"]`. A hook
  block with an empty `set` needs nothing.

## [0.3.0] - 2026-10-06

### Breaking

- `manifest_version` must be `"0.3.0"`.
- A manifest with covenant `utxo_types` must declare `"requires": ["simplicity"]`.
- `chain` accepts only `elements`, `bitcoin`, `liquid` or `btc`; `cross-chain` is refused.

### Added

- `"chain": "bitcoin"` (or `"btc"`): manifests for Bitcoin mainnet, testnet, signet and
  regtest. Fields that only make sense on Elements (non-policy assets, issuance, blinded
  outputs) are invalid on a Bitcoin manifest.
- `requires`: the capabilities a wallet must support to run the manifest, including
  namespaced capabilities (`ns::name`) defined by third parties.

## [0.2.0] - 2026-08-20

### Breaking

- `manifest_version` must be `"0.2.0"`, and readers enforce it.
- `utxo_type.confidential` is removed; set `confidential` on each output instead.

### Added

- `blinding` (`asset_bf` / `value_bf`) on outputs and inputs, to pin or declare blinding
  factors.
- `confidential: true` on covenant outputs, and confidential covenant inputs.
- `allow_change` on actions: `none`, `lbtc_only` or `any`.
- `params` on `utxo_type`, and `args` at each place it's used.
- `script_hash` param compute: `sha256(scriptPubKey)` of an address.
- `simplicity_hl.unstable_features`, for SimplicityHL `imports` and `enums`.

### Changed

- A reissuance uses the spent token's asset blinding factor as its
  `issuance_blinding_nonce`.
- Pinning an output's `asset_bf` to the factor an input of the same asset already carries
  is invalid.
