# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Both workspace crates —
`tx-manifest-lib` and `tx-manifest-wallet` — carry the same version and are
released together.

No changelog was kept before 0.2.0; for 0.1.x see the git history.

## [0.2.1] - 2026-09-09

A maintenance release. No format change: `manifest_version` stays `0.2.0` and
every 0.2.0 manifest reads the same way it did.

### Added

- **CI.** `cargo test --workspace --locked` now runs on Linux and Windows for
  every pull request and every push to `main`, with a `rustfmt` + `clippy` job
  beside it that reports but does not yet gate. `--locked` on purpose: the
  `simplicityhl` git dependency is pinned to an exact rev in the lock file, and
  a run that silently updated it would not be testing what a release builds.
- **Tests for the change/fee split.** The rule that an L-BTC surplus with no
  declared change output and no `allow_change` is an error — the rule that keeps
  an oversized input from being handed to a miner — shipped in 0.2.0 with no
  test of its own. It now has eight, covering the strict default, the
  one-satoshi case, both paths where change is permitted, and the two internal
  passes that deliberately do not enforce it. Nothing about the rule changed;
  what changed is that it can no longer be removed in silence.
- **`.gitattributes`**, so a Windows checkout keeps LF endings on the checked-in
  JSON, Rust and YAML. The schema test compares the file byte-for-byte against
  the string the Rust model emits, which is always LF, and a CRLF checkout
  failed on that alone. The test also normalizes line endings before comparing,
  so it no longer depends on the checkout's configuration.

### Changed

- The L-BTC change/fee decision moved out of `build_inner` into
  `resolve_lbtc_balance`, a pure function. Behaviour and error text are
  unchanged. Reaching the rule through `build_pset` needs a funded wallet, and
  this is the one calculation in the builder whose silent wrong answer is
  measured in the user's satoshis, so it is worth being able to test on its own.

## [0.2.0] - 2026-08-20

**Breaking:** a manifest that sets `utxo_type.confidential` no longer parses.
Confidentiality is now declared per output.

**Breaking:** `manifest_version` must now read `"0.2.0"`. The field carries the
version of the *format*, which moves separately from these crates, and the
change above is a breaking format change — so it moves too. Every example was
updated.

### Added

- **`manifest_version` is enforced.** It was parsed, printed by `describe`, and
  otherwise ignored, so a `0.1.0` file went on being read under `0.2.0` rules.
  It is now checked in `Manifest::from_json_str` — the one door every caller
  goes through, rather than in `validate`, which is a command a user may never
  run. The rule is semver with the qualification semver places on initial
  development: a differing major is incompatible, and while the major is `0` a
  differing minor is too, because `0.y` is where the breaking changes live. The
  patch is ignored.

  It has to be a hard error and not a warning. A stale manifest does not
  announce itself: `0.1.0` declared confidentiality per `utxo_type` and `0.2.0`
  declares it per output, so a `0.1.0` file that happens to use no removed field
  parses clean and then builds a transaction with the wrong outputs blinded.

- **Blinding factors can be declared.** An output or an input may carry a
  `blinding` block of `asset_bf` / `value_bf`. Each is a 32-byte scalar written
  as a decimal, a `0x` string, a `params.X` / `instance.X` reference, or
  arithmetic over one (`params.RT_FACTOR + 1`). On an output it pins what the
  builder would otherwise pick at random; on a covenant input it states the
  factors the spent UTXO was created with. Needed by any covenant that verifies
  its own UTXOs as Pedersen commitments, because Elements' `blind_last` chooses
  every factor itself.
- **Confidential covenant outputs.** `confidential: true` on a `utxo_type`
  destination blinds the output, using the wallet's change blinding key.
- **Confidential covenant inputs.** Their prevout is rebuilt from the asset,
  the amount and the declared factors — a taproot sighash and Simplicity's
  `inputUTXOsHash` both cover only a spent output's asset, value and
  scriptPubKey, so the reconstruction is exact and needs no network access.
- **`allow_change`** on an action: `none`, `lbtc_only` or `any`, bounding which
  surpluses may become a change output the manifest never declared.
- **A parameter interface for `utxo_type`**: `params` on the type and `args` at
  each site, which closes the type's scope so its address derivation reads only
  what it declares.
- **`script_hash` param compute**, deriving `sha256(scriptPubKey)` from an
  address so a covenant's committed hash and the address paid to cannot drift.
- **On-chain amounts.** A pinned outpoint reads its amount and asset from the
  chain, outranking anything the manifest or an operator supplies.
- **`simplicity_hl.unstable_features`** for opting into SimplicityHL `imports`
  and `enums`.

### Changed

- A reissuance now writes the spent token's asset blinding factor as its
  `issuance_blinding_nonce`, which is the value Elements rebuilds the token's
  generator from. Previously a constant placeholder.
- Pinning an output's `asset_bf` to the value an input of the same asset already
  carries is refused with an explanation. The surjection proof would have a zero
  shift to prove; secp reports only `CannotProveSurjection`.

### Removed

- **`utxo_type.confidential`** (breaking). It answered per address a question
  that is per output: one covenant address can hold a blinded reissuance token
  beside an explicit collateral UTXO. Use `confidential` on the output. Every
  example set it to `false`, and the builder only ever read it to warn.
