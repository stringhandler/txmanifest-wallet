# 0002: Hooks are an optional capability

- **Status:** accepted
- **Date:** 2026-10-07

## Context

Hooks let a manifest set values while a transaction is being built: `on_resolved` on an
input (typically to record an asset id an issuance input just created), and
`on_pre_broadcast` / `on_post_broadcast` on an action.

Neither of the existing browser-extension wallets (humid, apogee) runs hooks. Both refuse
manifests that contain them. A wallet that doesn't implement hooks had no way to know in
advance that a manifest needs them; it found out by parsing the manifest or partway
through a run.

`requires` already exists for this kind of question: it lists what a wallet must support,
and a wallet without Simplicity refuses any manifest that requires `simplicity`.

## Decision

1. **`hooks` is a core capability**, alongside `simplicity`. A manifest that sets a value in
   any hook must declare `"requires": ["hooks"]`. A hook block with an empty `set` does
   nothing and needs nothing.
2. **It is inferred and checked like `simplicity`.** `validate` reports a manifest that uses
   hooks without declaring them, and a wallet that doesn't run hooks refuses a manifest
   that requires them, before doing anything else.
3. **`create_instance` is not a hook** and stays in the core format.
4. **The two lending examples keep their hooks** and declare `hooks`, so they show the
   capability in use. They are wire-compatible with the live simplicity-lending protocol,
   and rewriting them without hooks would need re-checking that on a test network.

## Consequences

- `tx-manifest-wallet` runs hooks on every network, so its targets always provide `hooks`.
  Another wallet reports what it supports with `capabilities --supports`, e.g.
  `--supports simplicity` for one that compiles Simplicity but runs no hooks; the lending
  examples then come back unsupported.
- A manifest that used hooks without declaring them now fails `validate`. It was already
  unrunnable by a wallet without hooks; now that's visible up front.
- Unlike `simplicity`, `hooks` is a property of the wallet, not of the chain or the node.
  The capability list is the residue the `chain` field can't settle, which includes
  optional parts of the format as well as soft forks.
