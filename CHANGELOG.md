# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Both workspace crates —
`tx-manifest-lib` and `tx-manifest-wallet` — carry the same version and are
released together.

No changelog was kept before 0.2.0; for 0.1.x see the git history.

## [Unreleased]

**Breaking:** `manifest_version` must now read `"0.3.0"`. The changes below make
a `0.2.0` file read wrongly rather than fail, so the version moves. Every
example was updated.

**Breaking:** a manifest with covenant `utxo_types` must now declare
`"requires": ["simplicity"]`, or `validate` fails.

**Breaking:** `chain` is now a closed vocabulary — `elements`, `bitcoin`, and
the aliases `liquid` and `btc`. It was a free-form string that nothing read;
`cross-chain` was previously accepted with a warning and is now refused.

### Added

- **`chain` module — the seam between this engine and the ledger it targets.**
  Everything here was written against Elements, where a great deal is assumed:
  outputs carry an asset id, amounts may be blinded, the fee is its own `TxOut`,
  taproot tags are domain-separated with `/elements`, and a Simplicity tapleaf
  will be executed. None of that holds on Bitcoin. The module sorts those
  assumptions by who settles them: `ChainFamily` properties follow from the
  ledger, `Capability` is what a manifest must state because the chain does not
  settle it, and `Activation` is what the specific node provides.

- **`requires`: the features a manifest needs that `chain` does not already
  imply.** Deliberately one core capability, `simplicity` — because it is the
  only one the chain does not answer. It is live on Elements and a proposed soft
  fork on Bitcoin (BINANA 2026-0003, leaf version `0xbe`, not activated on any
  public network), so whether a Bitcoin node honours it is a property of that
  node.

  `validate` checks it both ways: a covenant manifest omitting `simplicity` is
  an error, since `requires` is what a target gets checked against before a
  build; declaring what nothing uses is a warning only, because the inference
  reads field presence rather than semantics and must not block a run on its own
  guess.

  The empty list is the point of the field, not a degenerate case. A manifest
  that declares nothing needs nothing a stock node lacks — which is exactly the
  manifest that can target Bitcoin today.

- **Namespaced capabilities.** A bare name is defined by this format and comes
  from a closed set, so a typo is an error rather than a silently-ignored
  request. A name containing `::` (`custom::my-feature`, `mosaik::tessera`)
  belongs to whoever owns the namespace: this crate parses it, round-trips it
  verbatim, and judges it in neither direction — never inferred, never reported
  unused. A target satisfies one only by naming it in `Activation::extensions`.
  Core names normalize `_` to `-`; namespaced ones do not, since rewriting them
  would make two spellings this crate treats as equal and their owner may not.

- **`Manifest::chain_mismatches`** reports, per field, where a manifest uses
  something its chain lacks — an issuance input or a blinded output on Bitcoin.
  This replaced the `multi-asset` / `asset-issuance` / `confidential-amounts`
  capabilities: the check was worth keeping, but making an author *declare* them
  was not, because `chain: "bitcoin"` already says there are no native assets. A
  restatement is something that can disagree with itself. The rule now reads the
  chain directly, and reports the dot-path of each site rather than one verdict —
  an author porting a protocol needs the list, not the answer.

  An `asset` naming the policy asset outright (`"lbtc"`) is single-asset
  behaviour and stays clean on Bitcoin. That is how the portable examples here
  are written, and counting it as multi-asset marked `p2pk` and `last_will`
  unportable when they are the two that port most cleanly.

- **Esplora defaults follow the configured network** across both chains, rather
  than choosing between two Liquid URLs on `is_mainnet`. An explicit
  `default_esplora` still wins; pointing a Bitcoin wallet at a Liquid instance
  would otherwise surface as confusing decode failures rather than an obvious
  misconfiguration.

- **`bitcoin_backend` — Esplora chain access for Bitcoin.** Esplora serves
  Bitcoin and Liquid from the same REST shape, so only the base URL differs
  (`/api` vs `/liquid/api`) — but `lwk_wollet`'s client decodes Elements
  transactions, whose outputs carry asset ids and commitments no Bitcoin response
  has. Built on `ureq`, which this crate already used to POST transactions.

  Response decoding is split from fetching, as free functions over `&str`: the
  HTTP calls cannot be unit-tested, and the decoding is where the mistakes live —
  an amount read as a float, a txid byte order flipped, a missing field defaulted
  to zero. The fixtures include a response captured verbatim from
  `blockstream.info/signet/api`, so the decoder is checked against what Esplora
  actually sends rather than against a fixture written from the same assumptions
  as the code.

  Scanning ends on a gap of unused addresses measured by transaction *history*,
  not by the presence of UTXOs. The distinction is not hypothetical: the BIP86
  test mnemonic's first signet address has 153 transactions and an empty UTXO
  set, and a scan keyed on UTXOs would call it unused and stop early. Regtest has
  no default URL, so an operator configures one rather than being pointed at
  somebody else's chain.

- **`bitcoin_wallet` — BIP86 key derivation, addresses and signing** on
  `rust-bitcoin` directly rather than on a wallet framework. What this engine
  asks of a wallet is small: derive a key, produce an address, sign a hash, know
  which UTXOs are ours. Covenant inputs are self-describing and the descriptor is
  single-key, so a framework would mostly contribute a descriptor language,
  persistence model and coin-selection policy that none of this uses.

  Addresses are single-key P2TR with no script tree, checked against the vectors
  published in BIP86 rather than against this implementation's own output — a
  wrong derivation still produces valid-looking addresses the wallet will hand
  out and watch and then be unable to spend from, and nothing catches that except
  an external reference.

  Key-path and covenant signing are separate methods because they are not
  interchangeable: a key-path spend must be signed with the *tweaked* key the
  output commits to, while a Simplicity program checks against the *untweaked*
  key baked into it. Both directions are tested, including that each signature
  fails to verify against the other key. `Debug` is written by hand and redacts
  the root key, since `Xpriv`'s own `Debug` prints spendable material.

- **`psbt_builder` — Bitcoin transaction construction.** The counterpart to
  `pset_builder`, as a separate module rather than a generic one: the two chains
  share the shape of the job and almost none of its substance, and roughly two
  thirds of `pset_builder` is machinery for things Bitcoin does not have. What is
  genuinely common — the input/output vocabulary and the two-pass fee loop — is
  mirrored under the same names, including the guarantee that a declared output's
  index in the request is its index in the transaction.

  The difference that reaches furthest is that **the fee is not an output**.
  Elements places a fee `TxOut` and the transaction balances by construction;
  Bitcoin defines the fee as inputs minus outputs, so nothing writes it down. A
  slip that would produce a visibly wrong fee output on Elements produces a
  silently overpaid fee here, so the balance is asserted rather than assumed and
  `BuildPsbtResult::fee` reports what was actually left over. Change below the
  dust threshold folds into the fee, and the reported number says so.

  Also carries the Bitcoin **signing** path: BIP341 key-path sighashes,
  signatures stored as `tap_key_sig`, and a finalizer that turns each into a
  one-element witness. Only the inputs a caller names are touched, so a
  transaction mixing wallet and covenant inputs can be signed here and have its
  covenant inputs finalized by `covenant` without either clobbering the other.
  Computing a sighash requires *every* input's prevout — a taproot sighash
  commits to all spent outputs, so one missing `witness_utxo` would silently
  change every signature — and a missing one is refused rather than worked
  around.

  `from_pset_request` narrows the Elements request the lifecycle already
  assembles into a Bitcoin one. That assembly is ~800 lines of destination
  resolution, covenant address derivation and state metadata, almost none of it
  chain-specific, so there is one assembly path and the chains part company at
  the build boundary rather than in two copies that drift. The conversion is a
  narrowing, not a translation: assets, issuance, blinding and confidential
  outputs are **refused rather than dropped**. `validate` already rejects those
  on a Bitcoin manifest, so anything arriving here with them set got past a check
  that should have caught it, and silently ignoring it would turn a bug in that
  check into a transaction meaning something other than the manifest said.

  Not yet dispatched from `lifecycle` — that remains the last integration step.

- **`capabilities` command and `Manifest::supported_by` — the support check
  `requires` exists for.** A third-party wallet answers "do I handle this file"
  by passing what it implements and reading a verdict, instead of reimplementing
  this crate's inference over the manifest body:

  ```
  $ tx-manifest-wallet capabilities m.json                    # the contract
  chain    : elements
  requires : simplicity

  $ tx-manifest-wallet capabilities m.json --supports simplicity
  ✓ supported                                                 # exit 0

  $ tx-manifest-wallet capabilities m.json --supports "" --json
  { "supported": false, "missing": ["simplicity"], ... }      # exit 1
  ```

  `--supports` sets the exit code so it can gate CI. Without it the command
  reports the contract and stops, rather than answering a question about a
  wallet nobody named — exiting 0 there would read as a passing check. The chain
  is checked alongside the capabilities and reported differently, because the two
  mean different things to an implementor: a capability gap is closable by
  implementing something, a wrong chain is not.

  Scope worth stating: a `supported` verdict certifies the *ledger* requirements
  only. OP_RETURN outputs, relative timelocks and similar transaction shapes are
  not in the capability vocabulary, so an implementor still reads the manifest
  body for those.

- **The jet set is chosen from the chain, and `requires` is enforced at run time.**
  `CompileOpts` gained a `family`, so the SimplicityHL jet hinter follows the
  manifest's `chain` the way `debug_symbols` already did — it belongs there for
  the same reason, since a jet's CMR depends on its position in its jet set and
  therefore moves every covenant address. Verified against the Bitcoin-enabled
  forks: `p2pk.simf` compiles unchanged under both jet sets and yields two
  different CMRs, so a covenant address differs per chain for two independent
  reasons (jet CMRs and the taproot tag domain).

  This build still pins upstream SimplicityHL, which ships no `BitcoinJetHinter`,
  so a Bitcoin covenant is refused with an error naming the fork that works
  rather than being silently compiled against the Elements jet set — which would
  succeed for any program using only shared jets and produce an address on the
  wrong chain.

- **`config.json` gained `simplicity_activated` and `extra_capabilities`,** and
  `lifecycle::run` now refuses before deriving, signing or broadcasting anything
  if the target cannot provide what `requires` declares. `validate` cannot do
  this: it is offline, and Simplicity on Bitcoin is a property of the node rather
  than of the chain. Also refuses when the manifest's `chain` and the wallet's
  network disagree — caught at the gate, where the message can be about the
  mistake, rather than deep in address derivation, where it would be about
  taproot tags.

### Changed

- **Taproot tag domains are derived from the chain rather than hardcoded.**
  `build_tapbranch` took the `TapBranch/elements` tag as a constant; it now takes
  a `ChainFamily`, as do `dry_run_covenant` and `finalize_covenant_input`.
  `compute_covenant_address` derives it from the network it already receives, so
  no caller changed. This is the one change here that cannot fail loudly: the
  wrong tag yields a well-formed address that no script path can ever satisfy,
  so it is now pinned by a test that cross-checks the Elements branch against
  `rust-elements`' own tag.

- **The Simplicity leaf version comes from one constant for both chains.**
  `simplicity::leaf_version()` returns an `elements::taproot::LeafVersion`,
  which is the wrong type the moment a Bitcoin tree is built. The byte is the
  same either way (`0xbe`, matching `TAPROOT_LEAF_TAPSIMPLICITY` in the Bitcoin
  proposal), so it is now `chain::SIMPLICITY_LEAF_VERSION`.

- **The generated JSON Schema matches the parser exactly** for the two new
  types. The `schemars` derive emits only canonical spellings, which would make
  an editor flag `"chain": "liquid"` in files this engine reads happily —
  including every example here. `Capability`'s schema is an `anyOf` of the
  closed core list and a namespace pattern, since an `enum` cannot express a set
  that is closed at one end and open at the other.

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
