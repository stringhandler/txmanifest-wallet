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

- **A Bitcoin transaction built by this engine is confirmed on chain.** Against
  the `contrib/regtest` node: a `chain: "bitcoin"`, `requires: []` manifest
  resolved its input from a UTXO-set scan, built a PSBT, signed a key-path spend,
  and the node accepted it — `testmempoolaccept` `allowed: true`, then one
  confirmation with 150,000 sat at the declared destination, change to the
  wallet, a single 64-byte witness item, and 308 sat over 154 vbytes: exactly the
  2 sat/vB asked for.

  Getting there surfaced four things no unit test could:

  - **The backend selection was never wired.** `BitcoinRun` built an
    `EsploraClient` directly, so `bitcoin_backend: "rpc"` was read, validated and
    ignored. Every Bitcoin run used Esplora regardless.
  - **`default_network` could not be set to any Bitcoin network.** The CLI setter
    checked against a two-item list written before Bitcoin support existed, so
    regtest could only be configured by editing the file by hand. It now
    validates by parsing.
  - **`config` showed Elements fields for a Bitcoin config** — an Esplora URL a
    Bitcoin run never consults, beside a network that cannot use it. It now shows
    the backend the configured chain actually uses, with the RPC password
    redacted.
  - **Regtest's Esplora fallback pointed at a public signet.** It now points at
    localhost, which fails to connect — the right failure. The old default would
    have quietly answered questions about somebody else's chain, and did exactly
    that until the run caught it.

- **`TX_MANIFEST_DATA_DIR` relocates the wallet's on-disk state**, config
  included. The config lived at a fixed global path that `config::load` resolved
  with no argument, so pointing the wallet at a regtest meant overwriting the
  config a user's real funds are reached through — which made the thing
  untestable by anyone who also used it.

- **`bitcoin_rpc` — chain access over a node's own JSON-RPC,** selectable with
  `bitcoin_backend: "rpc"`. Esplora is right against a public network, where
  somebody else runs the indexer; it is the wrong tool against a regtest you just
  started, where it means an electrs and an API server to index four blocks.
  `scantxoutset` finds our coins from descriptors with no wallet, no import and
  no rescan, and `generatetoaddress` funds a regtest wallet without a faucet.

  Amounts are converted from Bitcoin Core's decimal BTC **textually**, never
  through `f64`. A BTC amount is a decimal fraction with eight places, which
  binary floating point cannot hold exactly; `0.1` BTC via a float lands just
  under 10,000,000 and truncates to 9,999,999, and an amount one satoshi off
  invalidates every signature committing to it.

  The two backends differ in what bounds a scan, which is worth knowing: Esplora
  reads address *history* and finds coins beyond a gap of spent addresses, while
  a UTXO-set scan has no history, so the gap limit becomes the hard edge of how
  far it looks.

- **`contrib/regtest` — a Simplicity-enabled regtest.** A container built from
  `delta1/bitcoin@simplicity-inquisition`. `SIMPLICITY` is active from height 0,
  alongside `OP_CAT`, `CHECKTEMPLATEVERIFY`, `CHECKSIGFROMSTACK` and
  `ANYPREVOUT`. It appears as an enabled **script flag**, not as a BIP9
  deployment — so `deployment_active` checks `getdeploymentinfo`'s `script_flags`
  as well as its `deployments`, since looking only at the latter reports an
  active rule as inactive and would refuse a covenant run that would have worked.

- **Fixed: a Bitcoin run could have sent money to the wrong place.** Manifest
  addresses were parsed as `elements::Address` at both sites that read one, and
  that parser rejects every Bitcoin address. Neither site treated the failure as
  fatal: the output loop dropped the output and built the transaction *without
  it* — the declared payment missing, its value falling into change — and
  `from_address` degraded from "spend this specific coin" to "spend anything".
  Both failed with only a warning in a long interactive log, behind a
  transaction that then built and broadcast successfully.

  `assembly::parse_destination` now parses for the chain in play, and both call
  sites treat a failure as fatal. Dropping a declared output or a declared
  restriction is not a recoverable condition. Bitcoin addresses are also checked
  against the run's network rather than merely parsed — a mainnet address parses
  fine on a signet run.

  `select_input` now takes the run's `Network` and derives both the asset it
  matches on and its address parser from it, so the two cannot drift apart again.

- **Fixed: a Bitcoin run would have reported a funded wallet as empty.**
  `select_input` resolved the manifest labels `"lbtc"` / `"bitcoin"` through an
  `ElementsNetwork`, so on a Bitcoin run it looked for Liquid's policy asset
  while the scan produced the synthetic Bitcoin one. The two never match, and the
  failure mode was silent: no error, no wrong transaction, just "no wallet UTXOs
  available" from a wallet holding funds. `select_input` now takes the run's
  policy asset directly — the asset a run spends is a property of the run, not of
  a network.

  Every module-level test passed throughout, because the disagreement was
  *between* two modules that were each individually right. `tests/bitcoin_path.rs`
  now exercises the seam rather than the parts: scanned UTXO → the shared
  assembly's vocabulary → the narrowing → a built, signed, extractable
  transaction, with the signature verified against the scriptPubKey being spent.
  It also pins the specific mismatch, so it cannot come back.

- **Bitcoin runs are dispatched from `lifecycle::run`.** A Bitcoin manifest now
  loads a `BitcoinWallet`, scans Esplora for UTXOs, runs the shared assembly, and
  then builds, signs and broadcasts a PSBT. Elements is untouched.

  The two paths diverge at the build, not before: Elements carries on to the
  separate signing, covenant dry-run and finalize steps, because a PSET passes
  through three stages that can each fail in a way worth reporting. Bitcoin does
  all three at once — covenant execution needs the upstream jet FFI, so the only
  transactions reachable there are plain payments, and splitting three mechanical
  operations across three steps would invent places to stop. A covenant input on
  a Bitcoin run is refused with that explanation rather than silently skipped.

  Bitcoin UTXOs are presented to input selection in LWK's `WalletTxOut` shape by
  `assembly::bitcoin_spendable_utxos` — the input-side counterpart of the
  synthetic policy asset, and safe for the same reason: the outpoint, value and
  scriptPubKey are real, the asset and blinding factors are synthetic, and the
  narrowing checks and drops the synthetic ones. Doing it this way keeps input
  selection — several hundred lines of amount and asset matching — off the list
  of things being rewritten, which matters because that code is in the path funds
  move along. A test carries a UTXO through the assembly's vocabulary and back
  out through the narrowing to confirm the real fields survive.

  `BitcoinRun` carries its own `Network` rather than deriving one from
  `network_for_asset`, which is an `ElementsNetwork` computed from the wallet
  file's mainnet flag and is meaningless on Bitcoin — taking it from there would
  hand the covenant derivation the wrong chain.

- **`assembly` — the seam between the shared lifecycle and the chain under it.**
  `lifecycle::run`'s input/output assembly is ~800 lines of destination
  resolution, covenant address derivation, amount evaluation and state metadata.
  It turns out to need exactly **six** things from the chain: a covenant's
  scriptPubKey, an asset label resolved to an id, a change address, the next
  receive address, the policy asset, and whether outputs are confidential by
  default. `AssemblyContext` is those six, with `ElementsContext` over LWK and
  `BitcoinContext` over `BitcoinWallet`.

  One assembly path rather than two: a duplicate would agree on the day it was
  written and drift by the next release, in ways only a funded transaction would
  reveal. The lifecycle rewiring is a pure refactor — the existing tests are what
  say so.

  The assembly still speaks the Elements vocabulary on both chains: outputs carry
  an `AssetId` and an optional blinding key, and on Bitcoin the asset is a single
  synthetic constant and the blinding key is always `None`. That is a deliberate
  leak. The alternative — a neutral vocabulary both chains widen from — means
  rewriting all 800 lines against it, which is the risk the seam exists to avoid.
  The synthetic asset is not a fiction that has to hold together on its own:
  `psbt_builder::from_pset_request` refuses any second asset or blinding key, so
  the narrowing enforces the invariant rather than this module being trusted to
  maintain it.

  `AddressInfo` carries both the script and its encoding, because the assembly
  genuinely uses both — the script goes into the transaction, the encoding into
  the line a user reads to check where their money went. Deriving one from the
  other at the call site would mean the shared assembly picking an encoding,
  which is exactly what it must not do.

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

- **Covenant scriptPubKeys are derived per chain, not just addresses.** The
  taproot *tweak* is domain-separated the same way the tag hashes are
  (`TapTweak/elements` versus `TapTweak`), so one covenant tree yields different
  scriptPubKey **bytes** on the two chains — not merely a different address
  string. That is a third independent reason a covenant address is chain-specific,
  alongside the jet CMRs and the TapBranch tag, and the only one with no visible
  symptom: an Elements-derived script is a perfectly well-formed P2TR output on
  Bitcoin, and a transaction paying it looks entirely normal right up until nobody
  can ever spend it.

  `covenant_script_pubkey_for` dispatches on the network and
  `compute_bitcoin_covenant_address` is its Bitcoin half; both share one
  merkle-root computation so they cannot fold different trees while disagreeing
  (correctly) about the tweak. A Bitcoin address built from Elements compile
  options is refused, so the tweak and the jet set cannot come from different
  chains.

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
