# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Both workspace crates —
`tx-manifest-lib` and `tx-manifest-wallet` — carry the same version and are
released together.

No changelog was kept before 0.2.0; for 0.1.x see the git history.

## [Unreleased]

**Breaking:** `description` is gone from every position in the format. Developer
prose moves to `$comment`; the prose a *user* reads at a param prompt moves to
`ui_help`. A manifest that still sets `description` does not parse.

**Breaking:** `manifest_version` must now read `"0.3.0"`.

**Breaking:** every manifest-side name is `snake_case` — action `params`,
contract-template `fields`, and `create_instance.fields`. A wallet has no label
field for a param: the name *is* the label, so `collateral_amount` title-cases
into "Collateral amount" and reads as a value someone supplies rather than as a
compiled-in constant.

The one thing that stays SCREAMING is a `.simf` `param::` identifier, and drawing
the line there is what makes `compile_params` legible for the first time. An entry
now reads `SIMF_PARAM: manifest_name`, where before it read `"X": "X"` and nothing
told a reader which side was which — the left is compiled into the covenant, the
right is looked up in the manifest.

Every `params.json` collapses accordingly: the two spellings that used to serve a
param and a same-named field are now one key.

### Changed

- **`description` split into `$comment` and `ui_help`.** One key had been doing
  two jobs. It was excluded from the registry hash like a comment, yet `describe`
  printed it, `prompt` used it as the hint beside a param, and `lifecycle` put
  the manifest's, the action's, and each output's copy on screen during a run —
  four paths by which text nobody had signed reached a user about to authorise a
  transaction. `canonical.rs` asserted this could not happen and `preview.rs`
  refused `description` as a label fallback for exactly that reason; neither was
  true of the run itself.

  The split makes the rule structural rather than aspirational. `$comment` is
  stripped in `Manifest::from_json_str` before deserialization, so no field
  survives for a renderer to reach — the guarantee holds whether or not anyone
  remembers it. `ui_help` is a declared field and **is** hashed, because the text
  beside a prompt steers what a user types and is worth as much to an attacker
  as the confirmation screen.

  `UNHASHED_KEYS` is now identical to `STRIPPED_KEYS`, and that is the invariant:
  a key may be left out of the hash exactly when the parser guarantees it can
  never be shown.

- **`describe` reads `$comment` back from the file.** It is the one renderer that
  shows developer prose, and it is a documentation command that authorises
  nothing, so it re-parses the original bytes and looks comments up by path. The
  parsed `Manifest` every other renderer holds carries none.

- **Prose in the examples follows the rename** where it is decidable: a SCREAMING
  word in a `$comment` or `ui_help` was rewritten when no `.simf` constant shares
  its spelling. 139 mentions where one does are left as they were — at that point
  the prose is as likely to mean the compiled-in constant as the manifest name,
  and only a reader can tell.

### Removed

- `Manifest::description`, `Action::description`, `Input::description`,
  `Output::description`, `ContractTemplate::description`, and
  `UtxoParamDef::description` — use `$comment`.
- `UtxoType::description`, which was additionally the format's only *required*
  prose field.
- `ParamDef::description` and `FieldDef::description` — use `ui_help`.

## [0.2.0] - 2026-08-20

**Breaking:** a manifest that sets `utxo_type.confidential` no longer parses.
Confidentiality is now declared per output.

**Breaking:** `manifest_version` must now read `"0.2.0"`. The field carries the
version of the *format*, which moves separately from these crates, and the
change above is a breaking format change — so it moves too. Every example was
updated.

### Added

- **Two rules that keep a manifest id unambiguous**, checked by `validate` and, as
  far as JSON Schema can express them, by the published schema. `manifest-id`
  refuses to print an id for a file that breaks either — an id another
  implementation would compute differently is worse than no id, and worst of all
  once a signature exists over it.

  *Numbers must be integers.* `1.0`, `1e2` and `1.5` all parse, and JSON
  libraries disagree about how to write them back out, so the id would depend on
  which one computed it. Integers round-trip identically everywhere, which is why
  the rule is "integers only" rather than a full RFC 8785 number normalisation.
  The schema catches `1.5` at edit time; it cannot catch `1.0`, because draft-07
  validates parsed values and `1.0` *is* an integer by then — only the checker,
  which sees how the number was written, catches that.

  *Strings must be in Unicode NFC.* `é` as one code point and as `e` + U+0301
  render identically and hash differently. RFC 8785 leaves normalisation to the
  application, so this has to be a rule about what a manifest may contain: left
  open, a look-alike manifest could show a signer the same confirmation screen,
  character for character, under a different id. No schema keyword can express
  this, so it lives in `validate` alone.

- **Publisher signatures, and a `tx-manifest-sign` CLI to make them.** A manifest
  may carry a root `signatures` array of `{ public_key, signature }` — BIP-340
  x-only keys over `tagged("txmanifest/signature/v1", manifest_id)`.

  *Unhashed, at the root only.* A signature that changed the id would invalidate
  every other signature over the same file, so only the first signer could ever
  exist; excluded, any number of parties sign the same id independently and
  stripping the block leaves the id untouched. This is the **second** reason a key
  may be left out of the hash, and it is not the first one: `$comment` is safe
  because the parser guarantees it never reaches a user, while `signatures` is
  read *and* displayed and is safe because its content is checked against the
  hash. Both arguments are written out in `canonical.rs`; a third key needs its
  own, not an analogy. Nested, `signatures` is a field no type declares, so
  `deny_unknown_fields` rejects the file — "unhashed" must not be a property that
  can appear at any depth.

  *The entry carries only what the signature covers.* No role, no timestamp, no
  display name: an unsigned field beside a signature is free for anyone to edit,
  and `"role": "auditor"` relabelled to `"publisher"` costs an attacker nothing.

  *A signature is not trust.* The file supplies the key, so anyone can add an
  entry. `verified_keys` returns which keys verified rather than a bool, `verify
  --require <key>` fails closed, and the block is capped and rejects a repeated
  key — a list of plausible strangers is a display attack, not an endorsement.

  *A stale signature is an error, not a warning.* The block survives every edit to
  the manifest, so an author who changes a label leaves an entry that still reads
  as "signed" to anything that does not check. `validate` and both CLIs reject it.

  The signing tool is a separate binary over a new **`tx-manifest-core`** crate —
  canonical form, id, id-stability rules, signatures — because a publisher signing
  a JSON file should not build a wallet, an Esplora client and a SimplicityHL
  compiler to do it: 55 crates instead of 296. `tx-manifest-lib` re-exports it, so
  `tx_manifest_lib::canonical::…` paths are unchanged, and a pinned test vector
  fixes the id against the hash-backend swap that move required. Signed files are
  build products: the examples here stay unsigned and `.gitignore` keeps
  `*.signed.json` out.

- **`manifest-id <manifest>`**, the id a registry keys a manifest by and a
  signature commits to: a BIP-340-style tagged SHA-256 (`txmanifest/id/v1`) over
  the manifest's canonical form. Canonicalization sorts keys at every depth and
  drops `$comment` and `$schema`, so reindenting a file or rewriting a developer
  note leaves the id — and any signature over it — intact, while everything a
  signer reads (`ui.label`, `ui.role`, `ui_help`) is covered. That split is only
  safe because those two keys are stripped before deserialization and so cannot
  reach a screen; it is why `description`, which was unhashed yet printed, had
  to go. `--canonical` writes the exact preimage bytes, unterminated, so a
  registry can store them or pipe them to its own hasher.

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
