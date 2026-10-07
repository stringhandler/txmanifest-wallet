# 0001: Pin Simplicity programs by hash and compiler version

- **Status:** accepted
- **Date:** 2026-10-07

## Context

A manifest references its Simplicity programs by path (`"source": "./lending.simf"`). Its
manifest id is computed from the manifest file, so the programs were not covered by it:
editing, swapping or corrupting a `.simf` file left the id unchanged while changing where
funds are locked. A wallet given a manifest and its sources separately, such as a browser
extension receiving a request from a dapp, had no way to check it was given the right
sources.

Nothing in a manifest said which compiler a program was written for either, and
different compilers could in principle produce different programs from the same source.

## Decision

1. **The manifest id stays derived from the manifest file alone.** Each program reference
   carries a hash of the file it points to, so the id covers the programs.
2. **Hashes are self-describing:** `"sha256:<lowercase hex>"`, over the file's exact bytes.
   `sha256` is the only algorithm defined; an unknown one is an error.
3. **Two forms, both valid, and they may be mixed:**
   - on the reference: `source` / `source_hash` / `simplicity_hl_version` on a `utxo_types`
     script, `simf` / `simf_hash` / `simplicity_hl_version` on a `tapleaf` or `simf_fn`
     compute;
   - a top-level `programs` table of `{ source, hash, simplicity_hl_version }`, named from a
     reference with `"program": "<name>"`.

   Every reference to one file must agree on its hash and version. A reference that
   states neither inherits them; one that states a different value is an error.
4. **Compiler versions are semver requirements**, with the same syntax and meaning as
   SimplicityHL's `simc "<range>";` directive (`"0.7.1"` means `^0.7.1`). Where a program's
   requirement comes from, highest priority first: the reference or `programs` entry, then
   `simplicity_hl.version` for the whole manifest, then the file's own `simc` directive.
   The manifest can narrow the file's directive but never widen it, because the compiler
   still enforces the directive.
5. **Pinned and unpinned.** A program is *pinned* when it has a hash and a compiler-version
   requirement. A manifest with any unpinned program is unpinned:
   - allowed while developing (`validate` warns; `run --allow-unpinned` runs it). A
     program edited since it was pinned counts as unpinned here, so `run --allow-unpinned`
     warns about the stale hash instead of refusing;
   - refused for publishing (`validate --strict` errors) and by wallets, which must not
     run an unpinned manifest. `run` refuses by default; the library's `Unpinned::Allow`
     exists only for development tooling such as `--allow-unpinned`.

   Manifests written before this change load as unpinned.
6. **Introduced in manifest format `0.3.1`.** The change only adds fields, so it's a patch
   release of the format: `0.3.0` manifests still load (as unpinned).
7. **The compiler version is not separately part of the manifest id.** It's a declared
   requirement, covered by the id like any other field.

## Consequences

- Changing one byte of a pinned program makes loading fail, naming the file and both
  hashes, unless running with `--allow-unpinned`, where it's a warning. Two manifests that differ only in a program hash have different ids.
- Every program is read once per run, by one checked loader; the covenant code receives
  source text, never a path.
- Authors refresh hashes after editing a program with `tx-manifest-wallet pin`, which
  edits only the hash values and leaves the rest of the file as written.
  `pin --check` fails if any hash is missing or stale, for CI.
- **Assumption:** a newer SimplicityHL compiles the same source to the same program as the
  version it was written for. Under that assumption a requirement is a minimum, and wallets
  on different compiler versions derive the same addresses. If it stops holding,
  requirements must become exact versions.
- **Single-file programs only.** A program is compiled from the one file it names; imports
  from other files are not resolved, so one hash per file is enough. Supporting multi-file
  programs will need the hash rule extended to their dependencies.
- **A planned compiled object file** for Simplicity programs could replace compiling from
  source. The hash rule ("exact bytes of whatever `source` points at") carries over to it
  unchanged.
- The protocol-defined program ids some manifests carry (e.g. simplicity-lending's
  `LENDING_PROGRAM_ID`) are unrelated and unchanged.
