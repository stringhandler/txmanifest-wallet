# Migration: rename the `compile_params.NAME` reference namespace to `instance.NAME`

**Status:** TODO
**Origin:** transaction-manifest spec change (tx_manifest_spec repo). This doc tells the
manifest-wallet side what to change to stay in sync.

## Background

The manifest formula/reference namespace `compile_params.NAME` was a vestige of an older
spec version that had a top-level `compile_params` block. That block is long gone. In every
current manifest, a `compile_params.NAME` reference resolves to a **class/instance field**
loaded from the instance file (Classes & Instances extension) — verified: 100% of such
references in the example manifests map to an instance field, and none are anything else.

So the spec renamed the **value reference namespace** from `compile_params.` to `instance.`:

| Manifest construct | Before | After |
|---|---|---|
| Value read in a formula / asset / amount / witness `source.key` | `compile_params.NAME` | `instance.NAME` |
| Hook `set` target | `"compile_params.NAME": "<expr>"` | `"instance.NAME": "<expr>"` |
| `create_instance.fields` `$`-substitution | `"$compile_params.NAME"` | `"$instance.NAME"` |

**Unchanged — do NOT rename these:**

- The covenant **wiring field** `script.compile_params` (the object that maps a `.simf`
  program's own compile-time parameter names to values). It is still called `compile_params`
  in the manifest JSON. In the Rust code this is the `compile_params: &HashMap<String,String>`
  arguments in `covenant.rs` — leave them as-is.
- Internal storage names may stay: `ExecutionContext::compile_params`, `get_compile_param()`,
  etc. still work — the values they hold are exactly the instance fields. Renaming them to
  `instance` / `get_instance_field()` is optional cosmetic cleanup, not required. Only the
  **manifest-facing string prefix** must change.

## Code changes

Change the recognized reference prefix from `"compile_params."` to `"instance."` (and the
bare namespace token `"compile_params"` to `"instance"`) at these sites:

**`txmanifest_lib/src/eval.rs`**
- `162` — `name.strip_prefix("compile_params.")` → `strip_prefix("instance.")`
- `321` — `token == "compile_params"` → `token == "instance"`
- `336` — `result.push_str("compile_params.")` → `push_str("instance.")` (unresolved-token passthrough)
- `415` — `"compile_params" => ctx.get_compile_param(key)...` → match arm `"instance" => ...`

**`txmanifest_lib/src/lifecycle.rs`** — every `strip_prefix("compile_params.")`:
- `565`, `654`, `753`, `1494`, `2922`, `2940`, `3022`, `3150`, `3194`, `3378`

(Search the whole crate for the literal `"compile_params."` and `"compile_params"` used as a
manifest prefix/namespace token to catch any site this list misses — e.g.
`grep -rn 'compile_params' --include=*.rs txmanifest_lib/src`. Ignore hits that are the
`script.compile_params` wiring map or internal field/method names.)

### Recommended: transitional alias (optional)

If any manifests exist outside this repo, accept **both** prefixes for a release, preferring
`instance.`, then drop the legacy one:

```rust
let key = name.strip_prefix("instance.")
    .or_else(|| name.strip_prefix("compile_params.")); // deprecated alias — remove after transition
```

If there are no external manifests, a hard cut is fine (the spec has already removed the old
name).

## Fixtures / examples to update

These carry `compile_params.` references and must be re-synced:

- `examples/last_will/txmanifest.json` (4 refs)
- `examples/lending/txmanifest.json` (94 refs)
- Any inline JSON in `#[test]` modules that uses `compile_params.` (grep the `.rs` files).

The rename is a safe pure-text replacement — the wiring field `"compile_params":` has no
trailing dot, so it is untouched:

```bash
# from repo root
python - <<'PY'
import pathlib
for f in ["examples/last_will/txmanifest.json","examples/lending/txmanifest.json"]:
    p=pathlib.Path(f); b=p.read_bytes()
    p.write_bytes(b.replace(b"compile_params.", b"instance."))
PY
```

Then confirm each file is still valid JSON and that `"compile_params":` wiring blocks remain.

## Related spec change (separate but adjacent)

The inert `taproot_leaf` witness (conventionally `SPEND_PATH`, `expr: "<utxo_type>_leaf"`) was
**removed** from the spec and examples, because the wallet never consumed it — the spend leaf
and control block are derived directly from the covenant program. Optional cleanup here:

- Drop `"taproot_leaf"` from `KNOWN_WITNESS_TYPES` and remove its no-op arm in
  `txmanifest_lib/src/validate.rs` (so a stray one now warns as unrecognized).
- Note the name collision: in `examples/last_will`, `SPEND_PATH` is a **real** `simplicityhl`
  program witness (`match witness::SPEND_PATH` in `last_will.simf`) — keep those. Only the
  `type: "taproot_leaf"` entries were removed.

## Acceptance

- `cargo test` passes with fixtures updated.
- Running the `lending` and `last_will` examples end-to-end produces the same covenant
  addresses and PSETs as before (the change is a pure reference rename; behavior is identical).
