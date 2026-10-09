# Glossary

Terms as this repo uses them. Where a term is defined in more detail, the entry links there.

**Action.** One operation a manifest defines: its parameters, the inputs it spends, the
outputs it creates. Declared under `actions`, or under a contract template.

**Capability.** Something a wallet must support to run a manifest, listed in the
manifest's `requires`. The format defines `simplicity` (the manifest uses a Simplicity
program) and `hooks` (it sets values in hooks; see
[decision 0002](decisions/0002-hooks-capability.md)). Third parties may define their own
under a namespace (`ns::name`).

**Compiler-version requirement.** The SimplicityHL versions a program is written for, as a
semver requirement in the syntax of SimplicityHL's `simc` directive: `"0.7.1"` means
`^0.7.1`. See [decision 0001](decisions/0001-program-pinning.md).

**Content hash.** A self-describing hash of a file's exact bytes: `"sha256:<lowercase
hex>"`. See [decision 0001](decisions/0001-program-pinning.md).

**Contract template.** A reusable contract definition under `contract_templates`: typed
fields plus the actions that operate on one instance of it.

**Hook.** A block that sets values while a transaction is being built: `on_resolved` on an
input, `on_pre_broadcast` / `on_post_broadcast` on an action. Optional for a wallet to
support; a manifest using one requires `hooks`.

**Instance.** One deployed contract made from a template: the values its fields were given
when it was created.

**Manifest.** A `txmanifest.json` file describing a protocol's transactions. The format is
defined by [`schema/txmanifest.schema.json`](../schema/txmanifest.schema.json).

**Manifest id.** The hash identifying a manifest, computed from its canonical form. It is
derived from the manifest file alone; programs are covered through their content hashes.

**Pin / pinned / unpinned.** A program is *pinned* when the manifest gives it a content
hash and it has a compiler-version requirement (from the manifest or its own `simc`
directive). A manifest is pinned when all its programs are. Unpinned manifests are for
development only: wallets refuse them. `tx-manifest-wallet pin` writes the hashes. See
[decision 0001](decisions/0001-program-pinning.md).

**Program.** A Simplicity program, written in SimplicityHL (a `.simf` file), that a
covenant or a computed parameter uses.

**Program reference.** A place in a manifest that names a program: a `utxo_types` script's
`source` or `program`, or a `tapleaf` / `simf_fn` compute's `simf` or `program`.

**Programs table.** The optional top-level `programs` object of named programs, each with
its `source`, `hash` and `simplicity_hl_version`, which program references can name.

**State.** The on-chain UTXOs a contract instance currently holds, as recorded after each
broadcast.

**SWEL.** The expression language used inside manifests for amounts, references and
conditions (`params.amount_sat`, `vault_in.amount_sat - fee`). Not yet formally specified.

**UTXO type.** A kind of output a manifest's actions create or spend, under `utxo_types`;
for a covenant, the program that locks it.
