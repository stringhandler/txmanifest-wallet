# shrincs-signer

A command-line SHRINCS signer for [`examples/pq_shrincs`](../../examples/pq_shrincs). It
is a thin driver around [shrincs-cpp](https://github.com/BlockstreamResearch/shrincs-cpp),
upstream's reference implementation; all the cryptography is upstream's.

This is a stopgap. The plan is for signers to run inside the wallet as Simplicity
programs, after which this goes away.

```sh
make                      # fetches shrincs-cpp into deps/, builds bin/shrincs-signer
bin/shrincs-signer new    --seed key.seed --state key.q
bin/shrincs-signer pubkey --seed key.seed
bin/shrincs-signer sign   --seed key.seed --state key.q --msg <32-byte hex>
```

- `new` writes a random 48-byte seed (`SK.seed ‖ SK.prf ‖ PK.seed`, as hex) and a state
  file at q = 0, both mode 0600. It refuses to overwrite either.
- `pubkey` prints `PK = PK.seed ‖ PK.root`, the manifest's `bytes32` param.
- `sign` makes a stateful signature with the next leaf index. It prints
  `{"SIG": …, "OTHER_ROOT": …}` as SimplicityHL values in the layout
  `examples/pq_shrincs/shrincs_spend.simf` reads. It also checks the signature with
  shrincs-cpp before printing it.

## State

The state file holds the last leaf index used. Each signature uses the next one, and a
key has 207 (1 to 206 in the unbalanced tree, then 207). **Reusing an index lets anyone
forge**, so:

- `sign` writes and syncs the new index *before* printing the signature. A crash can
  waste an index, but never reuses one.
- `sign` refuses to run without a state file rather than assume q = 0, because a lost
  state file is how an index gets reused.
- Keep the state file with the seed, and never restore an old copy of it.

Stateless signatures, which SHRINCS falls back to after 207 or when the state is lost,
aren't supported here.

## Build notes

- shrincs-cpp is pinned to `fde3603`. That commit produces the FORS+C signatures
  upstream's `main` verifier accepts. Later commits moved to PORS+FP, which it rejects.
- `-DSHRINCS_L` selects the parameters the verifier hard-codes (W=4, L=64, S=140,
  HSF=206). shrincs-cpp defaults to SHRINCS-B, whose signatures the verifier rejects.
- `-include algorithm` works around upstream's `hash.cpp` using `std::min` without
  including `<algorithm>`. GCC's headers supply it; Apple clang's libc++ does not.
- It needs OpenSSL 3. On macOS the Makefile finds Homebrew's `openssl@3`; elsewhere, set
  `OPENSSL_PREFIX` or install `libssl-dev`.
