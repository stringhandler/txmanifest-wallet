# SHRINCS verifier (vendored)

A copy of [shrincs-simplicity-verifier](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier),
the SimplicityHL verifier for the SHRINCS hash-based signature scheme, used by the
post-quantum signature work.

- `upstream/` is upstream at commit
  `9d3791a2331928d6596abf922c5125ffec58aeeb` (2026-10-01), unmodified. It holds the
  `.simf` sources, `examples/` with their witness files, `README.md` and `LICENSE` (CC0).
  Upstream's bundled `simfony` binary, `docs/`, `scripts/` and `Makefile` are left out.

Nothing here is compiled directly. Each example that uses the verifier flattens it into
its own directory with `mcpp -P`, as upstream's `scripts/` do, and commits the result. The
result is what gets compiled and pinned, and committing it means tests don't need the
preprocessor:

- `examples/pq_shrincs_smoke/build.sh` flattens upstream's own example, unmodified.
- `examples/pq_shrincs/build.sh` flattens the wrapper that pins the key and the message.

Both were run with mcpp 2.7.2. Other preprocessors work too, but need not produce the
same bytes, and the bytes are what a pin hashes.

To update: copy the same files from a newer upstream commit into `upstream/`, update the
commit above, rerun both `build.sh` scripts, run `tx-manifest-wallet pin` on both
manifests, and run the tests.
