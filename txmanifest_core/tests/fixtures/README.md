# Test fixtures

Files the tests read. Nothing here is an example to copy.

- `lending_v2/` and `lending_v3/` are frozen copies of lending contracts whose addresses,
  OP_RETURN payloads and witnesses the tests pin against the chain and against
  [simplicity-lending](https://github.com/BlockstreamResearch/simplicity-lending). They
  catch a compiler or encoding change that would move a live address, so they must not be
  edited: a change here is a change to the ground truth.
- `unstable_enums.simf` is a program that only compiles with an unstable compiler feature
  enabled.
