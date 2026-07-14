# Phase 2c — Engine: richer OP_RETURN encoding (LE integers + program_id)

## Goal
Produce the deployed protocol's 50-byte offer-creation OP_RETURN.

## Layout (smplx `lending/metadata.rs::encode`, LENGTH=50)
| field | off | width | order |
|-------|-----|-------|-------|
| program_id | 0 | 4 | `sha256(lending.simf SOURCE text)[..4]` |
| principal_asset_id | 4 | 32 | internal order (`into_inner().0`) |
| principal_amount | 36 | 8 | **u64 LE** |
| loan_expiration_time | 44 | 4 | **u32 LE** |
| principal_interest_rate | 48 | 2 | **u16 LE** |

`program_id` = first 4 bytes of `SHA256(raw .simf source string)` — NOT the CMR
(`smplx-sdk-0.0.5/src/program/core.rs:129-135`).

## Engine work
Current `eval::eval_op_return_data` handles `concat(ref,…)` with hex + asset reversal
only. Extend the OP_RETURN `data` mini-language to support typed fields:
- LE-encoded integers of a given width (u8/u16/u32/u64), e.g. from an `instance.X` value.
- `program_id(<simf path>)` = `sha256(source)[..4]`.
- asset-id already handled (reverse to internal).
Design: allow a structured `data` (ordered list of `{value, type, width?}`) or extend the
concat expression with typed helpers. Keep the existing `concat(...)` form working.

## Acceptance
- A manifest OP_RETURN output produces the exact 50-byte payload for given params;
  first 4 bytes == lending program_id; decodes correctly with SL's
  `decode_metadata_op_return`.
- Unit test asserting the byte layout for known params.

## Files
- `txmanifest_lib/src/eval.rs` (`eval_op_return_data`), `txmanifest_lib/src/manifest.rs`
  (Output.data shape if structured), `txmanifest_lib/src/lifecycle.rs` (op_return handler).
