# Docs

This repository defines the txmanifest format, and other wallets implement it, so the
format's terms and design decisions are recorded here.

- [`glossary.md`](glossary.md): the terms this repo uses, one entry each.
- [`format-changelog.md`](format-changelog.md): changes to the manifest format, by
  `manifest_version`.
- [`decisions/`](decisions): one record per settled design decision, numbered in order.

## Decision records

Each record is short: the context, what was decided, and what follows from it. Once
accepted, a record isn't edited except for typos. A later decision that changes it gets
a new record, and the old one's status becomes "superseded by NNNN".

To add one, copy the shape of the latest record, take the next number, and link any new
terms from the glossary.
