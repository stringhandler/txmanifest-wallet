# Examples

Each directory holds a `txmanifest.json`, the `.simf` programs it references, and
sometimes a `params.json` with sample values. Every example here passes
`tx-manifest-wallet validate` (CI checks this).

Roughly in order of complexity:

| Example | Chain | What it shows |
|---------|-------|---------------|
| [`p2pk`](p2pk) | Liquid | The smallest covenant: lock coins to a key with a Simplicity checksig program, then spend them. Start here. |
| [`bitcoin_pay`](bitcoin_pay) | Bitcoin | A plain payment with no covenant: what a manifest looks like on Bitcoin, and the `fee` keyword. |
| [`bitcoin_covenant`](bitcoin_covenant) | Bitcoin | The `p2pk` program on Bitcoin, run on the Simplicity signet or a local regtest. |
| [`last_will`](last_will) | Liquid | A recursive covenant with a timelocked inheritance path, a cold-key break-out and a hot-key refresh. |
| [`dex`](dex) | Liquid | Tessera: a keyless atomic-swap offer anyone can fill, or refund after a timeout. |
| [`deadcat_v3`](deadcat_v3) | Liquid | A binary prediction market with on-chain oracle resolution and confidential reissuance tokens. Derived from [Deadcat](https://github.com/Resolvr-io/deadcat); not interoperable with it. |
| [`lending_v2`](lending_v2) | Liquid | Peer-to-peer collateralised lending, wire-compatible with [simplicity-lending](https://github.com/BlockstreamResearch/simplicity-lending). |
| [`lending_v3`](lending_v3) | Liquid | Work in progress: the redesigned "issuance factory" version of simplicity-lending — create a factory, then offer, accept, cancel, claim and repay loans. |

The examples with their own README (`bitcoin_pay`, `bitcoin_covenant`, `lending_v2`)
include full walkthroughs.
