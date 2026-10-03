# Provenance

Generated from this repository's history by `scripts/provenance.py` when it was extracted, so that what came before a given release or competition is a matter of record.

The cut-off is **2026-09-14**, the first day of Colosseum's Crypto World's Fair. Everything dated before it is pre-existing work and is disclosed as such. The idea started at ETH Belgrade x Superteam Balkan (26 and 27 August 2026, frozen at [st3fansrb/vbel](https://github.com/st3fansrb/vbel)); commits between that hackathon and the cut-off are part of the pre-existing work too.

| Package | First commit | Last commit | Commits before the cut-off | Commits after |
|---|---|---|---|---|
| `packages/core` | 2026-08-24 | 2026-09-30 | 8 | 10 |
| `packages/records` | 2026-08-24 | 2026-09-30 | 16 | 9 |
| `packages/adapter-solana` | 2026-08-24 | 2026-09-29 | 2 | 9 |
| `packages/adapter-ethereum` | 2026-08-27 | 2026-09-29 | 1 | 5 |
| `packages/adapter-identity-ledger` | 2026-09-05 | 2026-09-29 | 2 | 5 |
| `packages/adapter-identity-static` | 2026-08-27 | 2026-09-29 | 1 | 4 |

## Source files added after the cut-off

Per package, the source files whose first commit is later than the cut-off, with that date. A file not listed here existed at the cut-off, possibly in an earlier form. Files that were moved into a package from elsewhere keep the date of their first appearance anywhere, because the history was carried across the move.

**`packages/core`**

- `packages/core/src/anchor-auth.ts` (2026-09-29)
- `packages/core/src/message.ts` (2026-09-28)
- `packages/core/src/signer.ts` (2026-09-28)

**`packages/records`**

- `packages/records/src/handoff.ts` (2026-09-29)
- `packages/records/src/identityContext.ts` (2026-09-29)
- `packages/records/src/index.ts` (2026-09-29)
- `packages/records/src/verify.ts` (2026-09-29)

**`packages/adapter-solana`**

- `packages/adapter-solana/src/env.ts` (2026-09-29)
- `packages/adapter-solana/src/wallet-signer.ts` (2026-09-28)

**`packages/adapter-ethereum`**

- `packages/adapter-ethereum/src/env.ts` (2026-09-29)

**`packages/adapter-identity-ledger`**

None.

**`packages/adapter-identity-static`**

None.

## How to read this

Counting commits and dates says what came first. It does not say how much of a file's behaviour is new: a file that existed at the cut-off may have been rewritten since, and a file added since may be a move of code that was already there. That is a judgement to make from the diff, and the diff is here to make it from (`git log --stat -- <path>`).

