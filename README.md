# VBEL

**Independently verifiable signed records with detectable changes and blockchain anchoring.**

Two companies keep one shared record of what happened between them. Every step is signed by
whoever did it and chained to the one before, so a later edit is provable instead of silent, and a
reader who does not trust either company can check the whole thing in their own process or browser.

```text
Signer                                   Reader (holds nothing of the signer's)
  sign record ─▶ chain to the last ─▶ link ─▶ decode ─▶ verify signatures, order, payloads
                                                    └▶ "this field changed" / "this was withheld"
```

## What it is, and what it is not

It proves a record was **not changed since it was signed**, in this order, by this key, and
optionally that it existed by a given time on a public chain.

It does **not** prove that what a record says is true, that goods arrived, that a claim is legally
enforceable, or that an invoice was not financed elsewhere. A valid signature and an anchor say
nothing about any of that. A name in a self asserted identity claim is exactly as trustworthy as
whoever wrote it, and the library reports it as `self-asserted` rather than as verified.
Withheld evidence is reported as withheld, never as a clean bill of health.

It is not a qualified electronic ledger under eIDAS 2.0 and it is not a compliance product.

## Packages

| Package | What it is |
|---|---|
| [`@vbel/core`](packages/core) | The envelope (frozen at v0.1), RFC 8785 canonical JSON, hashing, ed25519 signing and counter-signing (by a key you hold, or a `Signer` such as a wallet), chain validation, identity and registration primitives, anchoring authorisation. No I/O, imports nothing else in this repository. |
| [`@vbel/records`](packages/records) | What makes core usable by an application: a chain of records whose payloads may be withheld, a link codec, a verdict per record, selective disclosure with a signed cover sheet, identity claims that travel with the chain. Domain-neutral: you bring the shape of your own records. |
| [`@vbel/adapter-solana`](packages/adapter-solana) | Anchors a record's hash on Solana through the SPL Memo program, with no custom program, and turns a Solana wallet into a signer so a person can read what they approve. |
| [`@vbel/adapter-ethereum`](packages/adapter-ethereum) | Anchors a hash in the calldata of a zero-value transaction on an EVM chain. |
| [`@vbel/adapter-identity-ledger`](packages/adapter-identity-ledger) | Resolves who a key belongs to from registration records carried in the chain itself. |
| [`@vbel/adapter-identity-static`](packages/adapter-identity-static) | Resolves keys from an explicit list a verifier chooses to trust. |

Dependencies point inward only: core knows no adapter, and swapping a chain is one file that
satisfies `LedgerAdapter`.

## Try it

```bash
pnpm install
pnpm build
pnpm example
```

[`examples/verify-in-your-app`](examples/verify-in-your-app) signs two records for an order type it
invents, sends them as a link, and checks them from the other side. Then it edits an amount and
shows the check naming the field, and withholds a record and shows it reported as withheld rather
than forged. Read its last lines: it says what the output does not prove.

```bash
pnpm test        # every package, no network needed
pnpm typecheck
```

Anchoring needs a funded testnet key. Copy `.env.example` to `.env`, then:

```bash
set -a && source .env && set +a && pnpm --filter @vbel/adapter-solana smoke:anchor
```

## Status

Pre-1.0. The envelope is frozen; everything above it may change between minor versions until 1.0.
Signing keys are yours to hold: nothing in this repository stores or recovers one. Records are not
persisted by the library; a chain is data you keep, or carry in a link.

## Provenance

This repository was extracted from the codebase that also holds a demo application and two
domain modules (delivery and payment), which are not part of it. Its history is filtered to the
paths above. [`PROVENANCE.md`](PROVENANCE.md) lists, per package, when it first appeared and when it
last changed, and which source files were added after 28 August 2026, so that what pre-dates a given
competition or release is a matter of record. An earlier submission of the same idea, built for a
hackathon on 26 and 27 August 2026, is at [st3fansrb/vbel](https://github.com/st3fansrb/vbel) and is
unchanged.

## License

Apache-2.0. See [LICENSE](LICENSE).
