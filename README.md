# VBEL

**Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public chain.**

[![CI](https://github.com/VBEL-HQ/VBEL-core/actions/workflows/ci.yml/badge.svg)](https://github.com/VBEL-HQ/VBEL-core/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)

Two companies keep one shared record of what happened between them. Every step is signed by
whoever did it and chained to the one before. A later edit is provable instead of silent, and a
reader who trusts neither company can check the whole record in their own process or browser. No
server holds the chain and there is no account: the records travel as a link.

## What a check looks like

The reader holds nothing of the signer's. They decode the link and ask for a verdict per record:

```ts
import { validateChain } from "@vbel/core";
import { buildIdentityContext, decodeChain, registrationsIn, splitHandoff, verifyAll } from "@vbel/records";

// `OrderNote` is your own zod schema. Anything in the link that it does not describe is refused.
const decoded = await decodeChain(link, { [SCHEMA_ORDER_NOTE]: OrderNote });
const { records, registrations } = splitHandoff(decoded);

validateChain(records.map((r) => r.event)).valid; // order and links intact
const verdicts = await verifyAll(records, buildIdentityContext(registrationsIn(registrations)));

for (const record of records) {
  const v = verdicts.get(record.event.envelope.eventId)!;
  v.signatureValid; // signed by the key the record names
  v.payloadState;   // "verified" | "withheld" | "mismatch"
  v.differences;    // [{ path: "$.quantity", expected: 470, actual: 500 }]
  v.identity;       // { name: "Example Supplier Ltd", assurance: "self-asserted" }
}
```

This is the reader half of [`examples/verify-in-your-app`](examples/verify-in-your-app), which also
does the signing. Run it with `pnpm example`. After someone changes a quantity from 470 to 500, the
check names the field; after a record is withheld, it says so and does not call it forged:

```text
2. After someone changes the quantity from 470 to 500:
  signature valid | payload verified | Example Supplier Ltd (self-asserted) | {"orderRef":"PO-1001","quantity":500,"note":"dispatched"}
  signature valid | payload mismatch | Example Supplier Ltd (self-asserted) | {"orderRef":"PO-1001","quantity":500,"note":"30 units short"}
      changed: $.quantity, was 470, now 500

3. With the second record withheld:
  signature valid | payload verified | Example Supplier Ltd (self-asserted) | {"orderRef":"PO-1001","quantity":500,"note":"dispatched"}
  signature valid | payload withheld | Example Supplier Ltd (self-asserted) | (sealed)
```

## Packages

| Package | What it gives you | Source |
|---|---|---|
| [`@vbel/core`](packages/core) | The event envelope (frozen at v0.1), RFC 8785 canonical JSON, SHA-256 hashing, ed25519 signing and counter-signing, chain validation, identity and registration primitives, anchoring authorisation. No I/O. | [`packages/core/src`](packages/core/src) |
| [`@vbel/records`](packages/records) | What makes core usable in an application: a chain whose payloads may be withheld, a link codec, a verdict per record, selective disclosure with a signed cover sheet, identity claims that travel with the chain. Domain-neutral. | [`packages/records/src`](packages/records/src) |
| [`@vbel/adapter-solana`](packages/adapter-solana) | Anchors a record's hash on Solana through the SPL Memo program, and turns a Solana wallet into a signer. | [`packages/adapter-solana/src`](packages/adapter-solana/src) |
| [`@vbel/adapter-ethereum`](packages/adapter-ethereum) | Anchors a hash in the calldata of a zero-value transaction on an EVM chain. | [`packages/adapter-ethereum/src`](packages/adapter-ethereum/src) |
| [`@vbel/adapter-identity-ledger`](packages/adapter-identity-ledger) | Resolves who a key belongs to from registration records carried in the chain itself. | [`packages/adapter-identity-ledger/src`](packages/adapter-identity-ledger/src) |
| [`@vbel/adapter-identity-static`](packages/adapter-identity-static) | Resolves keys from an explicit list that a verifier chooses to trust. | [`packages/adapter-identity-static/src`](packages/adapter-identity-static/src) |

`core` imports nothing else in this repository; everything else depends on it, never the reverse.
Swapping a chain is one file that satisfies the `LedgerAdapter` interface in
[`ledger.ts`](packages/core/src/ledger.ts).

## Where to start reading

| To understand | Read |
|---|---|
| The record format | [`envelope.ts`](packages/core/src/envelope.ts) |
| What is signed, and how a signature is checked | [`sign.ts`](packages/core/src/sign.ts) |
| Why two equal records hash equally | [`canonicalize.ts`](packages/core/src/canonicalize.ts) |
| Signing with a wallet instead of a held key | [`signer.ts`](packages/core/src/signer.ts), [`message.ts`](packages/core/src/message.ts) |
| How a stored payload is checked against what was signed | [`payload.ts`](packages/core/src/payload.ts) |
| Withholding a payload without breaking the chain, and recording that it was shown | [`disclosure.ts`](packages/records/src/disclosure.ts), [`disclosure.ts`](packages/core/src/disclosure.ts) |
| Superseding and revoking, since records are never deleted | [`lifecycle.ts`](packages/core/src/lifecycle.ts) |
| Turning a chain into a link and back | [`codec.ts`](packages/records/src/codec.ts) |
| How a record gets its verdict | [`verify.ts`](packages/records/src/verify.ts) |
| Who signed, and how sure to be | [`identityContext.ts`](packages/records/src/identityContext.ts), [`registration.ts`](packages/records/src/registration.ts) |

## What it proves, and what it does not

It proves that a record was **not changed since it was signed**, in this order, by this key, and
optionally that it existed by a given time on a public chain.

It does **not** prove that what a record says is true, that goods arrived, that a claim is legally
enforceable, or that an invoice was not financed elsewhere. A name in a self-asserted identity claim
is exactly as trustworthy as whoever wrote it, and the library reports it as `self-asserted` rather
than as verified. Withheld evidence is reported as withheld, never as a clean bill of health.

It is not a qualified electronic ledger under eIDAS 2.0 and it is not a compliance product.

## Development

```bash
pnpm install
pnpm build
pnpm test        # every package, no network needed
pnpm typecheck
pnpm example
```

Anchoring needs a funded testnet key. Copy `.env.example` to `.env`, then:

```bash
set -a && source .env && set +a && pnpm --filter @vbel/adapter-solana smoke:anchor
```

## Status

Pre-1.0. The envelope is frozen; everything above it may change between minor versions until 1.0.
Signing keys are yours to hold: nothing in this repository stores or recovers one. Records are not
persisted by the library. A chain is data you keep, or carry in a link.

See [SECURITY.md](SECURITY.md) to report a vulnerability and [CONTRIBUTING.md](CONTRIBUTING.md) to
contribute.

## Provenance

This repository was extracted from the codebase that also holds a demo application and two domain
modules (delivery and payment), which are not part of it. Its history is filtered to the paths above.
[`PROVENANCE.md`](PROVENANCE.md) lists, per package, when it first appeared and when it last changed,
and which source files were added after 28 August 2026, so that what pre-dates a given competition or
release is a matter of record. An earlier submission of the same idea, built for a hackathon on 26 and
27 August 2026, is at [st3fansrb/vbel](https://github.com/st3fansrb/vbel) and is unchanged.

## License

Apache-2.0. See [LICENSE](LICENSE).
