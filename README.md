# VBEL

**Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public chain.**

[![CI](https://github.com/VBEL-HQ/VBEL-core/actions/workflows/ci.yml/badge.svg)](https://github.com/VBEL-HQ/VBEL-core/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)

Two companies keep one shared record of what happened between them. Every step is signed by
whoever did it and chained to the one before. A later edit is provable instead of silent, and a
reader who trusts neither company can check the whole record in their own process or browser. No
server holds the chain and there is no account: the records travel as a link.

## What a check tells you

| It proves | It does not prove |
|---|---|
| The record was **not changed** since it was signed | That what it says is **true** |
| It came **in this order**, from **this key** | That goods arrived, or that a claim is legally enforceable |
| Optionally, that it **existed by a given time** on a public chain | That an invoice was not financed elsewhere |

- A name in an identity claim is only as trustworthy as whoever wrote it. It is reported as
  `self-asserted`, never as verified.
- Withheld evidence is reported as **withheld**, never as a clean bill of health.

VBEL is not a qualified electronic ledger under eIDAS 2.0, and not a compliance product.

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

| Package | One line |
|---|---|
| [`@vbel/core`](packages/core) | Envelope, canonical JSON, hashing, ed25519 signing, chain validation. No I/O. |
| [`@vbel/records`](packages/records) | Records an app can use: withholdable payloads, link codec, a verdict per record, selective disclosure. You bring your own record shapes. |
| [`@vbel/adapter-solana`](packages/adapter-solana) | Anchor a hash on Solana (SPL Memo, no custom program). Use a wallet as a signer. |
| [`@vbel/adapter-ethereum`](packages/adapter-ethereum) | Anchor a hash in the calldata of a zero-value EVM transaction. |
| [`@vbel/adapter-identity-ledger`](packages/adapter-identity-ledger) | Resolve who a key belongs to from claims carried in the chain itself. |
| [`@vbel/adapter-identity-static`](packages/adapter-identity-static) | Resolve keys from a list the verifier chooses to trust. |

`core` imports nothing else here. Everything depends on it, never the reverse, so changing chain
means changing one file that satisfies [`LedgerAdapter`](packages/core/src/ledger.ts).

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

## Development

```bash
pnpm install
pnpm build
pnpm test        # every package, no network needed
pnpm typecheck
pnpm example
```

<details>
<summary>Anchoring on a testnet</summary>

Needs a funded testnet key. Copy `.env.example` to `.env`, then:

```bash
set -a && source .env && set +a && pnpm --filter @vbel/adapter-solana smoke:anchor
```

</details>

## Status

**Pre-1.0.** The envelope is frozen at v0.1. Everything above it may change between minor versions.

- **Keys are yours.** Nothing here stores or recovers one.
- **Nothing is persisted.** A chain is data you keep, or carry in a link.

To report a vulnerability see [SECURITY.md](SECURITY.md). To contribute see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Provenance

Extracted from a larger codebase that also holds a demo app and two domain modules (delivery and
payment), which are not part of this repository. [`PROVENANCE.md`](PROVENANCE.md) records, per
package, when it first appeared and last changed, and which files were added after 28 August 2026.
The earlier hackathon submission of the same idea (26 and 27 August 2026) is at
[st3fansrb/vbel](https://github.com/st3fansrb/vbel) and is unchanged.

## License

Apache-2.0. See [LICENSE](LICENSE).
