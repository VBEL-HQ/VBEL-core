# @vbel/core

The record format and the cryptography under it. No I/O, no network, and it imports nothing else in VBEL.

```bash
pnpm add @vbel/core
```

## What it does

- **Envelope.** The signed event format, frozen at v0.1 ([`envelope.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/envelope.ts)).
- **Canonical JSON and hashing.** RFC 8785, so two implementations hash the same object to the same bytes
  ([`canonicalize.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/canonicalize.ts),
  [`hash.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/hash.ts)).
- **Signing and verification.** ed25519 over the event hash, counter-signing, and verification that reports
  what failed rather than only that something did
  ([`sign.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/sign.ts)).
- **Signers.** A `KeyPair` you hold, or any `Signer` such as a wallet that only exposes `signMessage`
  ([`signer.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/signer.ts)).
- **Chains.** Linking, ordering and lifecycle: corrections supersede, revocations follow the claim they
  withdraw, and nothing is deleted
  ([`lifecycle.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/lifecycle.ts)).
- **Identity.** Registration and attestation primitives, with the assurance of a name kept apart from the
  validity of a signature.
- **Anchoring authorisation.** A proof that the requester holds a key that signed the record
  ([`anchor-auth.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/core/src/anchor-auth.ts)).

## Sign one event and check it

```ts
import { generateKeyPair, hashPayload, signEnvelope, verifyEnvelopeSignature, type Envelope } from "@vbel/core";

const keys = await generateKeyPair();
const payload = { orderRef: "PO-1001", quantity: 500 };

const envelope: Envelope = {
  schema: "urn:example:event:order-note:v1",
  eventId: crypto.randomUUID(),
  subjectId: "urn:example:order:PO-1001",
  issuerId: "urn:example:org:supplier",
  issuedAt: new Date().toISOString(),
  previousEventHash: null, // the eventHash of the record before this one, or null for the first
  payloadHash: hashPayload(payload),
  status: "ACTIVE",
  supersedes: null,
  supersedeReason: null,
  revokes: null,
  revokeReason: null,
  policyId: "urn:example:policy:v1",
  privacy: "off-chain",
  nonce: crypto.randomUUID(),
};

const event = await signEnvelope({ envelope, signer: keys, signerId: envelope.issuerId });
await verifyEnvelopeSignature(event); // true
```

The envelope commits to the payload by hash and never contains it, which is what lets a payload be
withheld later without breaking the chain. To carry records between parties, see
[`@vbel/records`](https://github.com/VBEL-HQ/VBEL-core/tree/main/packages/records).

## Part of VBEL

Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public
chain. The [repository readme](https://github.com/VBEL-HQ/VBEL-core#readme) says what that does and
does not prove.

Apache-2.0.
