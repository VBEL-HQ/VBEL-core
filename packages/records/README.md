# @vbel/records

What makes `@vbel/core` usable in an application: a chain whose payloads may be withheld, a link codec, a
verdict for every record, selective disclosure, and identity claims that travel with the chain. It is
domain-neutral: the shape of what a record says is yours.

```bash
pnpm add @vbel/records @vbel/core zod
```

## What it does

- **Link codec.** `encodeWithIdentity` and `decodeChain` turn a chain into a compact string and back, and
  refuse anything your schemas do not describe
  ([`codec.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/records/src/codec.ts)).
- **Verdicts.** `verifyAll` gives every record a signature result, a payload state (`verified`, `withheld`
  or `mismatch`), the fields that differ, and who signed with how much assurance
  ([`verify.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/records/src/verify.ts)).
- **Selective disclosure.** `redactChain` withholds payloads, and a signed cover sheet records what was shown
  ([`disclosure.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/records/src/disclosure.ts)).
- **Identity that travels.** Self-registrations, vouches and revocations are records in the same chain, so a
  reader resolves who signed from the link alone
  ([`registration.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/records/src/registration.ts)).
- **Handoff.** Fits a chain and its registrations into what a QR code can carry
  ([`handoff.ts`](https://github.com/VBEL-HQ/VBEL-core/blob/main/packages/records/src/handoff.ts)).

## Check a link

```ts
import { validateChain } from "@vbel/core";
import { buildIdentityContext, decodeChain, registrationsIn, splitHandoff, verifyAll } from "@vbel/records";

// `OrderNote` is your own zod schema, keyed by the schema URN your records carry.
const decoded = await decodeChain(link, { [SCHEMA_ORDER_NOTE]: OrderNote });
const { records, registrations } = splitHandoff(decoded);

validateChain(records.map((r) => r.event)).valid;
const verdicts = await verifyAll(records, buildIdentityContext(registrationsIn(registrations)));

for (const record of records) {
  const v = verdicts.get(record.event.envelope.eventId)!;
  console.log(v.signatureValid, v.payloadState, v.differences, v.identity);
}
```

A complete program that signs on one side and checks on the other is in
[`examples/verify-in-your-app`](https://github.com/VBEL-HQ/VBEL-core/tree/main/examples/verify-in-your-app).

A valid check means the records were not changed after signing, in this order, by this key. It does not
mean that what they say is true.

## Part of VBEL

Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public
chain. The [repository readme](https://github.com/VBEL-HQ/VBEL-core#readme) says what that does and
does not prove.

Apache-2.0.
