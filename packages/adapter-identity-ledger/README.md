# @vbel/adapter-identity-ledger

An `IdentityResolver` over registrations carried in the chain itself, so a reader learns whose key signed a
record from the link alone and no registry has to be fetched.

```bash
pnpm add @vbel/adapter-identity-ledger
```

```ts
import { LedgerIdentityRegistry } from "@vbel/adapter-identity-ledger";

// `registrations` are the EntityRegistrationPayloads found in the chain.
const resolver = new LedgerIdentityRegistry(registrations);
const attestation = await resolver.resolve("urn:example:org:supplier", event.envelope.issuedAt);
```

A registration is a claim somebody signed and sent along. That makes it inspectable, not true. A key that
has only vouched for itself is `self-asserted`; a vouch from a key the verifier already trusts is what
raises it. A vouch can corroborate a key and can never introduce one.

Most applications reach this through `buildIdentityContext` in
[`@vbel/records`](https://github.com/VBEL-HQ/VBEL-core/tree/main/packages/records) rather than directly.

## Part of VBEL

Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public
chain. The [repository readme](https://github.com/VBEL-HQ/VBEL-core#readme) says what that does and
does not prove.

Apache-2.0.
