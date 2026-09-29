# @vbel/adapter-identity-static

An `IdentityResolver` over a list the verifier chooses to trust. The trust root is the list itself, so where
it comes from is a decision for whoever runs the check.

```bash
pnpm add @vbel/adapter-identity-static
```

```ts
import { StaticIdentityRegistry } from "@vbel/adapter-identity-static";

// `raw` is untrusted JSON, such as a file on disk or a network response. It is validated before use.
const resolver = StaticIdentityRegistry.fromJSON(raw);
const attestation = await resolver.resolve("urn:example:org:supplier", event.envelope.issuedAt);
```

An issuer can hold several attestations with non-overlapping windows, which is how key rotation is
expressed: an old event keeps resolving to the key that was in force when it was signed.

A resolver backed by a directory, ENS text records or a certificate chain satisfies the same interface, so
events verified against this one stay verifiable against those without re-signing anything.

## Part of VBEL

Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public
chain. The [repository readme](https://github.com/VBEL-HQ/VBEL-core#readme) says what that does and
does not prove.

Apache-2.0.
