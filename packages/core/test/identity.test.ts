import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { hashPayload } from "../src/hash.js";
import type { Envelope } from "../src/envelope.js";
import {
  checkAttestationWindow,
  type IdentityResolver,
  type IssuerAttestation,
} from "../src/identity.js";
import { signAttestation, signEnvelope, verifyEvent } from "../src/sign.js";

const SUPPLIER = "urn:vbel:org:supplier-a";
const AT = "2026-08-25T10:00:00.000Z";

function envelopeFor(issuerId: string, issuedAt = AT): Envelope {
  return {
    schema: "urn:vbel:event:delivery-dispatched:v1",
    eventId: crypto.randomUUID(),
    subjectId: "urn:vbel:shipment:test-1",
    issuerId,
    issuedAt,
    previousEventHash: null,
    payloadHash: hashPayload({ units: 1000 }),
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: "urn:vbel:policy:v1",
    privacy: "off-chain",
    nonce: crypto.randomUUID(),
  };
}

function attestation(overrides: Partial<IssuerAttestation> & { publicKey: string }): IssuerAttestation {
  return {
    issuerId: SUPPLIER,
    attestedBy: "urn:vbel:registry:test",
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: null,
    signature: null,
    ...overrides,
  };
}

/** Minimal resolver — the interface is small enough that tests need no mocking library. */
function resolverFor(attestations: IssuerAttestation[]): IdentityResolver {
  return {
    async resolve(issuerId, at) {
      return (
        attestations.find(
          (a) => a.issuerId === issuerId && checkAttestationWindow(a, at) === "VALID"
        ) ?? null
      );
    },
  };
}

describe("checkAttestationWindow", () => {
  it("treats validUntil as exclusive and validFrom as inclusive", () => {
    const a = attestation({
      publicKey: "aa",
      validFrom: "2026-01-01T00:00:00.000Z",
      validUntil: "2026-06-01T00:00:00.000Z",
    });

    expect(checkAttestationWindow(a, "2025-12-31T23:59:59.000Z")).toBe("NOT_YET_VALID");
    expect(checkAttestationWindow(a, "2026-01-01T00:00:00.000Z")).toBe("VALID");
    expect(checkAttestationWindow(a, "2026-06-01T00:00:00.000Z")).toBe("EXPIRED");
  });

  it("treats a null validUntil as open-ended", () => {
    const a = attestation({ publicKey: "aa", validUntil: null });
    expect(checkAttestationWindow(a, "2099-01-01T00:00:00.000Z")).toBe("VALID");
  });
});

describe("verifyEvent without a resolver", () => {
  it("verifies internal consistency but reports that identity was never checked", async () => {
    const supplier = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor(SUPPLIER),
      signer: supplier,
      signerId: SUPPLIER,
    });

    const result = await verifyEvent(signed);

    expect(result.valid).toBe(true);
    expect(result.identityChecked).toBe(false);
    expect(result.attestation).toBeNull();
  });

  it("accepts an impostor, because internal consistency is all it can prove", async () => {
    const impostor = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor(SUPPLIER),
      signer: impostor,
      signerId: SUPPLIER,
    });

    // This is the gap the identity layer closes: nothing here is wrong
    // internally, and without a resolver nothing can say otherwise.
    const result = await verifyEvent(signed);
    expect(result.valid).toBe(true);
    expect(result.identityChecked).toBe(false);
  });
});

describe("verifyEvent with a resolver", () => {
  it("confirms an event signed with the attested key", async () => {
    const supplier = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor(SUPPLIER),
      signer: supplier,
      signerId: SUPPLIER,
    });
    const resolver = resolverFor([attestation({ publicKey: supplier.publicKeyHex })]);

    const result = await verifyEvent(signed, resolver);

    expect(result.valid).toBe(true);
    expect(result.identityChecked).toBe(true);
    expect(result.attestation?.publicKey).toBe(supplier.publicKeyHex);
  });

  it("rejects an impostor signing under someone else's issuerId", async () => {
    const supplier = await generateKeyPair();
    const impostor = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor(SUPPLIER),
      signer: impostor,
      signerId: SUPPLIER,
    });
    const resolver = resolverFor([attestation({ publicKey: supplier.publicKeyHex })]);

    const result = await verifyEvent(signed, resolver);

    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain("ISSUER_KEY_MISMATCH");
  });

  it("reports an issuer the registry has never heard of", async () => {
    const stranger = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor("urn:vbel:org:who-is-this"),
      signer: stranger,
      signerId: "urn:vbel:org:who-is-this",
    });

    const result = await verifyEvent(signed, resolverFor([]));

    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toEqual(["ISSUER_UNKNOWN"]);
  });

  it("rejects an event signed after its attestation expired", async () => {
    const supplier = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor(SUPPLIER, "2026-08-25T10:00:00.000Z"),
      signer: supplier,
      signerId: SUPPLIER,
    });
    // The resolver still returns it, as a registry serving historical records
    // would; core is what decides the window does not cover this event.
    const expired = attestation({
      publicKey: supplier.publicKeyHex,
      validUntil: "2026-06-01T00:00:00.000Z",
    });

    const result = await verifyEvent(signed, { async resolve() { return expired; } });

    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain("ATTESTATION_EXPIRED");
  });

  it("verifies a signed attestation, and rejects one that was altered", async () => {
    const supplier = await generateKeyPair();
    const registrar = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: envelopeFor(SUPPLIER),
      signer: supplier,
      signerId: SUPPLIER,
    });

    const attested = await signAttestation({
      attestation: attestation({ publicKey: supplier.publicKeyHex }),
      signer: registrar,
      signerId: "urn:vbel:registry:test",
    });

    expect((await verifyEvent(signed, resolverFor([attested]))).valid).toBe(true);

    // Widen the validity window without re-signing — the kind of edit a
    // relaying party could attempt on an attestation in transit.
    const altered = { ...attested, validUntil: "2099-01-01T00:00:00.000Z" };
    const result = await verifyEvent(signed, resolverFor([altered]));

    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain("ATTESTATION_SIGNATURE_INVALID");
  });
});
