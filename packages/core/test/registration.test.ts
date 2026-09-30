import { describe, expect, it } from "vitest";
import {
  SCHEMA_ENTITY_REGISTERED,
  subjectIdForEntity,
  EntityRegistrationPayloadSchema,
  assuranceOf,
  buildEntityRegistrationEnvelope,
  buildEntityRevocationEnvelope,
  honoursRevocation,
  type EntityRegistrationPayload,
} from "../src/registration.js";
import { hashPayload } from "../src/hash.js";

const VALID_PUBLIC_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ENTITY_ID = "org:bank-a";
const REGISTERED_AT = "2026-01-01T00:00:00.000Z";

const basePayload: EntityRegistrationPayload = {
  entityId: ENTITY_ID,
  displayName: "Bank A",
  publicKey: VALID_PUBLIC_KEY,
  role: "payee",
  registeredAt: REGISTERED_AT,
  validUntil: null,
  attestedBy: null,
};

describe("subjectIdForEntity", () => {
  it("formats entity identifier with the correct URN prefix", () => {
    expect(subjectIdForEntity("org:bank-a")).toBe("urn:vbel:entity:org:bank-a");
    expect(subjectIdForEntity("supplier-123")).toBe("urn:vbel:entity:supplier-123");
  });
});

describe("EntityRegistrationPayloadSchema", () => {
  it("parses a valid registration payload", () => {
    const result = EntityRegistrationPayloadSchema.parse(basePayload);
    expect(result).toEqual(basePayload);
  });

  it("applies default values for optional nullable fields when missing", () => {
    const minimalInput = {
      entityId: ENTITY_ID,
      displayName: "Bank A",
      publicKey: VALID_PUBLIC_KEY,
      registeredAt: REGISTERED_AT,
    };
    const result = EntityRegistrationPayloadSchema.parse(minimalInput);
    expect(result.role).toBeNull();
    expect(result.validUntil).toBeNull();
    expect(result.attestedBy).toBeNull();
  });

  it("rejects invalid public key formats", () => {
    const invalidKeys = [
      "not-a-hex-string",
      "0123456789abcdef", // too short (16 chars)
      VALID_PUBLIC_KEY + "00", // too long (66 chars)
      VALID_PUBLIC_KEY.slice(0, 63) + "Z", // non-hex character
    ];

    for (const publicKey of invalidKeys) {
      expect(() =>
        EntityRegistrationPayloadSchema.parse({
          ...basePayload,
          publicKey,
        })
      ).toThrow();
    }
  });

  it("rejects empty strings for entityId and displayName", () => {
    expect(() =>
      EntityRegistrationPayloadSchema.parse({
        ...basePayload,
        entityId: "",
      })
    ).toThrow();

    expect(() =>
      EntityRegistrationPayloadSchema.parse({
        ...basePayload,
        displayName: "",
      })
    ).toThrow();
  });

  it("rejects invalid datetime strings for registeredAt or validUntil", () => {
    expect(() =>
      EntityRegistrationPayloadSchema.parse({
        ...basePayload,
        registeredAt: "invalid-date",
      })
    ).toThrow();

    expect(() =>
      EntityRegistrationPayloadSchema.parse({
        ...basePayload,
        validUntil: "2026-13-45", // invalid ISO
      })
    ).toThrow();
  });
});

describe("assuranceOf", () => {
  it("returns 'self-asserted' when attestedBy is null", () => {
    const payload = { ...basePayload, attestedBy: null };
    expect(assuranceOf(payload)).toBe("self-asserted");
  });

  it("returns 'vouched' when attestedBy is specified", () => {
    const payload = { ...basePayload, attestedBy: "urn:vbel:org:notary" };
    expect(assuranceOf(payload)).toBe("vouched");
  });
});

describe("buildEntityRegistrationEnvelope", () => {
  it("builds an envelope for a self-asserted entity registration", () => {
    const envelope = buildEntityRegistrationEnvelope({ payload: basePayload });

    expect(envelope.schema).toBe(SCHEMA_ENTITY_REGISTERED);
    expect(envelope.subjectId).toBe("urn:vbel:entity:org:bank-a");
    expect(envelope.issuerId).toBe(ENTITY_ID);
    expect(envelope.issuedAt).toBe(REGISTERED_AT);
    expect(envelope.previousEventHash).toBeNull();
    expect(envelope.payloadHash).toBe(hashPayload(basePayload));
    expect(envelope.status).toBe("ACTIVE");
    expect(envelope.supersedes).toBeNull();
    expect(envelope.supersedeReason).toBeNull();
    expect(envelope.revokes).toBeNull();
    expect(envelope.revokeReason).toBeNull();
    expect(envelope.policyId).toBe("urn:vbel:policy:v1");
    expect(envelope.privacy).toBe("off-chain");
    expect(envelope.eventId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
    expect(envelope.nonce).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
  });

  it("uses attestedBy as issuerId for vouched registrations", () => {
    const voucherId = "urn:vbel:org:notary";
    const vouchedPayload = { ...basePayload, attestedBy: voucherId };
    const envelope = buildEntityRegistrationEnvelope({ payload: vouchedPayload });

    expect(envelope.issuerId).toBe(voucherId);
  });

  it("allows custom parameters for issuedAt, previousEventHash, and policyId", () => {
    const customIssuedAt = "2026-02-01T12:00:00.000Z";
    const previousEventHash = "abc123def456";
    const policyId = "urn:vbel:policy:custom:v2";

    const envelope = buildEntityRegistrationEnvelope({
      payload: basePayload,
      issuedAt: customIssuedAt,
      previousEventHash,
      policyId,
    });

    expect(envelope.issuedAt).toBe(customIssuedAt);
    expect(envelope.previousEventHash).toBe(previousEventHash);
    expect(envelope.policyId).toBe(policyId);
  });

  it("validates the payload before constructing the envelope", () => {
    const invalidPayload = { ...basePayload, publicKey: "invalid" };
    expect(() =>
      buildEntityRegistrationEnvelope({ payload: invalidPayload as EntityRegistrationPayload })
    ).toThrow();
  });
});

describe("buildEntityRevocationEnvelope", () => {
  it("builds an envelope for an entity revocation", () => {
    const revokesEventId = "event-12345";
    const revokeReason = "key compromised";
    const issuerId = ENTITY_ID;
    const previousEventHash = "hash-999";

    const envelope = buildEntityRevocationEnvelope({
      payload: basePayload,
      revokes: revokesEventId,
      revokeReason,
      issuerId,
      previousEventHash,
    });

    expect(envelope.schema).toBe(SCHEMA_ENTITY_REGISTERED);
    expect(envelope.subjectId).toBe("urn:vbel:entity:org:bank-a");
    expect(envelope.issuerId).toBe(issuerId);
    expect(envelope.previousEventHash).toBe(previousEventHash);
    expect(envelope.payloadHash).toBe(hashPayload(basePayload));
    expect(envelope.status).toBe("REVOKED");
    expect(envelope.revokes).toBe(revokesEventId);
    expect(envelope.revokeReason).toBe(revokeReason);
    expect(envelope.policyId).toBe("urn:vbel:policy:v1");
    expect(envelope.privacy).toBe("off-chain");
    expect(typeof envelope.issuedAt).toBe("string");
    expect(new Date(envelope.issuedAt).toString()).not.toBe("Invalid Date");
  });

  it("allows overriding issuedAt and policyId on revocation", () => {
    const customIssuedAt = "2026-03-01T00:00:00.000Z";
    const policyId = "urn:vbel:policy:custom";

    const envelope = buildEntityRevocationEnvelope({
      payload: basePayload,
      revokes: "event-1",
      revokeReason: "key rotated",
      issuerId: ENTITY_ID,
      previousEventHash: "hash-0",
      issuedAt: customIssuedAt,
      policyId,
    });

    expect(envelope.issuedAt).toBe(customIssuedAt);
    expect(envelope.policyId).toBe(policyId);
  });
});

describe("honoursRevocation", () => {
  it("returns true when revocation issuer matches revoked claim issuer", () => {
    const issuer = "urn:vbel:org:bank-a";
    expect(honoursRevocation(issuer, issuer)).toBe(true);
  });

  it("returns false when revocation issuer differs from revoked claim issuer", () => {
    const claimIssuer = "urn:vbel:org:bank-a";
    const intruderIssuer = "urn:vbel:org:attacker";
    expect(honoursRevocation(intruderIssuer, claimIssuer)).toBe(false);
  });
});
