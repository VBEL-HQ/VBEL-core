import { describe, expect, it } from "vitest";
import { hashPayload } from "../src/hash.js";
import { diffPayloads, verifyPayload } from "../src/payload.js";
import type { Envelope } from "../src/envelope.js";

const payload = { shipmentRef: "SHP-1", lines: [{ sku: "SKU-1", quantityAccepted: 940 }] };

function envelopeFor(p: unknown): Envelope {
  return {
    schema: "urn:vbel:event:delivery-accepted:v1",
    eventId: "evt-1",
    subjectId: "urn:vbel:shipment:SHP-1",
    issuerId: "urn:vbel:org:buyer-b",
    issuedAt: "2026-08-26T14:02:00Z",
    previousEventHash: null,
    payloadHash: hashPayload(p),
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: "urn:vbel:policy:v1",
    privacy: "off-chain",
    nonce: "n-1",
  };
}

describe("verifyPayload", () => {
  it("accepts the payload the envelope committed to", () => {
    expect(verifyPayload(payload, envelopeFor(payload)).valid).toBe(true);
  });

  it("rejects a payload edited after signing", () => {
    const envelope = envelopeFor(payload);
    const tampered = { ...payload, lines: [{ sku: "SKU-1", quantityAccepted: 1000 }] };

    const result = verifyPayload(tampered, envelope);
    expect(result.valid).toBe(false);
    expect(result.actual).not.toBe(result.expected);
  });

  it("is insensitive to key order, since hashing is canonical", () => {
    const reordered = { lines: [{ quantityAccepted: 940, sku: "SKU-1" }], shipmentRef: "SHP-1" };
    expect(verifyPayload(reordered, envelopeFor(payload)).valid).toBe(true);
  });
});

describe("diffPayloads", () => {
  it("names the exact path of a changed nested value", () => {
    const tampered = { ...payload, lines: [{ sku: "SKU-1", quantityAccepted: 1000 }] };
    const differences = diffPayloads(payload, tampered);

    expect(differences).toEqual([
      { path: "$.lines[0].quantityAccepted", expected: 940, actual: 1000 },
    ]);
  });

  it("returns nothing for identical payloads", () => {
    expect(diffPayloads(payload, { ...payload })).toEqual([]);
  });

  it("reports an added field as a difference against undefined", () => {
    const differences = diffPayloads({ a: 1 }, { a: 1, b: 2 });
    expect(differences).toEqual([{ path: "$.b", expected: undefined, actual: 2 }]);
  });

  it("reports length changes in arrays", () => {
    const differences = diffPayloads({ xs: [1] }, { xs: [1, 2] });
    expect(differences).toEqual([{ path: "$.xs[1]", expected: undefined, actual: 2 }]);
  });
});
