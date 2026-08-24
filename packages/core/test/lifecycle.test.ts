import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { hashPayload } from "../src/hash.js";
import type { Envelope } from "../src/envelope.js";
import { signEnvelope } from "../src/sign.js";
import { validateChain } from "../src/lifecycle.js";

function envelope(overrides: Partial<Envelope>): Envelope {
  return {
    schema: "urn:vbel:event:delivery-dispatched:v1",
    eventId: crypto.randomUUID(),
    subjectId: "urn:vbel:shipment:test-1",
    issuerId: "urn:vbel:org:supplier-a",
    issuedAt: new Date().toISOString(),
    previousEventHash: null,
    payloadHash: hashPayload({}),
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: "urn:vbel:policy:v1",
    privacy: "off-chain",
    nonce: crypto.randomUUID(),
    ...overrides,
  };
}

describe("validateChain / deriveStatus", () => {
  it("walks dispatch -> acceptance -> correction and marks the acceptance SUPERSEDED", async () => {
    const supplier = await generateKeyPair();
    const buyer = await generateKeyPair();

    const dispatch = await signEnvelope({
      envelope: envelope({ payloadHash: hashPayload({ units: 1000 }) }),
      signer: supplier,
      signerId: "supplier-a",
    });

    const acceptance = await signEnvelope({
      envelope: envelope({
        previousEventHash: dispatch.eventHash,
        payloadHash: hashPayload({ units: 1000 }), // wrong on the wire, discovered later
        issuedAt: new Date(Date.now() + 1000).toISOString(),
      }),
      signer: buyer,
      signerId: "buyer-b",
    });

    const correction = await signEnvelope({
      envelope: envelope({
        schema: "urn:vbel:event:delivery-accepted:v1",
        previousEventHash: acceptance.eventHash,
        payloadHash: hashPayload({ units: 940, discrepancy: 60 }),
        supersedes: acceptance.envelope.eventId,
        supersedeReason: "short-shipped case discovered at store level",
        issuedAt: new Date(Date.now() + 2000).toISOString(),
      }),
      signer: buyer,
      signerId: "buyer-b",
    });

    const result = validateChain([dispatch, acceptance, correction]);

    expect(result.valid).toBe(true);
    expect(result.derivedStatus.get(dispatch.envelope.eventId)).toBe("ACTIVE");
    expect(result.derivedStatus.get(acceptance.envelope.eventId)).toBe("SUPERSEDED");
    expect(result.derivedStatus.get(correction.envelope.eventId)).toBe("ACTIVE");

    // both the superseded and the active record remain in the chain and still verify structurally
    expect([dispatch, acceptance, correction].every((e) => e.eventHash.startsWith("sha256:"))).toBe(true);
  });

  it("flags a broken previousEventHash link", async () => {
    const supplier = await generateKeyPair();
    const dispatch = await signEnvelope({
      envelope: envelope({}),
      signer: supplier,
      signerId: "supplier-a",
    });
    const orphanChild = await signEnvelope({
      envelope: envelope({ previousEventHash: "sha256:" + "0".repeat(64) }),
      signer: supplier,
      signerId: "supplier-a",
    });

    const result = validateChain([dispatch, orphanChild]);
    expect(result.valid).toBe(false);
    expect(result.issues[0]?.message).toMatch(/does not match any known event/);
  });

  it("flags a supersedes reference to an unknown eventId", async () => {
    const supplier = await generateKeyPair();
    const lone = await signEnvelope({
      envelope: envelope({ supersedes: "nonexistent-event-id" }),
      signer: supplier,
      signerId: "supplier-a",
    });

    const result = validateChain([lone]);
    expect(result.valid).toBe(false);
    expect(result.issues[0]?.message).toMatch(/supersedes references unknown eventId/);
  });
});
