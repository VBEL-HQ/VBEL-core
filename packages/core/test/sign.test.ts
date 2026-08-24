import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { hashPayload } from "../src/hash.js";
import type { Envelope } from "../src/envelope.js";
import {
  counterSignPreviousEvent,
  signEnvelope,
  verifyCounterSignature,
  verifyEnvelopeSignature,
  verifyEvent,
} from "../src/sign.js";

function baseEnvelope(overrides: Partial<Envelope>): Envelope {
  return {
    schema: "urn:vbel:event:delivery-dispatched:v1",
    eventId: crypto.randomUUID(),
    subjectId: "urn:vbel:shipment:test-1",
    issuerId: "urn:vbel:org:supplier-a",
    issuedAt: new Date().toISOString(),
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
    ...overrides,
  };
}

describe("signEnvelope / verifyEnvelopeSignature", () => {
  it("round-trips a single signed event", async () => {
    const supplier = await generateKeyPair();
    const envelope = baseEnvelope({});
    const signed = await signEnvelope({ envelope, signer: supplier, signerId: "urn:vbel:org:supplier-a" });

    expect(await verifyEnvelopeSignature(signed)).toBe(true);
  });

  it("fails verification when the payload is tampered with after signing", async () => {
    const supplier = await generateKeyPair();
    const envelope = baseEnvelope({});
    const signed = await signEnvelope({ envelope, signer: supplier, signerId: "urn:vbel:org:supplier-a" });

    const tampered = { ...signed, envelope: { ...signed.envelope, payloadHash: hashPayload({ units: 1_000_000 }) } };
    const result = await verifyEvent(tampered);

    expect(result.valid).toBe(false);
    expect(result.issues.join(" ")).toMatch(/eventHash does not match/);
  });

  it("fails verification with the wrong signer's key", async () => {
    const supplier = await generateKeyPair();
    const impostor = await generateKeyPair();
    const envelope = baseEnvelope({});
    const signed = await signEnvelope({ envelope, signer: supplier, signerId: "urn:vbel:org:supplier-a" });

    const swapped = { ...signed, signature: { ...signed.signature, publicKey: impostor.publicKeyHex } };
    expect(await verifyEnvelopeSignature(swapped)).toBe(false);
  });
});

describe("counter-signing (dispatch -> acceptance)", () => {
  it("the buyer counter-signs the dispatch event they are accepting", async () => {
    const supplier = await generateKeyPair();
    const buyer = await generateKeyPair();

    const dispatchEnvelope = baseEnvelope({ payloadHash: hashPayload({ units: 1000 }) });
    const dispatch = await signEnvelope({
      envelope: dispatchEnvelope,
      signer: supplier,
      signerId: "urn:vbel:org:supplier-a",
    });

    const acceptanceEnvelope = baseEnvelope({
      schema: "urn:vbel:event:delivery-accepted:v1",
      issuerId: "urn:vbel:org:buyer-b",
      previousEventHash: dispatch.eventHash,
      payloadHash: hashPayload({ units: 940, discrepancy: 60 }),
    });
    let acceptance = await signEnvelope({
      envelope: acceptanceEnvelope,
      signer: buyer,
      signerId: "urn:vbel:org:buyer-b",
    });
    acceptance = await counterSignPreviousEvent({
      signed: acceptance,
      counterSigner: buyer,
      signerId: "urn:vbel:org:buyer-b",
    });

    expect(await verifyEnvelopeSignature(acceptance)).toBe(true);
    expect(await verifyCounterSignature(acceptance)).toBe(true);
    expect((await verifyEvent(acceptance)).valid).toBe(true);

    // the counter-signature attests to the dispatch content specifically
    expect(acceptance.counterSignature?.signature).not.toBe(acceptance.signature.signature);
  });

  it("refuses to counter-sign an event with no previousEventHash", async () => {
    const buyer = await generateKeyPair();
    const orphan = await signEnvelope({
      envelope: baseEnvelope({}),
      signer: buyer,
      signerId: "urn:vbel:org:buyer-b",
    });

    await expect(
      counterSignPreviousEvent({ signed: orphan, counterSigner: buyer, signerId: "urn:vbel:org:buyer-b" })
    ).rejects.toThrow(/previousEventHash is null/);
  });
});
