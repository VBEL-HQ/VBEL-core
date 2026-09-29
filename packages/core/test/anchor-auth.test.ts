import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { hashPayload } from "../src/hash.js";
import type { Envelope } from "../src/envelope.js";
import { counterSignPreviousEvent, signEnvelope } from "../src/sign.js";
import {
  ANCHOR_PROOF_WINDOW_MS,
  anchorAuthority,
  authoriseAnchorRequest,
  signAnchorRequest,
} from "../src/anchor-auth.js";

function envelope(overrides: Partial<Envelope> = {}): Envelope {
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

async function fixture() {
  const issuer = await generateKeyPair();
  const event = await signEnvelope({ envelope: envelope(), signer: issuer, signerId: "urn:vbel:org:supplier-a" });
  return { issuer, event };
}

describe("authoriseAnchorRequest", () => {
  it("accepts the issuer asking for their own record", async () => {
    const { issuer, event } = await fixture();
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer });
    const result = await authoriseAnchorRequest({ event, chain: "solana", proof });
    expect(result).toEqual({ ok: true, eventHash: event.eventHash, signedAs: "issuer" });
  });

  it("accepts the counter-signer, who also put their name to the record", async () => {
    const issuer = await generateKeyPair();
    const buyer = await generateKeyPair();
    const first = await signEnvelope({ envelope: envelope(), signer: issuer, signerId: "urn:vbel:org:supplier-a" });
    const second = await counterSignPreviousEvent({
      signed: await signEnvelope({
        envelope: envelope({ previousEventHash: first.eventHash, issuerId: "urn:vbel:org:buyer-b" }),
        signer: buyer,
        signerId: "urn:vbel:org:buyer-b",
      }),
      counterSigner: issuer,
      signerId: "urn:vbel:org:supplier-a",
    });
    const proof = await signAnchorRequest({ eventHash: second.eventHash, chain: "ethereum", signer: issuer });
    const result = await authoriseAnchorRequest({ event: second, chain: "ethereum", proof });
    expect(result).toMatchObject({ ok: true, signedAs: "counter-signer" });
  });

  it("refuses someone who holds the link and not a key that signed", async () => {
    const { event } = await fixture();
    const stranger = await generateKeyPair();
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: stranger });
    expect(await authoriseAnchorRequest({ event, chain: "solana", proof })).toEqual({
      ok: false,
      refusal: "NOT_A_SIGNER",
    });
  });

  it("refuses a proof that names the issuer's key without holding it", async () => {
    const { issuer, event } = await fixture();
    const stranger = await generateKeyPair();
    const forged = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: stranger });
    forged.publicKey = issuer.publicKeyHex;
    expect(await authoriseAnchorRequest({ event, chain: "solana", proof: forged })).toEqual({
      ok: false,
      refusal: "BAD_PROOF",
    });
  });

  it("does not let a proof for one chain pay for the other", async () => {
    const { issuer, event } = await fixture();
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer });
    expect(await authoriseAnchorRequest({ event, chain: "ethereum", proof })).toEqual({
      ok: false,
      refusal: "BAD_PROOF",
    });
  });

  it("does not let a proof for one record pay for another", async () => {
    const { issuer, event } = await fixture();
    const other = await signEnvelope({ envelope: envelope(), signer: issuer, signerId: "urn:vbel:org:supplier-a" });
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer });
    expect(await authoriseAnchorRequest({ event: other, chain: "solana", proof })).toEqual({
      ok: false,
      refusal: "BAD_PROOF",
    });
  });

  it("refuses an event whose contents no longer match its hash", async () => {
    const { issuer, event } = await fixture();
    const tampered = { ...event, envelope: { ...event.envelope, subjectId: "urn:vbel:shipment:someone-else" } };
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer });
    expect(await authoriseAnchorRequest({ event: tampered, chain: "solana", proof })).toEqual({
      ok: false,
      refusal: "EVENT_INVALID",
    });
  });

  it("refuses something that is not an event", async () => {
    const issuer = await generateKeyPair();
    const proof = await signAnchorRequest({ eventHash: "sha256:" + "0".repeat(64), chain: "solana", signer: issuer });
    expect(await authoriseAnchorRequest({ event: { hello: "world" }, chain: "solana", proof })).toEqual({
      ok: false,
      refusal: "MALFORMED_EVENT",
    });
  });

  it("refuses a captured request once it has gone stale", async () => {
    const { issuer, event } = await fixture();
    const then = new Date(Date.now() - ANCHOR_PROOF_WINDOW_MS - 1000);
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer, now: then });
    expect(await authoriseAnchorRequest({ event, chain: "solana", proof })).toEqual({ ok: false, refusal: "STALE" });
  });

  it("refuses a request dated well into the future", async () => {
    const { issuer, event } = await fixture();
    const later = new Date(Date.now() + ANCHOR_PROOF_WINDOW_MS + 1000);
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer, now: later });
    expect(await authoriseAnchorRequest({ event, chain: "solana", proof })).toEqual({
      ok: false,
      refusal: "FROM_THE_FUTURE",
    });
  });

  it("tolerates ordinary clock drift", async () => {
    const { issuer, event } = await fixture();
    const drifted = new Date(Date.now() - 60_000);
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer, now: drifted });
    expect((await authoriseAnchorRequest({ event, chain: "solana", proof })).ok).toBe(true);
  });

  it("refuses a malformed signature without throwing", async () => {
    const { issuer, event } = await fixture();
    const proof = await signAnchorRequest({ eventHash: event.eventHash, chain: "solana", signer: issuer });
    expect(await authoriseAnchorRequest({ event, chain: "solana", proof: { ...proof, signature: "zz" } })).toEqual({
      ok: false,
      refusal: "BAD_PROOF",
    });
  });
});

describe("anchorAuthority", () => {
  it("finds the key that signed the record among the ones held", async () => {
    const { issuer, event } = await fixture();
    const other = await generateKeyPair();
    expect(anchorAuthority(event, [other, issuer])?.publicKeyHex).toBe(issuer.publicKeyHex);
  });

  it("finds nothing when none of the held keys signed it", async () => {
    const { event } = await fixture();
    expect(anchorAuthority(event, [await generateKeyPair()])).toBeNull();
  });
});
