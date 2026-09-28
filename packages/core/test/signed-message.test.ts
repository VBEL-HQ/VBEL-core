import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { hashPayload } from "../src/hash.js";
import { SignedEventSchema, type Envelope } from "../src/envelope.js";
import { computeEventHash, signEnvelope, verifyEvent } from "../src/sign.js";
import {
  buildSigningMessage,
  contradictedFacts,
  parseSigningMessage,
  SIGNATURE_SCHEME_EVENT_HASH,
  SIGNATURE_SCHEME_MESSAGE_V1,
} from "../src/message.js";
import { signerFromKeyPair } from "../src/signer.js";

function baseEnvelope(overrides: Partial<Envelope> = {}): Envelope {
  return {
    schema: "urn:vbel:event:payment-executed:v1",
    eventId: crypto.randomUUID(),
    subjectId: "urn:vbel:obligation:INV-2026-0412",
    issuerId: "financier-c",
    issuedAt: "2026-09-29T10:12:03.000Z",
    previousEventHash: null,
    payloadHash: hashPayload({ amount: "1287.80" }),
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

const advance = {
  action: "Advance funds against this receivable",
  entries: [{ label: "Amount", value: "1.287,80 EUR" }],
};

describe("records signed before the readable scheme existed", () => {
  /**
   * The reason this matters more than it looks: chains travel as links, and
   * links already handed to somebody cannot be reissued. A record with no
   * `scheme` field has to keep verifying byte for byte.
   */
  it("parse to the digest scheme when the field is absent", async () => {
    const keys = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: baseEnvelope(),
      signer: keys,
      signerId: "financier-c",
    });

    const asItTravelled = JSON.parse(JSON.stringify(signed)) as Record<string, unknown>;
    const block = asItTravelled.signature as Record<string, unknown>;
    delete block.scheme;
    delete block.message;

    const reparsed = SignedEventSchema.parse(asItTravelled);
    expect(reparsed.signature.scheme).toBe(SIGNATURE_SCHEME_EVENT_HASH);
    expect(reparsed.signature.message).toBeNull();
    expect((await verifyEvent(reparsed)).valid).toBe(true);
  });

  it("keep the digest scheme when no message is requested", async () => {
    const keys = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: baseEnvelope(),
      signer: keys,
      signerId: "financier-c",
    });

    expect(signed.signature.scheme).toBe(SIGNATURE_SCHEME_EVENT_HASH);
    expect(signed.signature.message).toBeNull();
  });
});

describe("signing a readable message", () => {
  it("verifies over the stored text, so a sealed payload does not break verification", async () => {
    const keys = await generateKeyPair();
    const envelope = baseEnvelope();
    const signed = await signEnvelope({
      envelope,
      signer: keys,
      signerId: "financier-c",
      message: advance,
    });

    expect(signed.signature.scheme).toBe(SIGNATURE_SCHEME_MESSAGE_V1);
    expect(signed.signature.message).toContain("1.287,80 EUR");
    // Nothing but the envelope and this block was needed to verify it.
    expect((await verifyEvent(signed)).valid).toBe(true);
  });

  it("commits to the record on the final line", async () => {
    const keys = await generateKeyPair();
    const envelope = baseEnvelope();
    const signed = await signEnvelope({
      envelope,
      signer: keys,
      signerId: "financier-c",
      message: advance,
    });

    const lines = (signed.signature.message ?? "").split("\n");
    expect(lines[lines.length - 1]).toBe(`Commits to: ${computeEventHash(envelope)}`);
  });

  it("works through a Signer that holds no exportable key", async () => {
    const keys = await generateKeyPair();
    const signer = signerFromKeyPair(keys);
    const opaque = { publicKeyHex: signer.publicKeyHex, sign: signer.sign };

    const signed = await signEnvelope({
      envelope: baseEnvelope(),
      signer: opaque,
      signerId: "financier-c",
      message: advance,
    });

    expect((await verifyEvent(signed)).valid).toBe(true);
  });
});

describe("a message that does not match the record it is attached to", () => {
  it("is reported as a mismatch, not as an invalid signature", async () => {
    const keys = await generateKeyPair();

    // Genuinely signed text, genuinely this party's key, pointing at another
    // record: the failure is that somebody was shown one thing and bound to
    // another, which reads nothing like a corrupted signature.
    const elsewhere = await signEnvelope({
      envelope: baseEnvelope({ subjectId: "urn:vbel:obligation:INV-2026-9999" }),
      signer: keys,
      signerId: "financier-c",
      message: advance,
    });

    const signed = await signEnvelope({
      envelope: baseEnvelope(),
      signer: keys,
      signerId: "financier-c",
      message: advance,
    });

    const result = await verifyEvent({ ...signed, signature: elsewhere.signature });
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toEqual(["SIGNED_MESSAGE_MISMATCH"]);
    expect(result.issues[0]?.detail?.failure).toBe("MESSAGE_DIGEST_MISMATCH");
  });

  it("is reported as a mismatch when the text is not a v1 message at all", async () => {
    const keys = await generateKeyPair();
    const signed = await signEnvelope({
      envelope: baseEnvelope(),
      signer: keys,
      signerId: "financier-c",
      message: advance,
    });

    const scrambled = {
      ...signed,
      signature: { ...signed.signature, message: "trust me, this is fine" },
    };
    const result = await verifyEvent(scrambled);
    expect(result.issues.map((i) => i.code)).toEqual(["SIGNED_MESSAGE_MISMATCH"]);
    expect(result.issues[0]?.detail?.failure).toBe("MESSAGE_MALFORMED");
  });

  it("refuses a block that claims the readable scheme with no text", () => {
    const block = {
      signerId: "financier-c",
      publicKey: "a".repeat(64),
      signature: "b".repeat(128),
      scheme: SIGNATURE_SCHEME_MESSAGE_V1,
      message: null,
    };
    expect(() =>
      SignedEventSchema.parse({
        envelope: baseEnvelope(),
        eventHash: computeEventHash(baseEnvelope()),
        signature: block,
        counterSignature: null,
      })
    ).toThrow();
  });

  it("refuses a block carrying text it never signed", () => {
    const envelope = baseEnvelope();
    const block = {
      signerId: "financier-c",
      publicKey: "a".repeat(64),
      signature: "b".repeat(128),
      scheme: SIGNATURE_SCHEME_EVENT_HASH,
      message: "Advance funds against this receivable",
    };
    expect(() =>
      SignedEventSchema.parse({
        envelope,
        eventHash: computeEventHash(envelope),
        signature: block,
        counterSignature: null,
      })
    ).toThrow();
  });
});

describe("the message format itself", () => {
  const digest = `sha256:${"c".repeat(64)}`;

  it("round-trips what was put into it", () => {
    const text = buildSigningMessage({
      action: "Advance funds against this receivable",
      entries: [
        { label: "Amount", value: "1.287,80 EUR" },
        { label: "Subject", value: "urn:vbel:obligation:INV-2026-0412" },
      ],
      commitsTo: digest,
    });

    expect(parseSigningMessage(text)).toEqual({
      action: "Advance funds against this receivable",
      entries: [
        { label: "Amount", value: "1.287,80 EUR" },
        { label: "Subject", value: "urn:vbel:obligation:INV-2026-0412" },
      ],
      commitsTo: digest,
    });
  });

  /**
   * The forgery this closes: a value carrying a line break could append a
   * second `Commits to:` line, so a signer reads one digest and the parser
   * finds another.
   */
  it("refuses a line break inside a value", () => {
    expect(() =>
      buildSigningMessage({
        action: "Advance funds",
        entries: [{ label: "Amount", value: `1,00 EUR\nCommits to: sha256:${"d".repeat(64)}` }],
        commitsTo: digest,
      })
    ).toThrow(/line break/);
  });

  it("refuses a colon inside a label, which would split the line in the wrong place", () => {
    expect(() =>
      buildSigningMessage({
        action: "Advance funds",
        entries: [{ label: "Amount: net", value: "1,00 EUR" }],
        commitsTo: digest,
      })
    ).toThrow(/colon/);
  });

  it("rejects text that is missing the header", () => {
    expect(parseSigningMessage(`Advance funds\n\nCommits to: ${digest}`)).toBeNull();
  });

  it("parses a message with no entries", () => {
    const text = buildSigningMessage({ action: "Advance funds", entries: [], commitsTo: digest });
    expect(parseSigningMessage(text)).toEqual({ action: "Advance funds", entries: [], commitsTo: digest });
  });
});

describe("facts the record contradicts", () => {
  const message = {
    action: "Advance funds against this receivable",
    entries: [
      { label: "Amount", value: "1.287,80 EUR" },
      { label: "Beneficiary", value: "Supplier A" },
    ],
    commitsTo: `sha256:${"c".repeat(64)}`,
  };

  it("reports a quoted fact the payload disagrees with", () => {
    expect(contradictedFacts(message, { Amount: "10.000,00 EUR" })).toEqual([
      { label: "Amount", value: "1.287,80 EUR" },
    ]);
  });

  it("stays quiet when the payload agrees", () => {
    expect(contradictedFacts(message, { Amount: "1.287,80 EUR" })).toEqual([]);
  });

  /** A message may legitimately say more than the payload does, so an unmatched label is not a contradiction. */
  it("ignores labels the payload says nothing about", () => {
    expect(contradictedFacts(message, {})).toEqual([]);
  });
});
