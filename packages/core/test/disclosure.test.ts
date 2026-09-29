import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signEnvelope, verifyEvent } from "../src/sign.js";
import { validateChain } from "../src/lifecycle.js";
import {
  buildDisclosureEnvelope,
  newDisclosureSubjectId,
  type DisclosurePayload,
} from "../src/disclosure.js";
import type { Envelope, SignedEvent } from "../src/envelope.js";
import { hashPayload } from "../src/hash.js";

const ISSUER = "urn:vbel:org:payee";
const SUBJECT = "urn:vbel:obligation:OBL-1";

function businessEnvelope(previousEventHash: string | null, issuedAt: string): Envelope {
  const payload = { note: `event at ${issuedAt}` };
  return {
    schema: "urn:vbel:event:payment-obligation:v1",
    eventId: crypto.randomUUID(),
    subjectId: SUBJECT,
    issuerId: ISSUER,
    issuedAt,
    previousEventHash,
    payloadHash: hashPayload(payload),
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

async function twoRecordChain() {
  const keys = await generateKeyPair();
  const first = await signEnvelope({
    envelope: businessEnvelope(null, "2026-09-01T10:00:00.000Z"),
    signer: keys,
    signerId: ISSUER,
  });
  const second = await signEnvelope({
    envelope: businessEnvelope(first.eventHash, "2026-09-02T10:00:00.000Z"),
    signer: keys,
    signerId: ISSUER,
  });
  return { keys, chain: [first, second], head: second };
}

function disclosurePayload(headHash: string, recipient: string, revealed: string[]): DisclosurePayload {
  return {
    disclosedSubjectId: SUBJECT,
    disclosedHeadHash: headHash,
    revealedEventIds: revealed,
    withheldEventIds: [],
    recipient,
    disclosedBy: ISSUER,
    disclosedAt: "2026-09-03T10:00:00.000Z",
    inResponseTo: null,
  };
}

async function sign(envelope: Envelope, keys: Awaited<ReturnType<typeof generateKeyPair>>): Promise<SignedEvent> {
  return signEnvelope({ envelope, signer: keys, signerId: ISSUER });
}

describe("a disclosure record alongside the chain it discloses", () => {
  it("does not break validateChain, because it sits on its own subject", async () => {
    const { keys, chain, head } = await twoRecordChain();
    const disclosure = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-a", [chain[0]!.envelope.eventId]),
        issuedAt: "2026-09-03T10:00:00.000Z",
      }),
      keys
    );

    const result = validateChain([...chain, disclosure]);
    expect(result.issues).toEqual([]);
    expect(result.valid).toBe(true);
  });

  /**
   * Why each disclosure mints a fresh subject: sharing one would put two events
   * on the same subject, both naming the head as predecessor, which is a fork.
   */
  it("stays valid when the same chain is disclosed twice to different recipients", async () => {
    const { keys, chain, head } = await twoRecordChain();
    const toA = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-a", []),
        issuedAt: "2026-09-03T10:00:00.000Z",
      }),
      keys
    );
    const toB = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-b", []),
        issuedAt: "2026-09-04T10:00:00.000Z",
      }),
      keys
    );

    expect(validateChain([...chain, toA, toB]).issues).toEqual([]);
  });

  it("breaks exactly as predicted if two disclosures are forced onto one subject", async () => {
    const { keys, chain, head } = await twoRecordChain();
    const shared = newDisclosureSubjectId();
    const toA = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-a", []),
        issuedAt: "2026-09-03T10:00:00.000Z",
        subjectId: shared,
      }),
      keys
    );
    const toB = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-b", []),
        issuedAt: "2026-09-04T10:00:00.000Z",
        subjectId: shared,
      }),
      keys
    );

    const issues = validateChain([...chain, toA, toB]).issues;
    expect(issues).toHaveLength(1);
    expect(issues[0]!.message).toContain("chain break for subject");
  });

  /**
   * The cover sheet has to be delivered with its chain: a disclosure verified
   * without the chain it names has a predecessor nobody can find.
   */
  it("reports a dangling predecessor when verified without the chain it names", async () => {
    const { keys, head } = await twoRecordChain();
    const disclosure = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-a", []),
        issuedAt: "2026-09-03T10:00:00.000Z",
      }),
      keys
    );

    const issues = validateChain([disclosure]).issues;
    expect(issues).toHaveLength(1);
    expect(issues[0]!.message).toContain("does not match any known event");
  });

  it("verifies its own signature from the envelope alone", async () => {
    const { keys, head } = await twoRecordChain();
    const disclosure = await sign(
      buildDisclosureEnvelope({
        payload: disclosurePayload(head.eventHash, "urn:vbel:org:auditor-a", []),
        issuedAt: "2026-09-03T10:00:00.000Z",
      }),
      keys
    );

    expect((await verifyEvent(disclosure)).valid).toBe(true);
  });
});
