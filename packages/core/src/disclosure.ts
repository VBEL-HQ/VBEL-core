import { z } from "zod";
import { hashPayload } from "./hash.js";
import type { Envelope } from "./envelope.js";

/**
 * Disclosure: the act of showing a chain to someone, recorded as evidence of
 * itself.
 *
 * It lives in core because it describes the ledger rather than anything the
 * ledger records: its vocabulary is subjects, event hashes and event ids. It
 * is the one payload schema core carries. Payloads are otherwise a domain
 * concern, but this is metadata about the register, in the same family as
 * AnchorReceipt and IssuerAttestation.
 *
 * A redacted chain already shows its own gaps, since a recipient can count
 * envelopes against payloads. What the record adds is non-repudiation of the
 * act. The discloser cannot later claim they handed over everything, nothing,
 * or a different version of the chain, because the disclosure names the head
 * it was made against.
 *
 * It says nothing about whether the withheld records were worth hiding.
 * Withholding is neutral about forgery; the record only makes the choice
 * attributable.
 */

const hashHex = /^sha256:[0-9a-f]{64}$/;

export const SCHEMA_DISCLOSURE = "urn:vbel:event:disclosure:v1";

/**
 * A disclosure gets a fresh subject every time, so showing a chain does not
 * fork it. Two parties disclosing the same chain would otherwise produce two
 * events claiming the same predecessor, which validateChain reports as a chain
 * break. With distinct subjects the per-subject ordering check sees one event
 * each, while the global previousEventHash lookup still resolves against the
 * disclosed head.
 *
 * The uniqueness matters: two disclosures sharing a subject recreate the fork.
 */
export function newDisclosureSubjectId(): string {
  return `urn:vbel:disclosure:${crypto.randomUUID()}`;
}

export const DisclosurePayloadSchema = z.object({
  /** The chain being disclosed. */
  disclosedSubjectId: z.string().min(1),
  /** The head of that chain at the moment of disclosure. Pins the version shown. */
  disclosedHeadHash: z.string().regex(hashHex),
  /** eventIds whose payloads travel with this disclosure. */
  revealedEventIds: z.array(z.string().min(1)),
  /** eventIds whose payloads were deliberately kept back. */
  withheldEventIds: z.array(z.string().min(1)),
  /** Who it was made to. Named, because a disclosure to nobody in particular is not one. */
  recipient: z.string().min(1),
  disclosedBy: z.string().min(1),
  disclosedAt: z.string().datetime({ offset: true }),
  /** The request being answered, when there was one. Null keeps an unsolicited disclosure possible. */
  inResponseTo: z.string().min(1).nullable().default(null),
});
export type DisclosurePayload = z.infer<typeof DisclosurePayloadSchema>;

export interface DisclosureEnvelopeParams {
  payload: DisclosurePayload;
  /** Defaults to now. Injectable so tests and fixtures are deterministic. */
  issuedAt?: string;
  policyId?: string;
  subjectId?: string;
}

/**
 * The only envelope core assembles. Domains build the events that describe
 * their own business; this one describes the register itself.
 *
 * `previousEventHash` is the disclosed chain's head, which makes the disclosure
 * verifiable against the chain it is about. As a consequence, blast radius
 * analysis treats the disclosure as a descendant of that head, so disclosing a
 * chain that contains a detected forgery reads as downstream of it.
 *
 * It also means a disclosure cannot be structurally validated alone: the
 * previousEventHash lookup resolves only within the events it is handed, so a
 * cover sheet verified without the chain it names reports a dangling link. The
 * cover sheet and the redacted chain must travel together.
 */
export function buildDisclosureEnvelope(params: DisclosureEnvelopeParams): Envelope {
  const payload = DisclosurePayloadSchema.parse(params.payload);

  return {
    schema: SCHEMA_DISCLOSURE,
    eventId: crypto.randomUUID(),
    subjectId: params.subjectId ?? newDisclosureSubjectId(),
    issuerId: payload.disclosedBy,
    issuedAt: params.issuedAt ?? new Date().toISOString(),
    previousEventHash: payload.disclosedHeadHash,
    payloadHash: hashPayload(payload),
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: params.policyId ?? "urn:vbel:policy:v1",
    privacy: "off-chain",
    nonce: crypto.randomUUID(),
  };
}
