import { z } from "zod";
import { hashPayload } from "./hash.js";
import type { Envelope } from "./envelope.js";

/**
 * Disclosure: the act of showing a chain to someone, recorded as evidence
 * of itself.
 *
 * This lives in core rather than in a domain package because it is about
 * the ledger, not about anything the ledger describes. Its whole vocabulary
 * is core's vocabulary — subjects, event hashes, event ids — and both
 * domains need it equally. A `domain-disclosure` package would force either
 * a domain to depend on a domain, which the inward-only dependency rule
 * forbids, or leave the type stranded outside the layering and wired up
 * from the app.
 *
 * It is the first payload schema core carries, and that is a real deviation
 * worth naming: payloads are otherwise deliberately a domain concern. The
 * justification is that this one is not a business payload. It is metadata
 * about the register, in the same family as AnchorReceipt and
 * IssuerAttestation, and it embeds into domains exactly the way
 * PaymentReference already does.
 *
 * What the record buys, given that a redacted chain already shows its own
 * gaps — a recipient counts seven envelopes and four payloads unaided — is
 * non-repudiation of the *act*. Afterwards the discloser cannot claim they
 * handed over everything, cannot claim they handed over nothing, and cannot
 * claim it was a different version of the chain, because the disclosure
 * names the head it was made against.
 *
 * It says nothing about whether the withheld records were worth hiding.
 * Withholding is neutral about forgery and this record does not change that;
 * it only makes the choice attributable.
 */

const hashHex = /^sha256:[0-9a-f]{64}$/;

export const SCHEMA_DISCLOSURE = "urn:vbel:event:disclosure:v1";

/**
 * A disclosure gets a fresh subject every time.
 *
 * This is what keeps a read-side act from forking the write-side chain. Two
 * parties disclosing the same chain would otherwise produce two events
 * claiming the same predecessor, which validateChain correctly reports as a
 * chain break. Distinct subjects mean the per-subject ordering loop sees one
 * event each and checks nothing, while the global previousEventHash lookup
 * still resolves against the disclosed head.
 *
 * The uniqueness is load-bearing, not cosmetic: two disclosures sharing a
 * subject recreate exactly the fork this avoids.
 */
export function newDisclosureSubjectId(): string {
  return `urn:vbel:disclosure:${crypto.randomUUID()}`;
}

export const DisclosurePayloadSchema = z.object({
  /** The chain being disclosed. */
  disclosedSubjectId: z.string().min(1),
  /**
   * The head of that chain at the moment of disclosure. Pins the version, so
   * "you were shown a different chain" is not available to either side
   * afterwards.
   */
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
 * their own business; this one describes the register itself, and belongs
 * with the schema that defines it rather than duplicated into every domain
 * that might be disclosed.
 *
 * `previousEventHash` is the disclosed chain's head. That is what makes the
 * disclosure verifiable against the thing it is about, and it has a
 * consequence worth keeping rather than designing away: blastRadius will
 * treat the disclosure as a descendant of that head, so disclosing a chain
 * containing a detected forgery reads as downstream of it. That is correct.
 *
 * It also means a disclosure cannot be structurally validated alone. The
 * global previousEventHash lookup resolves within the events it is handed,
 * so a cover sheet verified without the chain it names reports a dangling
 * link. Cover sheet and redacted chain travel together; that is a
 * requirement, not a presentation preference.
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
