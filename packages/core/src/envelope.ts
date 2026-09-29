import { z } from "zod";

/**
 * Frozen at v0.1. The envelope is what every hash and signature covers, so
 * changing a field changes the meaning of every record ever signed with it.
 * Everything else in this library is built on top of it; a new version is a
 * new schema URN and a new type, never an edit to this one.
 */

export const EventStatus = z.enum(["ACTIVE", "REVOKED"]);
export type EventStatus = z.infer<typeof EventStatus>;

const hashHex = /^sha256:[0-9a-f]{64}$/;

export const EnvelopeSchema = z.object({
  schema: z.string().min(1),
  eventId: z.string().min(1),
  subjectId: z.string().min(1),
  issuerId: z.string().min(1),
  issuedAt: z.string().datetime({ offset: true }),
  previousEventHash: z.string().regex(hashHex).nullable(),
  payloadHash: z.string().regex(hashHex),
  status: EventStatus,
  // Set only on a correction event: the eventId of the event this one supersedes.
  supersedes: z.string().nullable().default(null),
  supersedeReason: z.string().nullable().default(null),
  // Set only on a revocation event: the eventId of the event this one revokes.
  revokes: z.string().nullable().default(null),
  revokeReason: z.string().nullable().default(null),
  policyId: z.string().min(1),
  privacy: z.literal("off-chain"),
  nonce: z.string().min(1),
});
export type Envelope = z.infer<typeof EnvelopeSchema>;

/**
 * A single ed25519 signature: who signed, with what key, producing what bytes.
 * Used both for the issuer's own signature over eventHash, and for a
 * counter-signer's signature over a previousEventHash they are attesting to.
 */
export const SignatureBlockSchema = z.object({
  signerId: z.string().min(1),
  publicKey: z.string().min(1),
  signature: z.string().min(1),
});
export type SignatureBlock = z.infer<typeof SignatureBlockSchema>;

export const SignedEventSchema = z.object({
  envelope: EnvelopeSchema,
  eventHash: z.string().regex(hashHex),
  /** The issuer's own signature over eventHash. Always present. */
  signature: SignatureBlockSchema,
  /**
   * Present only when this event counter-signs the event it chains to
   * (envelope.previousEventHash). Signed over previousEventHash, not
   * over this event's own eventHash — it is an attestation to the prior
   * content, not a second signature of this one.
   */
  counterSignature: SignatureBlockSchema.nullable().default(null),
});
export type SignedEvent = z.infer<typeof SignedEventSchema>;
