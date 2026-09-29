import { z } from "zod";
import { SIGNATURE_SCHEME_EVENT_HASH, SIGNATURE_SCHEME_MESSAGE_V1 } from "./message.js";

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
 * A single ed25519 signature: who signed, with what key, over what bytes.
 * Used for the issuer's signature over eventHash and for a counter-signer's
 * signature over the previousEventHash they are attesting to.
 *
 * This block sits outside every hashed region: `computeEventHash` covers the
 * envelope alone, and `attestationSigningRegion` drops the signature before
 * hashing. Adding a field here therefore changes no digest.
 */
export const SignatureBlockSchema = z
  .object({
    signerId: z.string().min(1),
    publicKey: z.string().min(1),
    signature: z.string().min(1),
    /**
     * What bytes the signature is over. `event-hash` signs the digest string
     * itself, from code holding a key. `vbel-message-v1` signs the readable
     * text in `message`, whose last line is that digest, so a person reading a
     * wallet screen knows what they approve.
     *
     * Defaulted rather than required, so a block without it is a digest
     * signature and its encoding stays minimal.
     */
    scheme: z
      .enum([SIGNATURE_SCHEME_EVENT_HASH, SIGNATURE_SCHEME_MESSAGE_V1])
      .default(SIGNATURE_SCHEME_EVENT_HASH),
    /** The exact text that was signed under `vbel-message-v1`. Null under `event-hash`. */
    message: z.string().nullable().default(null),
  })
  .superRefine((block, ctx) => {
    const needsMessage = block.scheme === SIGNATURE_SCHEME_MESSAGE_V1;
    if (needsMessage && block.message === null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["message"],
        message: `scheme ${SIGNATURE_SCHEME_MESSAGE_V1} requires the signed text, since it is verified over the stored message rather than reconstructed`,
      });
    }
    if (!needsMessage && block.message !== null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["message"],
        message: `scheme ${block.scheme} signs the digest directly, so a stored message would be unsigned text presented as if it were signed`,
      });
    }
  });
export type SignatureBlock = z.infer<typeof SignatureBlockSchema>;

export const SignedEventSchema = z.object({
  envelope: EnvelopeSchema,
  eventHash: z.string().regex(hashHex),
  /** The issuer's own signature over eventHash. Always present. */
  signature: SignatureBlockSchema,
  /**
   * Present only when this event counter-signs the event it chains to
   * (envelope.previousEventHash). Signed over previousEventHash, not over this
   * event's own eventHash: it attests to the prior content and is not a second
   * signature of this one.
   */
  counterSignature: SignatureBlockSchema.nullable().default(null),
});
export type SignedEvent = z.infer<typeof SignedEventSchema>;
