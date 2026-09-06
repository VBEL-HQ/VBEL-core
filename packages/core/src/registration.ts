import { z } from "zod";
import { hashPayload } from "./hash.js";
import type { Envelope } from "./envelope.js";

/**
 * Registering an entity: the claim that a signing key belongs to a named
 * organisation, recorded the same way every other claim in this system is.
 *
 * Until now identity was a file we shipped. Every signature verified against
 * it proved only that the resolver we chose to load said so, which is a
 * claim about our configuration rather than about the world. Putting the
 * binding in the ledger does not by itself make it true, and nothing here
 * pretends otherwise. What it changes is that the claim becomes an object
 * with an author, a date and a signature, that a stranger can inspect and
 * decide about, instead of a line in a file only we can see.
 *
 * Two levels, and the difference between them is the whole point:
 *
 *   self asserted   the entity signs its own registration with the key it
 *                   is registering. This proves possession of the key and
 *                   nothing else. Anyone can generate a keypair and call
 *                   themselves a bank.
 *   vouched         somebody else signs a registration for that entity.
 *                   Worth exactly as much as the voucher is worth, which is
 *                   a question the reader has to answer and we must not
 *                   answer for them.
 *
 * There is no third level where we bless anyone. Somewhere there is always
 * a root that is trusted rather than proven, and being explicit about where
 * it sits is more useful than hiding it behind a checkmark.
 */

export const SCHEMA_ENTITY_REGISTERED = "urn:vbel:event:entity-registered:v1";

/** Hex encoded ed25519 public key, matching SignatureBlock.publicKey. */
const publicKeyHex = /^[0-9a-f]{64}$/;

export function subjectIdForEntity(entityId: string): string {
  return `urn:vbel:entity:${entityId}`;
}

export const EntityRegistrationPayloadSchema = z.object({
  /** The identifier that appears as `issuerId` on this entity's events. */
  entityId: z.string().min(1),
  /** What to call it on screen. The first fact about an entity a person actually reads. */
  displayName: z.string().min(1),
  publicKey: z.string().regex(publicKeyHex),
  /** What this entity does in the scenario, e.g. "payee". Free text, never enforced. */
  role: z.string().min(1).nullable().default(null),
  registeredAt: z.string().datetime({ offset: true }),
  /** Null means open ended, valid until something supersedes it. */
  validUntil: z.string().datetime({ offset: true }).nullable().default(null),
  /**
   * Who is making this claim. Null means the entity is vouching for itself,
   * which proves key possession and nothing more.
   */
  attestedBy: z.string().min(1).nullable().default(null),
});
export type EntityRegistrationPayload = z.infer<typeof EntityRegistrationPayloadSchema>;

/** How much a resolved identity is actually worth. Never collapse these into "verified". */
export type Assurance = "self-asserted" | "vouched";

export function assuranceOf(payload: EntityRegistrationPayload): Assurance {
  return payload.attestedBy === null ? "self-asserted" : "vouched";
}

export interface EntityRegistrationEnvelopeParams {
  payload: EntityRegistrationPayload;
  /**
   * The registration this one vouches for, when someone is attesting to an
   * entity that already registered itself. Null starts the entity's own
   * subject.
   */
  previousEventHash?: string | null;
  issuedAt?: string;
  policyId?: string;
}

/**
 * The issuer is whoever is making the claim: the entity itself when self
 * asserting, the voucher when attesting. That falls out of the same rule
 * every other event follows, and it is what lets a reader see at a glance
 * whose word an identity rests on.
 */
export function buildEntityRegistrationEnvelope(params: EntityRegistrationEnvelopeParams): Envelope {
  const payload = EntityRegistrationPayloadSchema.parse(params.payload);

  return {
    schema: SCHEMA_ENTITY_REGISTERED,
    eventId: crypto.randomUUID(),
    subjectId: subjectIdForEntity(payload.entityId),
    issuerId: payload.attestedBy ?? payload.entityId,
    issuedAt: params.issuedAt ?? payload.registeredAt,
    previousEventHash: params.previousEventHash ?? null,
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


export interface EntityRevocationParams {
  /** The claim being withdrawn, unchanged. Revoking does not restate it. */
  payload: EntityRegistrationPayload;
  /** eventId of the registration this withdraws. */
  revokes: string;
  revokeReason: string;
  /** Who is withdrawing. Must be whoever made the claim; see honoursRevocation. */
  issuerId: string;
  previousEventHash: string;
  issuedAt?: string;
  policyId?: string;
}

/**
 * Withdrawing an identity claim.
 *
 * A claim is withdrawn, never erased. The registration stays in the chain
 * and keeps verifying, and a later event says it no longer stands, which is
 * the same rule corrections and disputes follow. An identity that could be
 * deleted would let a party rewrite who they had been.
 *
 * Two things this is for. A key that was lost or rotated, withdrawn by its
 * owner. And a vouch somebody no longer stands behind, withdrawn by the
 * voucher: "I said this key was theirs, and I am taking that back."
 */
export function buildEntityRevocationEnvelope(params: EntityRevocationParams): Envelope {
  const payload = EntityRegistrationPayloadSchema.parse(params.payload);

  return {
    schema: SCHEMA_ENTITY_REGISTERED,
    eventId: crypto.randomUUID(),
    subjectId: subjectIdForEntity(payload.entityId),
    issuerId: params.issuerId,
    issuedAt: params.issuedAt ?? new Date().toISOString(),
    previousEventHash: params.previousEventHash,
    payloadHash: hashPayload(payload),
    status: "REVOKED",
    supersedes: null,
    supersedeReason: null,
    revokes: params.revokes,
    revokeReason: params.revokeReason,
    policyId: params.policyId ?? "urn:vbel:policy:v1",
    privacy: "off-chain",
    nonce: crypto.randomUUID(),
  };
}

/**
 * Whether a revocation is one this reader should act on.
 *
 * Only the party that made a claim may withdraw it. Without this check any
 * signer could revoke anybody's registration, which would turn a mechanism
 * for withdrawing your own word into a mechanism for silencing someone
 * else's. The signature on the revocation is verified elsewhere, like every
 * other signature; this decides whether a valid signature is the right one.
 */
export function honoursRevocation(revocationIssuerId: string, revokedClaimIssuerId: string): boolean {
  return revocationIssuerId === revokedClaimIssuerId;
}
