import { z } from "zod";
import { hashPayload } from "./hash.js";
import type { Envelope } from "./envelope.js";

/**
 * Registering an entity: the claim that a signing key belongs to a named
 * organisation, recorded in the ledger like any other claim.
 *
 * Putting the binding in the ledger does not make it true. It makes the claim
 * an object with an author, a date and a signature that a reader can inspect
 * and decide about, rather than an entry in a configuration file only the
 * verifier can see.
 *
 * There are two levels, and the difference between them matters:
 *
 *   self asserted   the entity signs its own registration with the key it is
 *                   registering. This proves possession of the key and
 *                   nothing else. Anyone can generate a keypair and call
 *                   themselves a bank.
 *   vouched         somebody else signs a registration for that entity. It is
 *                   worth as much as the voucher is, which the reader has to
 *                   judge.
 *
 * There is no third level that blesses anyone. Some root is always trusted
 * rather than proven, and it is better to be explicit about where it sits.
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
  /** What this entity does, e.g. "payee". Free text, never enforced. */
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
 * asserting, the voucher when attesting. A reader can therefore see whose word
 * an identity rests on.
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
 * A claim is withdrawn, never erased. The registration stays in the chain and
 * keeps verifying, and a later event says it no longer stands. An identity that
 * could be deleted would let a party rewrite who they had been.
 *
 * It covers two cases: a key that was lost or rotated, withdrawn by its owner,
 * and a vouch that somebody no longer stands behind, withdrawn by the voucher.
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
 * Whether a revocation is one a reader should act on.
 *
 * Only the party that made a claim may withdraw it. Without this check any
 * signer could revoke anybody's registration. The signature on the revocation
 * is verified separately; this decides whether a valid signature is the right
 * one.
 */
export function honoursRevocation(revocationIssuerId: string, revokedClaimIssuerId: string): boolean {
  return revocationIssuerId === revokedClaimIssuerId;
}
