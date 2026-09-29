import {
  buildEntityRegistrationEnvelope,
  buildEntityRevocationEnvelope,
  honoursRevocation,
  signEnvelope,
  SCHEMA_ENTITY_REGISTERED,
  type EntityRegistrationPayload,
  type KeyPair,
  type Signer,
} from "@vbel/core";
import { disclosedPayload, storedPayloadOf, type LedgerRecord } from "./types.js";

/**
 * Building the two kinds of identity claim, and keeping them apart.
 *
 * Neither is a verification. A registration is somebody saying something,
 * signed, so the saying is attributable. Whether to believe it is the reader's
 * decision, and a display should not present a self-signed registration the
 * way it presents a vouched one.
 */

/**
 * An entity claiming its own key. Signed with the key being registered, which
 * proves possession of it and nothing else: the name in it is unverified,
 * whatever it says.
 */
export async function buildSelfRegistration(params: {
  /** A held keypair or a wallet. */
  keys: KeyPair | Signer;
  entityId: string;
  displayName: string;
  role?: string | null;
  /** When the claim was made. Must predate any act it is expected to explain. */
  at?: string;
}): Promise<LedgerRecord> {
  const payload: EntityRegistrationPayload = {
    entityId: params.entityId,
    displayName: params.displayName,
    publicKey: params.keys.publicKeyHex,
    role: params.role ?? null,
    registeredAt: params.at ?? new Date().toISOString(),
    validUntil: null,
    attestedBy: null,
  };

  const event = await signEnvelope({
    envelope: buildEntityRegistrationEnvelope({ payload }),
    signer: params.keys,
    signerId: params.entityId,
  });

  return { label: "Registration", event, payload: disclosedPayload(payload), anchor: null, chainVerification: null };
}

/**
 * One entity vouching for another's key. Signed by the voucher, and worth as
 * much as the voucher is to whoever reads it, which this library does not judge.
 *
 * It chains to the registration it vouches for when there is one, so the claim
 * and the thing it is about stay linked.
 */
export async function buildVouch(params: {
  keys: KeyPair;
  voucherId: string;
  subject: EntityRegistrationPayload;
  previousEventHash?: string | null;
}): Promise<LedgerRecord> {
  const payload: EntityRegistrationPayload = {
    ...params.subject,
    registeredAt: new Date().toISOString(),
    attestedBy: params.voucherId,
  };

  const event = await signEnvelope({
    envelope: buildEntityRegistrationEnvelope({
      payload,
      previousEventHash: params.previousEventHash ?? null,
    }),
    signer: params.keys,
    signerId: params.voucherId,
  });

  return { label: "Registration", event, payload: disclosedPayload(payload), anchor: null, chainVerification: null };
}

/**
 * Withdraws a claim, signed by whoever made it.
 *
 * The caller has to supply the key of the original claimant, and readers check
 * the same thing independently: a revocation naming someone else's claim is
 * ignored. Otherwise it would silence other people instead of retracting your
 * own word.
 */
export async function buildRevocation(params: {
  keys: KeyPair;
  /** The claimant withdrawing, which must match the issuer of the target. */
  issuerId: string;
  /** The registration record being withdrawn. */
  target: LedgerRecord;
  reason: string;
  /**
   * Where this attaches in the chain. Defaults to the record being withdrawn,
   * which is right only when that record is the head. A vouch sits under the
   * registration it attests, and appending behind the wrong record would leave
   * the entity's chain unlinkable.
   */
  previousEventHash?: string | null;
}): Promise<LedgerRecord> {
  const payload = storedPayloadOf(params.target) as EntityRegistrationPayload | null;
  if (!payload) throw new Error("cannot withdraw a claim whose contents were not disclosed");

  const event = await signEnvelope({
    envelope: buildEntityRevocationEnvelope({
      payload,
      revokes: params.target.event.envelope.eventId,
      revokeReason: params.reason,
      issuerId: params.issuerId,
      previousEventHash: params.previousEventHash ?? params.target.event.eventHash,
    }),
    signer: params.keys,
    signerId: params.issuerId,
  });

  return { label: "Withdrawn", event, payload: disclosedPayload(payload), anchor: null, chainVerification: null };
}

/**
 * The identity claims that still stand.
 *
 * Withdrawn claims are dropped here, so nothing that resolves an issuer sees
 * one. A revocation counts only when the party withdrawing is the party that
 * made the claim; one naming somebody else's registration is ignored, since
 * obeying it would let any signer strike out any identity in the chain.
 */
export function standingRegistrations(records: LedgerRecord[]): LedgerRecord[] {
  const claims = records.filter((r) => r.event.envelope.schema === SCHEMA_ENTITY_REGISTERED);
  const issuerOf = new Map(claims.map((r) => [r.event.envelope.eventId, r.event.envelope.issuerId]));

  const withdrawn = new Set(
    claims.flatMap((r) => {
      const target = r.event.envelope.revokes;
      if (!target) return [];
      const claimIssuer = issuerOf.get(target);
      if (claimIssuer === undefined) return [];
      return honoursRevocation(r.event.envelope.issuerId, claimIssuer) ? [target] : [];
    })
  );

  return claims.filter(
    (record) =>
      record.event.envelope.revokes === null && !withdrawn.has(record.event.envelope.eventId)
  );
}

/** The same set, as the payloads a resolver reads. */
export function registrationsIn(records: LedgerRecord[]): EntityRegistrationPayload[] {
  return standingRegistrations(records).flatMap((record) => {
    const payload = storedPayloadOf(record);
    return payload ? [payload as EntityRegistrationPayload] : [];
  });
}
