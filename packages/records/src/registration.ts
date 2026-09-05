import {
  buildEntityRegistrationEnvelope,
  signEnvelope,
  SCHEMA_ENTITY_REGISTERED,
  type EntityRegistrationPayload,
  type KeyPair,
} from "@vbel/core";
import { disclosedPayload, storedPayloadOf, type LedgerRecord } from "./types";

/**
 * Building the two kinds of identity claim, and keeping them apart.
 *
 * Neither of these is a verification. A registration is somebody saying
 * something, signed, so the saying is attributable. Whether to believe it is
 * the reader's decision, and the UI must never take that decision for them
 * by rendering a self signed registration the way it renders a vouched one.
 */

/**
 * An entity claiming its own key. Signed with the key being registered,
 * which proves possession of it and nothing else: the name in it is
 * unverified, and would be unverified if it said Deutsche Bank.
 */
export async function buildSelfRegistration(params: {
  keys: KeyPair;
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
 * One entity vouching for another's key. Signed by the voucher, and worth
 * exactly what the voucher is worth to whoever is reading, which is a
 * question we deliberately do not answer.
 *
 * It chains to the registration it vouches for when there is one, so the
 * claim and the thing it is about stay linked.
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

/** Pulls the registration claims out of a set of records, ignoring everything else. */
export function registrationsIn(records: LedgerRecord[]): EntityRegistrationPayload[] {
  return records.flatMap((record) => {
    if (record.event.envelope.schema !== SCHEMA_ENTITY_REGISTERED) return [];
    const payload = storedPayloadOf(record);
    return payload ? [payload as EntityRegistrationPayload] : [];
  });
}
