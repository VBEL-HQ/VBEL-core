import { SCHEMA_ENTITY_REGISTERED, type EntityRegistrationPayload } from "@vbel/core";
import { encodeChain } from "./codec.js";
import { standingRegistrations } from "./registration.js";
import type { LedgerRecord } from "./types.js";

/**
 * What travels in a link besides the chain.
 *
 * A chain says who signed each record by name. The name means something only
 * with the claim that binds it to a key, and a recipient opening a link on
 * another device has never met these parties. So the registrations of the
 * people who signed ride behind the chain, in the same shape a disclosure
 * bundle uses, and are separated again on arrival so the reader works on the
 * business records and the identity layer works on the claims.
 */

export function isRegistration(record: LedgerRecord): boolean {
  return record.event.envelope.schema === SCHEMA_ENTITY_REGISTERED;
}

/** Splits what a link delivered into the case and the claims that came with it. */
export function splitHandoff(decoded: LedgerRecord[]): { records: LedgerRecord[]; registrations: LedgerRecord[] } {
  return {
    records: decoded.filter((r) => !isRegistration(r)),
    registrations: decoded.filter(isRegistration),
  };
}

/**
 * The claims a reader needs in order to resolve every signer in `records`,
 * chosen from `held`.
 *
 * Only standing claims for entities that actually signed something here:
 * sending everything a device has ever been shown would tell a recipient who
 * else this party deals with, which is not theirs to know and not needed to
 * read this chain.
 */
export function registrationsForSigners(records: LedgerRecord[], held: LedgerRecord[]): LedgerRecord[] {
  const signers = new Set(records.map((r) => r.event.envelope.issuerId));
  return standingRegistrations(held).filter((claim) => {
    const payload = claim.payload.state === "present" ? (claim.payload.stored as Partial<EntityRegistrationPayload>) : null;
    return payload?.entityId !== undefined && signers.has(payload.entityId);
  });
}

/** The chain plus the identity claims a recipient needs, as one link fragment. */
export async function encodeWithIdentity(
  records: LedgerRecord[],
  held: LedgerRecord[],
  extra: LedgerRecord[] = []
): Promise<string> {
  const seen = new Set<string>();
  const unique = [...registrationsForSigners(records, held), ...extra].filter((claim) => {
    const id = claim.event.envelope.eventId;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  return encodeChain([...records, ...unique]);
}
