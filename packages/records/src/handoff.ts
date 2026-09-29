import { SCHEMA_ENTITY_REGISTERED } from "@vbel/core";
import { encodeChain, QR_BYTE_CEILING } from "./codec.js";
import { standingRegistrations } from "./registration.js";
import { storedPayloadOf, type LedgerRecord } from "./types.js";

/**
 * The chain, plus the identity claims a recipient needs in order to read it.
 *
 * A chain names who signed each record. A name means something only with the
 * claim that binds it to a key, and a recipient on another device has never met
 * these parties, so the signers' claims travel with the chain or every record
 * reads as issued by nobody. They follow the chain in the shape a disclosure
 * bundle uses and are separated again on arrival, so the reader works on the
 * business records and the identity layer works on the claims.
 *
 * Attaching everything does not always fit. Measured on a three-record chain:
 * 1980 characters bare, 2800 with self-registrations, 3443 with vouches as
 * well, against a QR ceiling of 2953. Sealing a vouch's payload saves only 28
 * characters, because a registration's weight is its envelope and signature.
 *
 * So claims are included by what the recipient loses without them.
 *
 *   A self-registration is required. Without it the recipient cannot name who
 *   signed. These are always included, since a smaller link that cannot be read
 *   is not better.
 *
 *   A vouch is additional. It tells a reader who else put their name to a
 *   binding but is not what makes the chain legible. These are included while
 *   there is room.
 *
 * A short chain therefore carries its vouches and a long one does not, with no
 * decision needed in advance about which matters more.
 */

export interface Handoff {
  /** The chain as it will travel. */
  handed: LedgerRecord[];
  /**
   * Identity that did not fit. Returned rather than discarded so the sender can
   * be told what the recipient will not see; only the sender can know.
   *
   * Known gap: a recipient cannot tell a party nobody vouched for from a party
   * whose vouch did not fit.
   */
  omitted: LedgerRecord[];
}

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
 * Which claims a chain needs, chosen from `available`, within `budget`
 * characters of encoded link.
 *
 * Only standing claims (a withdrawn vouch is not sent) for parties who appear in
 * the chain. Sending everything a device has been shown would tell a recipient
 * who else this party deals with, which they do not need to read this chain.
 */
export async function planHandoff(
  records: LedgerRecord[],
  available: LedgerRecord[],
  budget: number = QR_BYTE_CEILING
): Promise<Handoff> {
  const needed = partiesIn(records);
  const relevant = standingRegistrations(available).filter((record) => {
    const payload = storedPayloadOf(record) as { entityId?: string } | null;
    return (
      payload?.entityId !== undefined &&
      needed.has(payload.entityId) &&
      !records.some((held) => sameEvent(held, record))
    );
  });

  const loadBearing = relevant.filter(isSelfRegistration);
  const additional = relevant.filter((r) => !isSelfRegistration(r));

  // Appended, never prepended: the first record decides the subject a chain is
  // stored and displayed under, and the chain's own subject must stay first.
  let handed = [...records, ...loadBearing];
  const omitted: LedgerRecord[] = [];

  // Measured rather than estimated: gzip makes the cost of one more record
  // depend on how much it repeats of the records already there.
  for (const vouch of additional) {
    const candidate = [...handed, vouch];
    if ((await encodeChain(candidate)).length <= budget) handed = candidate;
    else omitted.push(vouch);
  }

  return { handed, omitted };
}

/** The chain plus the identity claims a recipient needs, plus anything else that should ride along, as one link fragment. */
export async function encodeWithIdentity(
  records: LedgerRecord[],
  available: LedgerRecord[],
  extra: LedgerRecord[] = [],
  budget: number = QR_BYTE_CEILING
): Promise<string> {
  const { handed } = await planHandoff(records, available, budget);
  const seen = new Set(handed.map((r) => r.event.envelope.eventId));
  return encodeChain([...handed, ...extra.filter((r) => !seen.has(r.event.envelope.eventId))]);
}

/** Null `attestedBy` is the entity speaking for itself, which is the claim nothing else can replace. */
function isSelfRegistration(record: LedgerRecord): boolean {
  const payload = storedPayloadOf(record) as { attestedBy?: string | null } | null;
  return payload?.attestedBy === null || payload?.attestedBy === undefined;
}

/**
 * Everyone whose key a reader has to resolve: issuers, signers and
 * counter-signers. A counter-signature is a second party's claim about the
 * record, and a recipient who cannot name that party sees an endorsement from
 * nobody.
 */
function partiesIn(records: LedgerRecord[]): Set<string> {
  const parties = new Set<string>();
  for (const record of records) {
    if (record.event.envelope.schema === SCHEMA_ENTITY_REGISTERED) continue;
    parties.add(record.event.envelope.issuerId);
    parties.add(record.event.signature.signerId);
    if (record.event.counterSignature) parties.add(record.event.counterSignature.signerId);
  }
  return parties;
}

function sameEvent(a: LedgerRecord, b: LedgerRecord): boolean {
  return a.event.envelope.eventId === b.event.envelope.eventId;
}
