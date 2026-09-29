import { SCHEMA_ENTITY_REGISTERED } from "@vbel/core";
import { encodeChain, QR_BYTE_CEILING } from "./codec.js";
import { standingRegistrations } from "./registration.js";
import { storedPayloadOf, type LedgerRecord } from "./types.js";

/**
 * The chain, plus the identity claims a recipient needs in order to read it.
 *
 * A chain says who signed each record by name. The name means something only
 * with the claim that binds it to a key, and a recipient opening a link on
 * another device has never met these parties, so the claims of the people who
 * signed have to travel with the chain or every record reads as issued by
 * nobody. They ride behind the chain, in the shape a disclosure bundle uses,
 * and are separated again on arrival so the reader works on the business
 * records and the identity layer works on the claims.
 *
 * Attaching all of it does not always fit. Measured on a three-record chain:
 * 1980 characters bare, 2800 with self-registrations, 3443 with vouches as
 * well, against a QR ceiling of 2953. Sealing a vouch's payload saves 28
 * characters, because the weight of a registration is its envelope and
 * signature rather than what it says.
 *
 * So the split is by what the recipient loses without it.
 *
 *   A self-registration is load-bearing. Without it the recipient cannot name
 *   who signed at all. These go in whatever it costs, because a smaller link
 *   that cannot be read is not a better link.
 *
 *   A vouch is additional. It tells a reader who else put their name to a
 *   binding, which is worth having and is not what makes the chain legible.
 *   These go in while there is room.
 *
 * The budget is therefore a rule rather than a policy: a short chain carries
 * its vouches, a long one does not, and neither case needs a decision made in
 * advance about which matters more.
 */

export interface Handoff {
  /** The chain as it will travel. */
  handed: LedgerRecord[];
  /**
   * Identity that did not fit. Returned rather than discarded so the sender
   * can be told what the recipient will not see, which is the only end where
   * that is currently knowable.
   *
   * Known gap: a recipient cannot tell a party nobody vouched for from a party
   * whose vouch did not fit. Sealing the payload would have said so and costs
   * almost nothing to carry, which is exactly why it saves almost nothing to
   * omit.
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
 * Only standing claims (a withdrawn vouch is not sent) for parties who
 * actually appear in the chain: sending everything a device has ever been
 * shown would tell a recipient who else this party deals with, which is not
 * theirs to know and not needed to read this chain.
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

  /**
   * Appended, never prepended. The first record decides the subject a chain is
   * stored and displayed under, and a handoff about an invoice that announced
   * itself as being about an entity would be filed under the wrong thing at
   * the other end.
   */
  let handed = [...records, ...loadBearing];
  const omitted: LedgerRecord[] = [];

  // Measured rather than estimated. The encoding is gzip then base64url, so
  // the cost of one more record depends on how much it repeats of the ones
  // already there, and no per-record figure predicts it.
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
 * Everyone whose key a reader has to resolve: issuers, signers, and
 * counter-signers. A counter-signature is a second party's claim about the
 * record, and a recipient who cannot name them is being shown an endorsement
 * from nobody.
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
