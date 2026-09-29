import {
  buildDisclosureEnvelope,
  SCHEMA_DISCLOSURE,
  SCHEMA_ENTITY_REGISTERED,
  signEnvelope,
  verifyEvent,
  type DisclosurePayload,
  type IdentityResolver,
  type KeyPair,
} from "@vbel/core";
import { redactChain } from "./codec.js";
import { disclosedPayload, type LedgerRecord } from "./types.js";

export interface DisclosureRequest {
  /** The chain being shown. Disclosure records already in it are never re-disclosed. */
  records: LedgerRecord[];
  keys: KeyPair;
  /** The discloser, whose key signs. */
  discloserId: string;
  recipient: string;
  /** eventIds whose payloads travel. Everything else keeps its envelope only. */
  revealEventIds: string[];
  inResponseTo?: string | null;
  /**
   * Registration records to travel with the bundle, so the recipient can
   * resolve who signed what without being handed a registry separately. They
   * are their own subjects, so they add no link to the disclosed chain and
   * cannot break it. They reveal nothing new: every issuer named already
   * appears as an issuerId on an envelope the recipient receives.
   */
  includeRegistrations?: LedgerRecord[];
}

export interface DisclosureBundle {
  /** The redacted chain plus the cover sheet, in the order a reader meets them. */
  bundle: LedgerRecord[];
  disclosure: LedgerRecord;
  revealedEventIds: string[];
  withheldEventIds: string[];
}

/**
 * Produces what a recipient receives: the redacted chain and the signed
 * statement of what was done to it.
 *
 * The two must travel together. The cover sheet's `previousEventHash` is the
 * disclosed chain's head, and `validateChain` resolves that link only within
 * the events it is handed, so a cover sheet verified alone reports a dangling
 * predecessor.
 *
 * Disclosure records already present in `records` are dropped first, always. A
 * later disclosure that carried an earlier one would tell one reviewer that
 * another exists, which is a fact about who is being reviewed and by whom
 * rather than about the transaction.
 *
 * Withholding such a record's payload would not prevent that, since its
 * envelope alone is the disclosure. Omitting it entirely is clean because a
 * disclosure sits on its own subject, so removing it leaves no gap in the
 * disclosed chain's continuity.
 *
 * Including a past disclosure as evidence stays possible: name that record
 * explicitly in a new disclosure. It never happens just because a bundle was
 * passed back in.
 */
export async function buildDisclosure(request: DisclosureRequest): Promise<DisclosureBundle> {
  const chain = request.records.filter(
    (r) =>
      r.event.envelope.schema !== SCHEMA_DISCLOSURE &&
      r.event.envelope.schema !== SCHEMA_ENTITY_REGISTERED
  );
  const head = chain[chain.length - 1];
  if (!head) throw new Error("cannot disclose: there is no chain here");

  const first = chain[0]!;
  const reveal = new Set(request.revealEventIds);

  const revealedEventIds: string[] = [];
  const withheldEventIds: string[] = [];
  for (const record of chain) {
    const id = record.event.envelope.eventId;
    (reveal.has(id) ? revealedEventIds : withheldEventIds).push(id);
  }

  const payload: DisclosurePayload = {
    disclosedSubjectId: first.event.envelope.subjectId,
    disclosedHeadHash: head.event.eventHash,
    revealedEventIds,
    withheldEventIds,
    recipient: request.recipient,
    disclosedBy: request.discloserId,
    disclosedAt: new Date().toISOString(),
    inResponseTo: request.inResponseTo ?? null,
  };

  const event = await signEnvelope({
    envelope: buildDisclosureEnvelope({ payload }),
    signer: request.keys,
    signerId: request.discloserId,
  });

  const disclosure: LedgerRecord = {
    label: "Disclosure",
    event,
    payload: disclosedPayload(payload),
    anchor: null,
    chainVerification: null,
  };

  return {
    bundle: [...redactChain(chain, revealedEventIds), disclosure, ...(request.includeRegistrations ?? [])],
    disclosure,
    revealedEventIds,
    withheldEventIds,
  };
}

export interface CoverSheetReading {
  /** The cover sheet itself. */
  disclosure: LedgerRecord;
  payload: DisclosurePayload;
  /** The disclosed chain, which is the bundle with the cover sheet removed. */
  chain: LedgerRecord[];
  signature: "verified" | "invalid" | "unchecked";
  /**
   * Whether the chain delivered alongside the sheet is the version the sheet
   * names. A sheet describing a different head describes a different chain, and
   * this check is what gives the signed record its meaning.
   */
  headMatches: "matches" | "differs" | "unchecked";
}

/**
 * Reads a received bundle as a cover sheet plus the chain it describes.
 *
 * Returns null when the bundle carries no disclosure record, which is the
 * ordinary case for a chain handed to a counterparty rather than disclosed to
 * a reviewer. Such a handoff is not a disclosure and is not presented as one.
 */
export async function readCoverSheet(
  bundle: LedgerRecord[],
  resolver?: IdentityResolver
): Promise<CoverSheetReading | null> {
  const disclosure = [...bundle].reverse().find((r) => r.event.envelope.schema === SCHEMA_DISCLOSURE);
  if (!disclosure) return null;

  const payload = disclosure.payload.state === "present" ? (disclosure.payload.stored as DisclosurePayload) : null;
  const chain = bundle.filter(
    (r) =>
      r.event.envelope.schema !== SCHEMA_DISCLOSURE &&
      r.event.envelope.schema !== SCHEMA_ENTITY_REGISTERED
  );

  // A cover sheet whose own payload was withheld says nothing, so nothing is
  // claimed for it.
  if (!payload) {
    return { disclosure, payload: EMPTY_DISCLOSURE, chain, signature: "unchecked", headMatches: "unchecked" };
  }

  const verified = await verifyEvent(disclosure.event, resolver);
  const head = chain[chain.length - 1];

  return {
    disclosure,
    payload,
    chain,
    signature: verified.valid ? "verified" : "invalid",
    headMatches: !head ? "unchecked" : head.event.eventHash === payload.disclosedHeadHash ? "matches" : "differs",
  };
}

const EMPTY_DISCLOSURE: DisclosurePayload = {
  disclosedSubjectId: "",
  disclosedHeadHash: `sha256:${"0".repeat(64)}`,
  revealedEventIds: [],
  withheldEventIds: [],
  recipient: "",
  disclosedBy: "",
  disclosedAt: new Date(0).toISOString(),
  inResponseTo: null,
};
