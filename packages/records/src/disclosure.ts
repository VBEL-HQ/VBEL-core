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
import { redactChain } from "./recordCodec";
import { disclosedPayload, type LedgerRecord } from "./types";

export interface DisclosureRequest {
  /** The chain being shown. Disclosure records already in it are never re-disclosed. */
  records: LedgerRecord[];
  keys: KeyPair;
  /** The discloser, whose key signs. Split by console, as every other signature is. */
  discloserId: string;
  recipient: string;
  /** eventIds whose payloads travel. Everything else keeps its envelope only. */
  revealEventIds: string[];
  inResponseTo?: string | null;
  /**
   * Registration records to travel with the bundle, so the recipient can
   * resolve who signed what without being handed a registry separately and
   * asked to trust it. They are their own subjects, so they add no link to
   * the disclosed chain and cannot break it.
   *
   * They leak nothing the bundle did not already carry: every issuer named
   * here already appears as an issuerId on an envelope the recipient is
   * being given.
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
 * Produces what a recipient actually receives: the redacted chain and the
 * signed statement of what was done to it.
 *
 * The two travel together and that is a requirement rather than a
 * presentation choice. The cover sheet's `previousEventHash` is the
 * disclosed chain's head, and `validateChain` resolves that link within the
 * events it is handed, so a cover sheet verified alone reports a dangling
 * predecessor.
 *
 * Disclosure records already present in `records` are dropped before
 * anything else happens, and this is the enforcement point for the
 * recursion decision rather than a default someone can flip. A later
 * disclosure that carried an earlier one would tell auditor B that auditor
 * A exists, which is a fact about who is being reviewed and by whom, not a
 * fact about the transaction.
 *
 * Note that withholding the payload would not be enough to prevent that
 * leak: for a disclosure record the envelope's mere presence is the
 * disclosure. Omitting it entirely is only clean because a disclosure sits
 * on its own subject, so removing it leaves no gap in the disclosed chain's
 * continuity. Had disclosures been appended to the chain, omitting one would
 * have left a visible hole and forced a choice between leaking and looking
 * evasive.
 *
 * Including a past disclosure as evidence, to prove to one regulator that
 * you disclosed to their counterpart, stays possible. It is a deliberate act
 * of naming that record in a new disclosure, never something that happens
 * because a bundle was passed back in.
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
   * Whether the chain delivered alongside the sheet is the version the
   * sheet names. This is the check that makes the record worth signing: a
   * sheet that describes a different head is describing a different chain,
   * and saying so is the whole non-repudiation claim.
   */
  headMatches: "matches" | "differs" | "unchecked";
}

/**
 * Reads a received bundle as a cover sheet plus the chain it describes.
 *
 * Returns null when the bundle carries no disclosure record, which is the
 * ordinary case for a chain handed to a counterparty rather than disclosed
 * to a reviewer. That handoff is deliberately not a disclosure and must not
 * be dressed up as one.
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
  // claimed on its behalf.
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
