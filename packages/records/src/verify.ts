import { diffPayloads, verifyEvent, verifyPayload } from "@vbel/core";
import type { IdentityContext } from "./identityContext.js";
import type { LedgerRecord, PayloadState, RecordVerdict } from "./types.js";

/**
 * Runs entirely in the browser against the same @vbel/core the issuing API
 * uses. No server is consulted and no result is taken on trust — that is
 * the point of the verifier. The resolver is optional for the same reason:
 * verification degrades gracefully with no identity source, it doesn't fail.
 *
 * The signature and the chain position are established from the envelope
 * alone, so they hold for every record whether its payload travelled or
 * not. Only "what did this record say" needs a payload, and only for the
 * record it is about — which is the whole reason selective disclosure is
 * possible here without inventing any new cryptography.
 */
/**
 * Issue codes that are about *who* signed rather than about the signature.
 *
 * verifyEvent returns one list and one boolean, so before this split an
 * unregistered issuer made a record read "signature invalid". The signature
 * was fine. Saying otherwise points a reader at cryptography when the real
 * question is whose key it is, and those get answered by different people.
 */
const IDENTITY_ISSUE_CODES = new Set([
  "ISSUER_UNKNOWN",
  "ISSUER_KEY_MISMATCH",
  "ATTESTATION_NOT_YET_VALID",
  "ATTESTATION_EXPIRED",
  "ATTESTATION_SIGNATURE_INVALID",
]);

export async function verifyRecord(record: LedgerRecord, context: IdentityContext): Promise<RecordVerdict> {
  const signature = await verifyEvent(record.event, context.resolver);
  const identity = await context.describe(record.event.envelope.issuerId, record.event.envelope.issuedAt);

  const signatureIssues = signature.issues.filter((issue) => !IDENTITY_ISSUE_CODES.has(issue.code));

  const base = {
    signatureValid: signatureIssues.length === 0,
    signatureIssues,
    identity,
    counterSigned: record.event.counterSignature !== null,
  };

  // A withheld payload never reaches verifyPayload. Hashing absence would
  // produce a mismatch, and a mismatch means forgery everywhere downstream
  // — so the redaction itself would read as the crime.
  if (record.payload.state === "withheld") {
    return { ...base, payloadState: "withheld" as PayloadState, differences: [] };
  }

  const payload = verifyPayload(record.payload.stored, record.event.envelope);

  return {
    ...base,
    payloadState: (payload.valid ? "verified" : "mismatch") as PayloadState,
    differences: payload.valid ? [] : diffPayloads(record.payload.issuer, record.payload.stored),
  };
}

export async function verifyAll(
  records: LedgerRecord[],
  context: IdentityContext
): Promise<Map<string, RecordVerdict>> {
  const entries = await Promise.all(
    records.map(async (record) => [record.event.envelope.eventId, await verifyRecord(record, context)] as const)
  );
  return new Map(entries);
}
