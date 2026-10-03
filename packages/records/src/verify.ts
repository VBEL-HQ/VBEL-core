import { diffPayloads, verifyEvent, verifyPayload } from "@vbel/core";
import type { IdentityContext } from "./identityContext.js";
import type { LedgerRecord, PayloadState, RecordVerdict } from "./types.js";

/**
 * Issue codes that concern who signed rather than the signature itself.
 * verifyEvent returns one list of issues, and without this split an
 * unregistered issuer would make a record read "signature invalid" when the
 * signature is fine and the open question is whose key it is.
 */
const IDENTITY_ISSUE_CODES = new Set([
  "ISSUER_UNKNOWN",
  "ISSUER_KEY_MISMATCH",
  "ATTESTATION_NOT_YET_VALID",
  "ATTESTATION_EXPIRED",
  "ATTESTATION_SIGNATURE_INVALID",
]);

/**
 * Verifies one record with no server and no outside call, in any environment
 * that runs @vbel/core. The identity context is optional in the sense that
 * verification still works when nobody can say who a key belongs to; the
 * verdict then reports the identity as unknown.
 *
 * The signature and chain position are established from the envelope alone, so
 * they hold whether or not the payload travelled. Only what a record said needs
 * its payload, which is why selective disclosure needs no extra cryptography.
 */
export async function verifyRecord(record: LedgerRecord, context: IdentityContext): Promise<RecordVerdict> {
  const signature = await verifyEvent(record.event, context.resolver);
  const described = await context.describe(record.event.envelope.issuerId, record.event.envelope.issuedAt);

  const signatureIssues = signature.issues.filter((issue) => !IDENTITY_ISSUE_CODES.has(issue.code));

  /**
   * Splitting identity out of the signature must not lose it. The resolver can
   * answer for this issuer with a key other than the one that signed: anyone
   * can sign a registration for any name, and a later one can be the one that
   * resolves. The signature is then valid and the name is somebody else's, so
   * the record reads as signed by a key nobody is known to hold, never as
   * the named company's.
   */
  const keyMismatch = signature.issues.some((issue) => issue.code === "ISSUER_KEY_MISMATCH");
  const identity = keyMismatch
    ? { ...described, assurance: "unknown" as const, registration: null, vouchedBy: [] }
    : described;

  const base = {
    signatureValid: signatureIssues.length === 0,
    signatureIssues,
    identity,
    counterSigned: record.event.counterSignature !== null,
  };

  // A withheld payload never reaches verifyPayload. Hashing absence would
  // produce a mismatch, and a redaction would then read as a forgery.
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
