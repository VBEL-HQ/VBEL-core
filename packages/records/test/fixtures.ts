import { generateKeyPair, hashPayload, signEnvelope, type Envelope, type KeyPair } from "@vbel/core";
import { z } from "zod";
import { buildSelfRegistration, disclosedPayload, type LedgerRecord } from "../src/index.js";

/**
 * A record type invented for the tests, to show the library needs nothing
 * from any domain: a schema URN, a payload shape, and a chain of three.
 */
export const SCHEMA_NOTE = "urn:example:event:note:v1";
export const NoteSchema = z.object({ text: z.string(), amount: z.number() });
export type Note = z.infer<typeof NoteSchema>;
export const SCHEMAS = { [SCHEMA_NOTE]: NoteSchema };

export const AUTHOR = "urn:vbel:org:author";
export const AT = "2026-08-10T10:00:00.000Z";

function envelope(issuerId: string, payload: Note, previousEventHash: string | null, overrides: Partial<Envelope> = {}): Envelope {
  return {
    schema: SCHEMA_NOTE,
    eventId: crypto.randomUUID(),
    subjectId: "urn:example:subject:1",
    issuerId,
    issuedAt: AT,
    previousEventHash,
    payloadHash: hashPayload(payload),
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: "urn:example:policy:v1",
    privacy: "off-chain",
    nonce: crypto.randomUUID(),
    ...overrides,
  };
}

export async function noteRecord(
  keys: KeyPair,
  payload: Note,
  previous: LedgerRecord | null,
  overrides: Partial<Envelope> = {}
): Promise<LedgerRecord> {
  const event = await signEnvelope({
    envelope: envelope(AUTHOR, payload, previous?.event.eventHash ?? null, overrides),
    signer: keys,
    signerId: AUTHOR,
  });
  return { label: "Note", event, payload: disclosedPayload(payload), anchor: null, chainVerification: null };
}

/** Three notes, and the registration that says who the author is. */
export async function chainOfThree() {
  const keys = await generateKeyPair();
  const registration = await buildSelfRegistration({
    keys,
    entityId: AUTHOR,
    displayName: "The Author Ltd",
    at: "2026-08-01T00:00:00.000Z",
  });
  const first = await noteRecord(keys, { text: "first", amount: 100 }, null);
  const second = await noteRecord(keys, { text: "second", amount: 200 }, first);
  const third = await noteRecord(keys, { text: "third", amount: 300 }, second);
  return { keys, registration, records: [first, second, third] };
}
