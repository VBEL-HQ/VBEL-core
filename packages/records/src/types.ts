import type {
  AnchorReceipt,
  FieldDifference,
  LedgerVerificationResult,
  SignedEvent,
  VerificationIssue,
} from "@vbel/core";
import type { IdentityDescription } from "./identityContext.js";

/**
 * What a record says. The library does not know what shapes exist: a payload is
 * an object, and the schema URN on the envelope says which. To the verifier a
 * record is a record whatever domain issued it, so one verifier serves every
 * domain. Narrow the type where you know the schema, and register that schema
 * with the codec so a payload arriving in a link is validated before anything
 * reads it.
 */
export type RecordPayload = object;

/**
 * Whether this record's payload came with the chain.
 *
 * A withheld record is a different thing from a record with a missing field, so
 * it is a discriminated union rather than an optional property. An optional
 * field would let a withheld payload flow into a hash function or a cast and be
 * treated as broken, so a correctly redacted chain would read as forged. Behind
 * a discriminant, the compiler makes every reader say what it means by absence.
 */
export type PayloadSlot =
  | {
      readonly state: "present";
      /**
       * What the holder of the record has. Tampering can change this but not the
       * signed event, which is why the change is detectable.
       */
      readonly stored: RecordPayload;
      /**
       * The issuer's own copy, kept only so a reader can name which field
       * changed. A hash mismatch shows tampering on its own; naming the field
       * needs a reference copy, and this is it.
       */
      readonly issuer: RecordPayload;
    }
  | {
      readonly state: "withheld";
    };

/** Builds the present case. The only way to put a payload into a record. */
export function disclosedPayload(stored: RecordPayload, issuer: RecordPayload = stored): PayloadSlot {
  return { state: "present", stored, issuer };
}

/** Builds the withheld case. Deliberately verbose at the call site. */
export function withheldPayload(): PayloadSlot {
  return { state: "withheld" };
}

export interface LedgerRecord {
  /** Human label for display, e.g. "Acceptance". */
  label: string;
  event: SignedEvent;
  payload: PayloadSlot;
  anchor: AnchorReceipt | null;
  /**
   * Result of re-fetching the anchor transaction from its chain and confirming
   * it carries this event's hash. Distinct from `anchor` being set, which only
   * means the anchor call returned a receipt. Null until that re-check has run.
   */
  chainVerification: LedgerVerificationResult | null;
}

export function isWithheld(record: LedgerRecord): boolean {
  return record.payload.state === "withheld";
}

/**
 * The stored payload, or null when it was not disclosed.
 *
 * Collapsing withheld and absent to null suits code that only displays a fact.
 * Code that must tell the two apart, such as verification and blast radius,
 * should check `payload.state` directly.
 */
export function storedPayloadOf(record: LedgerRecord): RecordPayload | null {
  return record.payload.state === "present" ? record.payload.stored : null;
}

export function issuerPayloadOf(record: LedgerRecord): RecordPayload | null {
  return record.payload.state === "present" ? record.payload.issuer : null;
}

/**
 * What verification could establish about this record's payload.
 *
 * Three values rather than a boolean, because absence is not guilt. `withheld`
 * means the payload was not disclosed while the record's signature and chain
 * position still verify. `mismatch` means a payload was supplied and does not
 * hash to what was signed, which is a detected change. Treating the two alike
 * would accuse whoever redacted a chain on purpose.
 */
export type PayloadState = "verified" | "withheld" | "mismatch";

export interface RecordVerdict {
  /** Envelope hash integrity plus the issuer signature. */
  signatureValid: boolean;
  signatureIssues: VerificationIssue[];
  /** Who the signing key belongs to, and on whose word. */
  identity: IdentityDescription;
  payloadState: PayloadState;
  differences: FieldDifference[];
  counterSigned: boolean;
}
