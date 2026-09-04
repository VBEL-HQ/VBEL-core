import type {
  AnchorReceipt,
  DisclosurePayload,
  FieldDifference,
  LedgerVerificationResult,
  SignedEvent,
  VerificationIssue,
} from "@vbel/core";
import type { AcceptancePayload, DispatchPayload, SettlementPayload } from "@vbel/domain-delivery";
import type { PaymentDomainPayload } from "@vbel/domain-payment";

/**
 * Every payload shape a record in this app can carry, across both domains
 * plus the disclosure act itself.
 *
 * The delivery domain describes goods moving and settles at the end; the
 * payment domain makes the obligation the subject and treats a delivery,
 * when there is one, as attached evidence; a disclosure is about a chain
 * rather than part of one. They share this type and nothing else — a record
 * is a record to the verifier regardless of which of them issued it, which
 * is the property that lets one verifier serve all three.
 */
export type RecordPayload =
  | DispatchPayload
  | AcceptancePayload
  | SettlementPayload
  | PaymentDomainPayload
  | DisclosurePayload;

/**
 * Whether this record's payload came with the chain.
 *
 * A withheld record is a different kind of thing from a record with a
 * missing field, and the difference is deliberately expressed as a
 * discriminated union rather than as optional properties. Optional fields
 * would let a withheld payload flow into a hash function or a cast and be
 * silently treated as absent-and-therefore-broken, which is the exact
 * failure this whole change exists to prevent: a correctly redacted chain
 * reading as a forged one.
 *
 * Because the payload is behind a discriminant, `record.storedPayload` no
 * longer exists and the compiler forces every reader to say what it means
 * by absence. That is the point, and it is worth the churn.
 */
export type PayloadSlot =
  | {
      readonly state: "present";
      /**
       * What the record store currently holds. Tampering mutates this and
       * nothing else — the signed event is never touched, which is exactly
       * why the tampering becomes detectable.
       */
      readonly stored: RecordPayload;
      /**
       * The issuer's own copy, kept only so the UI can name which field
       * changed. A hash mismatch proves tampering on its own; naming the
       * field needs a trusted reference, and this is it.
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
  /** Human label for the timeline, e.g. "Acceptance". */
  label: string;
  event: SignedEvent;
  payload: PayloadSlot;
  anchor: AnchorReceipt | null;
  /**
   * Result of re-fetching the anchor transaction from its chain and
   * confirming it still carries this event's hash — distinct from `anchor`
   * being set, which only means the anchor call itself returned a receipt.
   * Null until that re-check has run.
   */
  chainVerification: LedgerVerificationResult | null;
}

export function isWithheld(record: LedgerRecord): boolean {
  return record.payload.state === "withheld";
}

/**
 * The stored payload, or null when it was not disclosed.
 *
 * Collapsing withheld and absent to null is correct for readers that only
 * want to display a business fact: an amount you were not shown and an
 * amount that is not in the chain are equally undisplayable. Readers that
 * must tell the two apart — the verifier, the blast radius, the work queue
 * — check `payload.state` directly instead of calling this.
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
 * Three values, not a boolean, because absence is not guilt. `withheld`
 * means the payload was deliberately not disclosed and the record's
 * signature and chain position still verify perfectly. `mismatch` means a
 * payload was supplied and does not hash to what was signed, which is a
 * detected forgery. Rendering or reasoning about them alike accuses whoever
 * performed a lawful redaction.
 */
export type PayloadState = "verified" | "withheld" | "mismatch";

export interface RecordVerdict {
  /** Envelope hash integrity plus the issuer signature. */
  signatureValid: boolean;
  signatureIssues: VerificationIssue[];
  /**
   * False when no IdentityResolver was supplied. In this app's demo
   * scenario, checked against a live ENS text record on Sepolia when
   * ENS_PARENT_NAME is configured, falling back to a small in-memory
   * registry otherwise — see lib/identity.ts.
   */
  identityChecked: boolean;
  payloadState: PayloadState;
  differences: FieldDifference[];
  counterSigned: boolean;
}
