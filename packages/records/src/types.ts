import type { AnchorReceipt, FieldDifference, SignedEvent, VerificationIssue } from "@vbel/core";
import type { AcceptancePayload, DispatchPayload } from "@vbel/domain-delivery";

export type DeliveryPayload = DispatchPayload | AcceptancePayload;

export interface LedgerRecord {
  /** Human label for the timeline, e.g. "Acceptance". */
  label: string;
  event: SignedEvent;
  /**
   * What the record store currently holds. Tampering mutates this and
   * nothing else — the signed event is never touched, which is exactly why
   * the tampering becomes detectable.
   */
  storedPayload: DeliveryPayload;
  /**
   * The issuer's own copy, kept only so the UI can name which field changed.
   * A hash mismatch proves tampering on its own; naming the field needs a
   * trusted reference, and this is it.
   */
  issuerPayload: DeliveryPayload;
  anchor: AnchorReceipt | null;
}

export interface RecordVerdict {
  /** Envelope hash integrity plus the issuer signature. */
  signatureValid: boolean;
  signatureIssues: VerificationIssue[];
  /**
   * False when no IdentityResolver was supplied, which is the current state
   * of this app: signatures are checked against the key embedded in the
   * event, and nothing confirms that key belongs to the issuer it names.
   */
  identityChecked: boolean;
  /** Does the stored document still hash to what was signed. */
  payloadValid: boolean;
  differences: FieldDifference[];
  counterSigned: boolean;
}
