import type { AnchorReceipt, FieldDifference, LedgerVerificationResult, SignedEvent, VerificationIssue } from "@vbel/core";
import type { AcceptancePayload, DispatchPayload, SettlementPayload } from "@vbel/domain-delivery";
import type { PaymentDomainPayload } from "@vbel/domain-payment";

/**
 * Every payload shape a record in this app can carry, across both domains.
 *
 * The delivery domain describes goods moving and settles at the end; the
 * payment domain makes the obligation itself the subject and treats a
 * delivery, when there is one, as attached evidence. They share this type
 * and nothing else — a record is a record to the verifier regardless of
 * which domain issued it, which is the property that lets one verifier
 * serve both.
 */
export type RecordPayload =
  | DispatchPayload
  | AcceptancePayload
  | SettlementPayload
  | PaymentDomainPayload;

/** @deprecated Use RecordPayload — kept while call sites migrate. */
export type DeliveryPayload = RecordPayload;

export interface LedgerRecord {
  /** Human label for the timeline, e.g. "Acceptance". */
  label: string;
  event: SignedEvent;
  /**
   * What the record store currently holds. Tampering mutates this and
   * nothing else — the signed event is never touched, which is exactly why
   * the tampering becomes detectable.
   */
  storedPayload: RecordPayload;
  /**
   * The issuer's own copy, kept only so the UI can name which field changed.
   * A hash mismatch proves tampering on its own; naming the field needs a
   * trusted reference, and this is it.
   */
  issuerPayload: RecordPayload;
  anchor: AnchorReceipt | null;
  /**
   * Result of re-fetching the anchor transaction from Solana and confirming
   * its memo still carries this event's hash — distinct from `anchor` being
   * set, which only means the anchor call itself returned a receipt. Null
   * until that re-check has run.
   */
  chainVerification: LedgerVerificationResult | null;
}

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
  /** Does the stored document still hash to what was signed. */
  payloadValid: boolean;
  differences: FieldDifference[];
  counterSigned: boolean;
}
