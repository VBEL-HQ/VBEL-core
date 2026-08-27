import type { AnchorReceipt, FieldDifference, LedgerVerificationResult, SignedEvent, VerificationIssue } from "@vbel/core";
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
