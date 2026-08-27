import { z } from "zod";
import { SignatureBlockSchema } from "./envelope.js";

/**
 * Who a signing key actually belongs to.
 *
 * Without this, verification only ever proves internal consistency: "some
 * key signed this envelope, and here is that key". Anyone can generate a
 * keypair, claim `issuerId: supplier-a`, and produce a record that verifies
 * perfectly. Binding an issuerId to a key is a claim about the world, and a
 * claim about the world needs someone willing to make it.
 *
 * That someone is `attestedBy`. This file defines the shape of the claim and
 * the contract for looking one up; it deliberately says nothing about where
 * attestations come from. A static registry, ENS, did:web and an eIDAS
 * certificate authority are all just implementations of IdentityResolver.
 */

export const IssuerAttestationSchema = z.object({
  issuerId: z.string().min(1),
  /** Hex-encoded ed25519 public key, matching SignatureBlock.publicKey. */
  publicKey: z.string().min(1),
  /** Who vouches for this binding. */
  attestedBy: z.string().min(1),
  validFrom: z.string().datetime({ offset: true }),
  /** Null means open-ended — valid until something supersedes it. */
  validUntil: z.string().datetime({ offset: true }).nullable().default(null),
  /**
   * The attestor's signature over this attestation minus this field.
   *
   * Null is legitimate and means the resolver itself is the trust root: you
   * trust the binding because you chose to configure that resolver. A signed
   * attestation is stronger — it can be relayed by an untrusted party and
   * still checked — but it only moves the question up one level, to whether
   * the attestor's own key is known. Somewhere there is always a root that is
   * trusted rather than proven, and it is better to be explicit about where.
   */
  signature: SignatureBlockSchema.nullable().default(null),
});
export type IssuerAttestation = z.infer<typeof IssuerAttestationSchema>;

/**
 * Resolution is time-scoped: an event signed in January must be checked
 * against the key that was valid in January, not against whatever key the
 * issuer rotated to since. Passing `at` rather than reading a clock is what
 * makes a record from years ago still verifiable — which the 10-year
 * retention obligation in TECHNICAL-BRIEF.md §2 requires.
 */
export interface IdentityResolver {
  resolve(issuerId: string, at: string): Promise<IssuerAttestation | null>;
}

export type AttestationWindow = "VALID" | "NOT_YET_VALID" | "EXPIRED";

export function checkAttestationWindow(
  attestation: IssuerAttestation,
  at: string
): AttestationWindow {
  const instant = Date.parse(at);
  if (instant < Date.parse(attestation.validFrom)) return "NOT_YET_VALID";
  if (attestation.validUntil !== null && instant >= Date.parse(attestation.validUntil)) {
    return "EXPIRED";
  }
  return "VALID";
}

/**
 * The region an attestation signature covers: everything except the
 * signature itself. Same rule as the event envelope — a signature is never
 * inside what it signs.
 */
export function attestationSigningRegion(
  attestation: IssuerAttestation
): Omit<IssuerAttestation, "signature"> {
  const { signature: _excluded, ...region } = attestation;
  return region;
}
