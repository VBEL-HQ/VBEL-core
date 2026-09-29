import { z } from "zod";
import { SignatureBlockSchema } from "./envelope.js";

/**
 * Who a signing key belongs to.
 *
 * Without this, verification proves only internal consistency: some key signed
 * this envelope. Anyone can generate a keypair, claim `issuerId: supplier-a`,
 * and produce a record that verifies. Binding an issuerId to a key is a claim
 * about the world, and it needs someone willing to make it. That someone is
 * `attestedBy`.
 *
 * This file defines the shape of the claim and the contract for looking one
 * up. It says nothing about where attestations come from: a static registry,
 * ENS, did:web or a certificate authority are all implementations of
 * IdentityResolver.
 */

export const IssuerAttestationSchema = z.object({
  issuerId: z.string().min(1),
  /** Hex-encoded ed25519 public key, matching SignatureBlock.publicKey. */
  publicKey: z.string().min(1),
  /** Who vouches for this binding. */
  attestedBy: z.string().min(1),
  validFrom: z.string().datetime({ offset: true }),
  /** Null means open-ended: valid until something supersedes it. */
  validUntil: z.string().datetime({ offset: true }).nullable().default(null),
  /**
   * The attestor's signature over this attestation minus this field.
   *
   * Null is legitimate and means the resolver itself is the trust root: the
   * binding is trusted because the verifier chose to configure that resolver.
   * A signed attestation can be relayed by an untrusted party and still be
   * checked, but it only moves the question up one level, to whether the
   * attestor's own key is known. Some root is always trusted rather than
   * proven, and this makes it explicit.
   */
  signature: SignatureBlockSchema.nullable().default(null),
});
export type IssuerAttestation = z.infer<typeof IssuerAttestationSchema>;

/**
 * Resolution is time-scoped: an event signed in January is checked against the
 * key that was valid in January, not the key the issuer rotated to since.
 * Taking `at` as a parameter rather than reading a clock keeps old records
 * verifiable.
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

/** The region an attestation signature covers: everything except the signature itself. */
export function attestationSigningRegion(
  attestation: IssuerAttestation
): Omit<IssuerAttestation, "signature"> {
  const { signature: _excluded, ...region } = attestation;
  return region;
}
