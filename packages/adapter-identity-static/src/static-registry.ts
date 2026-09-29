import { z } from "zod";
import {
  IssuerAttestationSchema,
  checkAttestationWindow,
  type IdentityResolver,
  type IssuerAttestation,
} from "@vbel/core";

/**
 * An IdentityResolver backed by an explicit list of attestations.
 *
 * The trust root is the registry itself: you believe `supplier-a` owns a key
 * because you chose to load a file that says so. That is weaker than a signed
 * attestation chain, and it is a registry you can read in full rather than a
 * resolver that looks authoritative and is not.
 *
 * A registry served over the network, ENS text records or a certificate chain
 * all satisfy the same interface, so events verified against this one stay
 * verifiable against those without re-signing anything.
 */

export const RegistryFileSchema = z.object({
  /** Who assembled this registry. Recorded so a stored copy is self-describing. */
  registryId: z.string().min(1),
  attestations: z.array(IssuerAttestationSchema),
});
export type RegistryFile = z.infer<typeof RegistryFileSchema>;

export class StaticIdentityRegistry implements IdentityResolver {
  private readonly byIssuer = new Map<string, IssuerAttestation[]>();
  readonly registryId: string;

  constructor(file: RegistryFile) {
    const parsed = RegistryFileSchema.parse(file);
    this.registryId = parsed.registryId;

    for (const attestation of parsed.attestations) {
      const existing = this.byIssuer.get(attestation.issuerId) ?? [];
      existing.push(attestation);
      this.byIssuer.set(attestation.issuerId, existing);
    }
  }

  /** Parses untrusted JSON, such as a registry read from disk or a network response. */
  static fromJSON(raw: unknown): StaticIdentityRegistry {
    return new StaticIdentityRegistry(RegistryFileSchema.parse(raw));
  }

  /**
   * Returns the attestation in force at `at`. That is what makes key rotation
   * expressible: an issuer can hold several attestations with non-overlapping
   * windows, and an old event keeps resolving to the key that was current when
   * it was signed.
   *
   * Overlapping windows are a misconfiguration. The latest validFrom wins, so
   * the answer is at least deterministic.
   */
  async resolve(issuerId: string, at: string): Promise<IssuerAttestation | null> {
    const candidates = (this.byIssuer.get(issuerId) ?? []).filter(
      (attestation) => checkAttestationWindow(attestation, at) === "VALID"
    );
    if (candidates.length === 0) return null;

    return candidates.reduce((latest, candidate) =>
      Date.parse(candidate.validFrom) > Date.parse(latest.validFrom) ? candidate : latest
    );
  }

  /** Every issuer the registry knows, for operator inspection. */
  issuers(): string[] {
    return [...this.byIssuer.keys()].sort();
  }
}
