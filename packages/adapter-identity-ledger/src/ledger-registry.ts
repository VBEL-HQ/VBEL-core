import {
  assuranceOf,
  checkAttestationWindow,
  type Assurance,
  type EntityRegistrationPayload,
  type IdentityResolver,
  type IssuerAttestation,
} from "@vbel/core";

/**
 * Resolves issuers from registration records the reader already holds.
 *
 * The difference from a static registry is who has to be trusted. A file
 * registry answers because the verifier configured it; this answers because
 * somebody signed a claim that travelled with the chain, and the reader can see
 * who that was. It does not make the claim true, only inspectable, which is the
 * most a verifier that consults nobody can offer.
 *
 * Registrations arrive inside a chain like everything else, so this takes
 * payloads and fetches nothing. A resolver that called a server would add a
 * network dependency to an operation that should work offline.
 */
export class LedgerIdentityRegistry implements IdentityResolver {
  private readonly byEntity = new Map<string, EntityRegistrationPayload[]>();
  readonly registryId = "urn:vbel:registry:ledger";

  constructor(registrations: EntityRegistrationPayload[]) {
    for (const registration of registrations) {
      const existing = this.byEntity.get(registration.entityId) ?? [];
      existing.push(registration);
      this.byEntity.set(registration.entityId, existing);
    }
  }

  private candidates(issuerId: string, at: string): EntityRegistrationPayload[] {
    return (this.byEntity.get(issuerId) ?? []).filter(
      (registration) => checkAttestationWindow(toAttestation(registration), at) === "VALID"
    );
  }

  /**
   * A vouch corroborates a key. It must never introduce one.
   *
   * Preferring vouched registrations would be wrong. Somebody else's word does
   * raise what a binding is worth, but it does not decide which key to use, and
   * anyone can sign a registration naming any entity. A stranger could vouch
   * for an entity with a key they control and displace the key its owner
   * registered.
   *
   * A self-asserted registration is signed by the very key it registers, so it
   * proves possession, which is all resolution needs. Vouches are reported
   * separately, where a reader can weigh them. Between two of equal standing
   * the later wins, so re-registering is how an entity rotates a key.
   */
  async resolve(issuerId: string, at: string): Promise<IssuerAttestation | null> {
    const best = this.best(issuerId, at);
    return best ? toAttestation(best) : null;
  }

  /** What the resolved identity is worth. Null when nothing resolved. */
  assuranceFor(issuerId: string, at: string): Assurance | null {
    const best = this.best(issuerId, at);
    return best ? assuranceOf(best) : null;
  }

  /** The registration that answered, for a reader who wants to see the claim itself. */
  registrationFor(issuerId: string, at: string): EntityRegistrationPayload | null {
    return this.best(issuerId, at);
  }

  /** Every entity this reader knows about, for naming and for choosing a recipient. */
  entities(): EntityRegistrationPayload[] {
    const now = new Date().toISOString();
    return [...this.byEntity.keys()]
      .map((entityId) => this.best(entityId, now))
      .filter((registration): registration is EntityRegistrationPayload => registration !== null)
      .sort((a, b) => a.displayName.localeCompare(b.displayName));
  }

  private best(issuerId: string, at: string): EntityRegistrationPayload | null {
    const candidates = this.candidates(issuerId, at);
    if (candidates.length === 0) return null;

    return candidates.reduce((winner, candidate) => {
      const winnerProvesPossession = assuranceOf(winner) === "self-asserted";
      const candidateProvesPossession = assuranceOf(candidate) === "self-asserted";
      if (candidateProvesPossession !== winnerProvesPossession) {
        return candidateProvesPossession ? candidate : winner;
      }
      return Date.parse(candidate.registeredAt) > Date.parse(winner.registeredAt) ? candidate : winner;
    });
  }
}

function toAttestation(registration: EntityRegistrationPayload): IssuerAttestation {
  return {
    issuerId: registration.entityId,
    publicKey: registration.publicKey,
    attestedBy: registration.attestedBy ?? registration.entityId,
    validFrom: registration.registeredAt,
    validUntil: registration.validUntil,
    // The signature that matters is the envelope's, over the whole registration
    // event, and verifyEvent checks it like any other. It is not repeated here,
    // so nobody checks a weaker copy.
    signature: null,
  };
}
