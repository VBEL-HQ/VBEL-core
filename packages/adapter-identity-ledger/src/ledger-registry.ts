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
 * registry answers because we configured it; this answers because somebody
 * signed a claim that travelled with the chain, and the reader can see who
 * that somebody was. It does not make the claim true. It makes the claim
 * inspectable, which is the most a verifier that consults nobody can offer.
 *
 * Registrations arrive the same way everything else does, inside a chain,
 * so this deliberately takes payloads rather than fetching anything. A
 * resolver that reached out to a server would put a network dependency in
 * the middle of the one operation this product promises works offline.
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
   * A registration somebody else signed outranks one the entity signed for
   * itself, because self assertion proves only key possession. Between two
   * of equal standing the later one wins, so re-registering is how an entity
   * rotates a key rather than a way to accumulate contradictions.
   */
  async resolve(issuerId: string, at: string): Promise<IssuerAttestation | null> {
    const best = this.best(issuerId, at);
    return best ? toAttestation(best) : null;
  }

  /** What the resolved identity is actually worth. Null when nothing resolved. */
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
      const winnerVouched = assuranceOf(winner) === "vouched";
      const candidateVouched = assuranceOf(candidate) === "vouched";
      if (candidateVouched !== winnerVouched) return candidateVouched ? candidate : winner;
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
    // The signature that matters is the envelope's, over the whole
    // registration event, and it is checked by verifyEvent like any other.
    // Duplicating it here would invite someone to check the weaker copy.
    signature: null,
  };
}
