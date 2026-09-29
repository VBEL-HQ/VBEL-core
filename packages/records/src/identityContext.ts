import { LedgerIdentityRegistry } from "@vbel/adapter-identity-ledger";
import type { EntityRegistrationPayload, IdentityResolver, IssuerAttestation } from "@vbel/core";

/**
 * Where a reader's answer to "who signed this" comes from, beyond the
 * registrations carried in the chain.
 */
export interface IdentityContextOptions {
  /**
   * A root the reader trusts by configuration (an ENS name, a file of known
   * keys), asked before the registrations in the chain. Optional: with none,
   * every identity is whatever the chain's own registrations say, at the
   * assurance they carry.
   */
  configured?: () => Promise<IdentityResolver>;
  /** What to call an issuer with no registration. Defaults to the slug after `urn:vbel:org:`. */
  nameFor?: (issuerId: string) => string;
}

/**
 * What a resolved issuer is actually worth, so a reader is never shown a
 * bare tick that hides the difference.
 *
 *   vouched        another entity signed a registration for this key
 *   self-asserted  the entity signed its own registration, proving key
 *                  possession and nothing about the name
 *   configured     a registry this deployment ships answered, which is a
 *                  claim about our configuration rather than about the world
 *   unknown        nothing resolved
 */
export type IdentityAssurance = "vouched" | "self-asserted" | "configured" | "unknown";

export interface IdentityDescription {
  name: string;
  assurance: IdentityAssurance;
  registration: EntityRegistrationPayload | null;
  /**
   * Entities that signed a registration for this key, other than the key's
   * own owner. Reported alongside the resolution rather than replacing it:
   * anyone can vouch for anyone, so a vouch must never be able to decide
   * which public key is trusted. What it can do is tell a reader who else
   * has put their name to this binding, which is a fact they can weigh.
   *
   * A vouch only counts when it attests the same key that actually
   * resolved. One naming a different key is vouching for a different
   * signer, and counting it would be the whole attack.
   */
  vouchedBy: string[];
}

export interface IdentityContext {
  resolver: IdentityResolver;
  describe(issuerId: string, at: string): Promise<IdentityDescription>;
}

/** What to call an issuer nobody has registered: the slug, so a reader can still match it against the envelope. */
function defaultNameFor(issuerId: string): string {
  return issuerId.replace("urn:vbel:org:", "");
}

/**
 * Builds the trust roots for a reader, in the order they get asked.
 *
 * The order is a security decision, not a preference. Registrations carried
 * in a chain are asked *last*, because anyone can sign a registration
 * claiming any entityId, and a self asserted claim must never be able to
 * displace a stronger root that already answers for that issuer. Adding a
 * root can only widen who resolves, never narrow it, so the widest and
 * weakest goes at the back.
 */
export function buildIdentityContext(
  registrations: EntityRegistrationPayload[],
  options: IdentityContextOptions = {}
): IdentityContext {
  const nameFor = options.nameFor ?? defaultNameFor;
  const displayNameFor = (issuerId: string, registration: EntityRegistrationPayload | null): string =>
    registration?.displayName ?? nameFor(issuerId);
  const configuredFor = (issuerId: string, at: string): Promise<IssuerAttestation | null> =>
    options.configured
      ? options.configured().then((resolver) => resolver.resolve(issuerId, at)).catch(() => null)
      : Promise.resolve(null);

  const ledger = new LedgerIdentityRegistry(registrations);

  return {
    resolver: {
      async resolve(issuerId: string, at: string) {
        const configured = await configuredFor(issuerId, at);
        if (configured) return configured;
        return ledger.resolve(issuerId, at);
      },
    },

    async describe(issuerId: string, at: string): Promise<IdentityDescription> {
      const configured = await configuredFor(issuerId, at);
      const registration = ledger.registrationFor(issuerId, at);
      const resolvedKey = configured?.publicKey ?? registration?.publicKey ?? null;

      const vouchedBy = registrations
        .filter(
          (claim) =>
            claim.entityId === issuerId &&
            claim.attestedBy !== null &&
            claim.attestedBy !== issuerId &&
            resolvedKey !== null &&
            claim.publicKey === resolvedKey
        )
        .map((claim) => claim.attestedBy!)
        .filter((voucher, i, all) => all.indexOf(voucher) === i);

      if (configured) {
        const named = registrations.find((claim) => claim.entityId === issuerId) ?? null;
        return {
          name: displayNameFor(issuerId, named),
          assurance: vouchedBy.length > 0 ? "vouched" : "configured",
          registration: named,
          vouchedBy,
        };
      }

      if (!registration) {
        return { name: displayNameFor(issuerId, null), assurance: "unknown", registration: null, vouchedBy: [] };
      }

      return {
        name: displayNameFor(issuerId, registration),
        assurance: vouchedBy.length > 0 ? "vouched" : (ledger.assuranceFor(issuerId, at) ?? "unknown"),
        registration,
        vouchedBy,
      };
    },
  };
}

/** Every entity a reader knows about, for naming and for choosing a recipient. */
export function knownEntities(registrations: EntityRegistrationPayload[]): EntityRegistrationPayload[] {
  return new LedgerIdentityRegistry(registrations).entities();
}
