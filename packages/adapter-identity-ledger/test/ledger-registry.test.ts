import { describe, expect, it } from "vitest";
import type { EntityRegistrationPayload } from "@vbel/core";
import { LedgerIdentityRegistry } from "../src/ledger-registry.js";

const CURVY = "urn:vbel:org:curvy";
const KEY_SELF = "aa".repeat(32);
const KEY_VOUCHED = "bb".repeat(32);

function registration(over: Partial<EntityRegistrationPayload> = {}): EntityRegistrationPayload {
  return {
    entityId: CURVY,
    displayName: "Curvy",
    publicKey: KEY_SELF,
    role: null,
    registeredAt: "2026-09-01T00:00:00.000Z",
    validUntil: null,
    attestedBy: null,
    ...over,
  };
}

const AT = "2026-09-10T00:00:00.000Z";

describe("LedgerIdentityRegistry", () => {
  it("resolves an entity that registered itself, and says the claim is only self asserted", async () => {
    const registry = new LedgerIdentityRegistry([registration()]);

    expect((await registry.resolve(CURVY, AT))?.publicKey).toBe(KEY_SELF);
    expect(registry.assuranceFor(CURVY, AT)).toBe("self-asserted");
  });

  /**
   * The ranking that carries the whole point. Anyone can sign their own
   * registration, so a claim somebody else put their name to outranks it.
   */
  it("prefers a vouched registration over a self asserted one", async () => {
    const registry = new LedgerIdentityRegistry([
      registration(),
      registration({ publicKey: KEY_VOUCHED, attestedBy: "urn:vbel:org:supplier-a" }),
    ]);

    expect((await registry.resolve(CURVY, AT))?.publicKey).toBe(KEY_VOUCHED);
    expect(registry.assuranceFor(CURVY, AT)).toBe("vouched");
  });

  it("treats a later registration of equal standing as a key rotation", async () => {
    const registry = new LedgerIdentityRegistry([
      registration(),
      registration({ publicKey: KEY_VOUCHED, registeredAt: "2026-09-05T00:00:00.000Z" }),
    ]);

    expect((await registry.resolve(CURVY, AT))?.publicKey).toBe(KEY_VOUCHED);
  });

  it("resolves an old event to the key that was current when it was signed", async () => {
    const registry = new LedgerIdentityRegistry([
      registration({ validUntil: "2026-09-04T00:00:00.000Z" }),
      registration({ publicKey: KEY_VOUCHED, registeredAt: "2026-09-05T00:00:00.000Z" }),
    ]);

    expect((await registry.resolve(CURVY, "2026-09-02T00:00:00.000Z"))?.publicKey).toBe(KEY_SELF);
    expect((await registry.resolve(CURVY, AT))?.publicKey).toBe(KEY_VOUCHED);
  });

  it("returns null for an entity it has never seen registered", async () => {
    const registry = new LedgerIdentityRegistry([registration()]);

    expect(await registry.resolve("urn:vbel:org:nobody", AT)).toBeNull();
    expect(registry.assuranceFor("urn:vbel:org:nobody", AT)).toBeNull();
  });

  it("lists what it knows, for naming and for choosing a recipient", () => {
    const registry = new LedgerIdentityRegistry([
      registration(),
      registration({ entityId: "urn:vbel:org:auditor-a", displayName: "Auditor A" }),
    ]);

    expect(registry.entities().map((e) => e.displayName)).toEqual(["Auditor A", "Curvy"]);
  });
});
