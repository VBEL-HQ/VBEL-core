import { describe, expect, it } from "vitest";
import { StaticIdentityRegistry } from "../src/static-registry.js";

const SUPPLIER = "urn:vbel:org:supplier-a";

function file(attestations: unknown[]) {
  return { registryId: "urn:vbel:registry:test", attestations };
}

describe("StaticIdentityRegistry", () => {
  it("resolves an issuer whose window covers the event time", async () => {
    const registry = StaticIdentityRegistry.fromJSON(
      file([
        {
          issuerId: SUPPLIER,
          publicKey: "aa".repeat(32),
          attestedBy: "urn:vbel:registry:test",
          validFrom: "2026-01-01T00:00:00.000Z",
          validUntil: null,
        },
      ])
    );

    const resolved = await registry.resolve(SUPPLIER, "2026-08-25T10:00:00.000Z");
    expect(resolved?.publicKey).toBe("aa".repeat(32));
  });

  it("returns null for an unknown issuer rather than throwing", async () => {
    const registry = StaticIdentityRegistry.fromJSON(file([]));
    expect(await registry.resolve(SUPPLIER, "2026-08-25T10:00:00.000Z")).toBeNull();
  });

  it("resolves key rotation by the time the event was signed, not by recency", async () => {
    const registry = StaticIdentityRegistry.fromJSON(
      file([
        {
          issuerId: SUPPLIER,
          publicKey: "old".padEnd(64, "0"),
          attestedBy: "urn:vbel:registry:test",
          validFrom: "2026-01-01T00:00:00.000Z",
          validUntil: "2026-06-01T00:00:00.000Z",
        },
        {
          issuerId: SUPPLIER,
          publicKey: "new".padEnd(64, "0"),
          attestedBy: "urn:vbel:registry:test",
          validFrom: "2026-06-01T00:00:00.000Z",
          validUntil: null,
        },
      ])
    );

    // An event from before the rotation must still resolve to the old key,
    // or every record signed before a rotation would stop verifying.
    expect((await registry.resolve(SUPPLIER, "2026-03-01T00:00:00.000Z"))?.publicKey).toBe(
      "old".padEnd(64, "0")
    );
    expect((await registry.resolve(SUPPLIER, "2026-08-01T00:00:00.000Z"))?.publicKey).toBe(
      "new".padEnd(64, "0")
    );
  });

  it("rejects a malformed registry at load rather than at resolve time", () => {
    expect(() => StaticIdentityRegistry.fromJSON({ registryId: "x", attestations: [{ issuerId: "" }] })).toThrow();
    expect(() => StaticIdentityRegistry.fromJSON({ attestations: [] })).toThrow();
  });

  it("lists the issuers it knows, for operator inspection", () => {
    const registry = StaticIdentityRegistry.fromJSON(
      file([
        {
          issuerId: "urn:vbel:org:buyer-b",
          publicKey: "bb".repeat(32),
          attestedBy: "urn:vbel:registry:test",
          validFrom: "2026-01-01T00:00:00.000Z",
        },
        {
          issuerId: SUPPLIER,
          publicKey: "aa".repeat(32),
          attestedBy: "urn:vbel:registry:test",
          validFrom: "2026-01-01T00:00:00.000Z",
        },
      ])
    );

    expect(registry.issuers()).toEqual(["urn:vbel:org:buyer-b", SUPPLIER]);
  });
});
