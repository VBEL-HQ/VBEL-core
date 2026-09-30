import { describe, expect, it } from "vitest";
import { validateChain } from "@vbel/core";
import {
  buildDisclosure,
  buildIdentityContext,
  buildRevocation,
  buildSelfRegistration,
  buildVouch,
  ChainDecodeError,
  computeBlastRadius,
  decodeChain,
  encodeChain,
  encodeWithIdentity,
  isWithheld,
  readCoverSheet,
  redactChain,
  planHandoff,
  registrationsIn,
  splitHandoff,
  standingRegistrations,
  storedPayloadOf,
  verifyAll,
  verifyRecord,
  type LedgerRecord,
} from "../src/index.js";
import { AUTHOR, chainOfThree, noteRecord, SCHEMAS, type Note } from "./fixtures.js";
import { generateKeyPair } from "@vbel/core";

const ids = (records: LedgerRecord[]) => records.map((r) => r.event.envelope.eventId);

describe("codec", () => {
  it("round trips a chain through a link, payloads included", async () => {
    const { records } = await chainOfThree();
    const decoded = await decodeChain(await encodeChain(records), SCHEMAS);
    expect(decoded).toEqual(records);
  });

  it("rejects a schema nobody registered, rather than passing it through", async () => {
    const { records } = await chainOfThree();
    await expect(decodeChain(await encodeChain(records))).rejects.toThrow(/unrecognized envelope schema/);
  });

  it("rejects a payload that does not fit the schema it was registered under", async () => {
    const { keys } = await chainOfThree();
    const bad = await noteRecord(keys, { text: "x", amount: "not a number" } as unknown as Note, null);
    await expect(decodeChain(await encodeChain([bad]), SCHEMAS)).rejects.toThrow(ChainDecodeError);
  });

  it("does not let a caller override the built-in schemas", async () => {
    const { registration } = await chainOfThree();
    const decoded = await decodeChain(await encodeChain([registration]), {
      "urn:vbel:event:entity-registered:v1": SCHEMAS["urn:example:event:note:v1"]!,
    });
    expect(decoded).toHaveLength(1);
  });

  it("accepts a payload that was withheld on purpose and rejects one that just went missing", async () => {
    const { records } = await chainOfThree();
    const redacted = redactChain(records, []);
    expect(await decodeChain(await encodeChain(redacted), SCHEMAS)).toHaveLength(3);

    const stripped = JSON.parse(JSON.stringify(records));
    delete stripped[0].payload;
    const { gzipSync } = await import("node:zlib");
    const link = gzipSync(JSON.stringify(stripped)).toString("base64url");
    await expect(decodeChain(link, SCHEMAS)).rejects.toThrow(/no payload slot/);
  });

  it("refuses garbage without throwing anything but a decode error", async () => {
    await expect(decodeChain("!!!not base64!!!", SCHEMAS)).rejects.toThrow(ChainDecodeError);
  });
});

describe("verification", () => {
  it("verifies a registered author's records, and names how much the name is worth", async () => {
    const { records, registration } = await chainOfThree();
    const verdicts = await verifyAll(records, buildIdentityContext(registrationsIn([registration])));
    for (const record of records) {
      const verdict = verdicts.get(record.event.envelope.eventId)!;
      expect(verdict.signatureValid).toBe(true);
      expect(verdict.payloadState).toBe("verified");
      expect(verdict.identity).toMatchObject({ name: "The Author Ltd", assurance: "self-asserted" });
    }
  });

  it("does not turn an unregistered signer into a bad signature", async () => {
    const { records } = await chainOfThree();
    const verdict = await verifyRecord(records[0]!, buildIdentityContext([]));
    expect(verdict.signatureValid).toBe(true);
    expect(verdict.identity.assurance).toBe("unknown");
  });

  it("never names a company for a record signed by a key other than the one that resolves", async () => {
    const { records, registration } = await chainOfThree();
    const stranger = await generateKeyPair();
    const later = await buildSelfRegistration({
      keys: stranger,
      entityId: AUTHOR,
      displayName: "The Author Ltd",
      // After the author's own registration and before the records were signed,
      // which is all it takes to be the one that resolves: the later of two
      // self registrations wins, because that is how a key is rotated.
      at: "2026-08-05T00:00:00.000Z",
    });
    const context = buildIdentityContext(registrationsIn([registration, later]));
    expect((await context.resolver.resolve(AUTHOR, records[0]!.event.envelope.issuedAt))?.publicKey).toBe(stranger.publicKeyHex);

    const verdict = await verifyRecord(records[0]!, context);
    expect(verdict.signatureValid).toBe(true);
    expect(verdict.identity.assurance).toBe("unknown");
    expect(verdict.identity.registration).toBeNull();
  });

  it("detects an edited payload and says which field", async () => {
    const { records, registration } = await chainOfThree();
    const first = records[0]!;
    const tampered: LedgerRecord = {
      ...first,
      payload: { state: "present", issuer: (first.payload as { issuer: object }).issuer, stored: { text: "first", amount: 999 } },
    };
    const verdict = await verifyRecord(tampered, buildIdentityContext(registrationsIn([registration])));
    expect(verdict.payloadState).toBe("mismatch");
    expect(verdict.differences.map((d) => d.path)).toEqual(["$.amount"]);
    expect(verdict.signatureValid).toBe(true);
  });

  it("treats a withheld payload as withheld, never as a forgery", async () => {
    const { records, registration } = await chainOfThree();
    const [verdict] = await Promise.all(
      redactChain(records, []).map((r) => verifyRecord(r, buildIdentityContext(registrationsIn([registration]))))
    );
    expect(verdict!.payloadState).toBe("withheld");
    expect(verdict!.signatureValid).toBe(true);
  });

  it("keeps the whole structure verifiable with every payload removed", async () => {
    const { records } = await chainOfThree();
    const redacted = redactChain(records, []);
    expect(redacted.every(isWithheld)).toBe(true);
    expect(validateChain(redacted.map((r) => r.event)).valid).toBe(true);
  });

  it("marks a record whose ancestor was edited, and does not mark descendants of a redaction", async () => {
    const { records, registration } = await chainOfThree();
    const context = buildIdentityContext(registrationsIn([registration]));

    const first = records[0]!;
    const edited = [
      { ...first, payload: { state: "present" as const, issuer: (first.payload as { issuer: object }).issuer, stored: { text: "first", amount: 1 } } },
      records[1]!,
      records[2]!,
    ];
    const contaminated = computeBlastRadius(edited, await verifyAll(edited, context));
    expect([...contaminated.get(records[2]!.event.envelope.eventId)!]).toEqual([first.event.envelope.eventId]);

    const redacted = redactChain(records, []);
    const clean = computeBlastRadius(redacted, await verifyAll(redacted, context));
    expect([...clean.values()].every((set) => set.size === 0)).toBe(true);
  });
});

describe("identity claims", () => {
  it("reports a vouch beside the key, and never lets it introduce one", async () => {
    const author = await generateKeyPair();
    const notary = await generateKeyPair();
    const stranger = await generateKeyPair();
    const self = await buildSelfRegistration({ keys: author, entityId: AUTHOR, displayName: "The Author Ltd" });
    const vouch = await buildVouch({
      keys: notary,
      voucherId: "urn:vbel:org:notary",
      subject: storedPayloadOf(self) as never,
      previousEventHash: self.event.eventHash,
    });
    // a stranger vouching for the author's name with the stranger's own key
    const hijack = await buildVouch({
      keys: stranger,
      voucherId: "urn:vbel:org:stranger",
      subject: { ...(storedPayloadOf(self) as object), publicKey: stranger.publicKeyHex } as never,
    });

    const described = await buildIdentityContext(registrationsIn([self, vouch, hijack])).describe(AUTHOR, new Date().toISOString());
    expect(described.registration?.publicKey).toBe(author.publicKeyHex);
    expect(described.vouchedBy).toEqual(["urn:vbel:org:notary"]);
    expect(described.assurance).toBe("vouched");
  });

  it("honours a withdrawal only from whoever made the claim", async () => {
    const author = await generateKeyPair();
    const notary = await generateKeyPair();
    const other = await generateKeyPair();
    const self = await buildSelfRegistration({ keys: author, entityId: AUTHOR, displayName: "The Author Ltd" });
    const vouch = await buildVouch({
      keys: notary,
      voucherId: "urn:vbel:org:notary",
      subject: storedPayloadOf(self) as never,
      previousEventHash: self.event.eventHash,
    });
    const byOther = await buildRevocation({ keys: other, issuerId: "urn:vbel:org:other", target: vouch, reason: "no" });
    const byNotary = await buildRevocation({ keys: notary, issuerId: "urn:vbel:org:notary", target: vouch, reason: "changed my mind" });

    expect(standingRegistrations([self, vouch, byOther])).toContain(vouch);
    expect(standingRegistrations([self, vouch, byNotary])).not.toContain(vouch);
  });

  it("carries only the claims of people who signed something in the link", async () => {
    const { records, registration } = await chainOfThree();
    const bystander = await buildSelfRegistration({
      keys: await generateKeyPair(),
      entityId: "urn:vbel:org:bystander",
      displayName: "Bystander",
    });
    const { handed, omitted } = await planHandoff(records, [registration, bystander]);
    expect(ids(handed)).toEqual(ids([...records, registration]));
    expect(omitted).toEqual([]);

    const link = await encodeWithIdentity(records, [registration, bystander]);
    const { records: business, registrations } = splitHandoff(await decodeChain(link, SCHEMAS));
    expect(business).toHaveLength(3);
    expect(ids(registrations)).toEqual(ids([registration]));
  });
});

describe("handoff budget", () => {
  it("keeps the claim without which nobody can be named, and drops a vouch that does not fit", async () => {
    const { records, registration } = await chainOfThree();
    const notary = await generateKeyPair();
    const vouch = await buildVouch({
      keys: notary,
      voucherId: "urn:vbel:org:notary",
      subject: storedPayloadOf(registration) as never,
      previousEventHash: registration.event.eventHash,
    });

    const roomy = await planHandoff(records, [registration, vouch]);
    expect(ids(roomy.handed)).toEqual(ids([...records, registration, vouch]));

    const withoutVouch = (await encodeChain([...records, registration])).length;
    const tight = await planHandoff(records, [registration, vouch], withoutVouch);
    expect(ids(tight.handed)).toEqual(ids([...records, registration]));
    expect(ids(tight.omitted)).toEqual(ids([vouch]));
  });

  it("never sends a withdrawn vouch", async () => {
    const { records, registration } = await chainOfThree();
    const notary = await generateKeyPair();
    const vouch = await buildVouch({
      keys: notary,
      voucherId: "urn:vbel:org:notary",
      subject: storedPayloadOf(registration) as never,
      previousEventHash: registration.event.eventHash,
    });
    const withdrawal = await buildRevocation({ keys: notary, issuerId: "urn:vbel:org:notary", target: vouch, reason: "no" });
    const { handed } = await planHandoff(records, [registration, vouch, withdrawal]);
    expect(ids(handed)).not.toContain(vouch.event.envelope.eventId);
  });
});

describe("selective disclosure", () => {
  it("discloses one record, seals the rest, and the cover sheet says so", async () => {
    const { keys, records, registration } = await chainOfThree();
    const { bundle, disclosure } = await buildDisclosure({
      records,
      keys,
      discloserId: AUTHOR,
      recipient: "urn:vbel:org:auditor",
      revealEventIds: [records[1]!.event.envelope.eventId],
      includeRegistrations: [registration],
    });

    const reading = await readCoverSheet(bundle);
    expect(reading).toMatchObject({ signature: "verified", headMatches: "matches" });
    expect(reading?.payload.revealedEventIds).toEqual([records[1]!.event.envelope.eventId]);
    expect(reading?.payload.withheldEventIds).toHaveLength(2);
    expect(disclosure.event.envelope.schema).toBe("urn:vbel:event:disclosure:v1");

    const verdicts = await verifyAll(bundle, buildIdentityContext(registrationsIn(bundle)));
    const states = records.map((r) => verdicts.get(r.event.envelope.eventId)!.payloadState);
    expect(states).toEqual(["withheld", "verified", "withheld"]);
  });

  it("notices when the chain delivered is not the one the cover sheet names", async () => {
    const { keys, records } = await chainOfThree();
    const { bundle } = await buildDisclosure({
      records,
      keys,
      discloserId: AUTHOR,
      recipient: "urn:vbel:org:auditor",
      revealEventIds: [],
    });
    const longer = [...bundle.slice(0, 3), await noteRecord(keys, { text: "later", amount: 1 }, records[2]!), ...bundle.slice(3)];
    expect((await readCoverSheet(longer))?.headMatches).toBe("differs");
  });

  it("returns nothing for a chain that was handed over rather than disclosed", async () => {
    const { records } = await chainOfThree();
    expect(await readCoverSheet(records)).toBeNull();
  });

  it("refuses to disclose nothing", async () => {
    const { keys } = await chainOfThree();
    await expect(
      buildDisclosure({ records: [], keys, discloserId: AUTHOR, recipient: "x", revealEventIds: [] })
    ).rejects.toThrow(/no chain/);
  });

  it("never re-discloses an earlier cover sheet", async () => {
    const { keys, records } = await chainOfThree();
    const first = await buildDisclosure({ records, keys, discloserId: AUTHOR, recipient: "urn:vbel:org:a", revealEventIds: [] });
    const second = await buildDisclosure({ records: first.bundle, keys, discloserId: AUTHOR, recipient: "urn:vbel:org:b", revealEventIds: [] });
    expect(second.bundle.filter((r) => r.event.envelope.schema === "urn:vbel:event:disclosure:v1")).toHaveLength(1);
    expect(second.bundle.every((r) => r.event.eventHash !== first.disclosure.event.eventHash)).toBe(true);
  });
});

