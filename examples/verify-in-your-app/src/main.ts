/**
 * Two sides of one exchange, in one file.
 *
 * "Supplier" signs two records about an order and sends a link. "Reviewer"
 * holds nothing of the supplier's: no key, no account, no server to ask. It
 * decodes the link and checks every record itself. Then the reviewer edits an
 * amount, and the check names the field, and finally the supplier withholds a
 * record and the reviewer is told it was withheld rather than forged.
 *
 * Everything the library does not know about your business is what you
 * bring: here, one record type ("order note") and its shape.
 */
import { generateKeyPair, hashPayload, signEnvelope, validateChain, type Envelope, type KeyPair } from "@vbel/core";
import {
  buildIdentityContext,
  buildSelfRegistration,
  decodeChain,
  disclosedPayload,
  encodeWithIdentity,
  redactChain,
  registrationsIn,
  splitHandoff,
  verifyAll,
  type LedgerRecord,
} from "@vbel/records";
import { z } from "zod";

// --- what is yours: a record type, and the shape of what it says -------------

const SCHEMA_ORDER_NOTE = "urn:example:event:order-note:v1";
const OrderNote = z.object({ orderRef: z.string(), quantity: z.number().int(), note: z.string() });
type OrderNote = z.infer<typeof OrderNote>;

const SUPPLIER = "urn:example:org:supplier";

function sign(keys: KeyPair, payload: OrderNote, previous: LedgerRecord | null): Promise<LedgerRecord> {
  const envelope: Envelope = {
    schema: SCHEMA_ORDER_NOTE,
    eventId: crypto.randomUUID(),
    subjectId: `urn:example:order:${payload.orderRef}`,
    issuerId: SUPPLIER,
    issuedAt: new Date().toISOString(),
    previousEventHash: previous?.event.eventHash ?? null,
    payloadHash: hashPayload(payload),
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: "urn:example:policy:v1",
    privacy: "off-chain",
    nonce: crypto.randomUUID(),
  };
  return signEnvelope({ envelope, signer: keys, signerId: SUPPLIER }).then((event) => ({
    label: "Order note",
    event,
    payload: disclosedPayload(payload),
    anchor: null,
    chainVerification: null,
  }));
}

// --- the supplier's side ------------------------------------------------------

async function supplierSends(): Promise<string> {
  const keys = await generateKeyPair();
  const registration = await buildSelfRegistration({
    keys,
    entityId: SUPPLIER,
    displayName: "Example Supplier Ltd",
    // A claim has to predate the acts it explains, so it is dated a moment ago.
    at: new Date(Date.now() - 60_000).toISOString(),
  });

  const dispatched = await sign(keys, { orderRef: "PO-1001", quantity: 500, note: "dispatched" }, null);
  const shortShipped = await sign(keys, { orderRef: "PO-1001", quantity: 470, note: "30 units short" }, dispatched);

  // The link carries the records and the claim that says whose key signed them.
  return encodeWithIdentity([dispatched, shortShipped], [registration]);
}

// --- the reviewer's side: holds nothing of the supplier's ---------------------

function show(title: string, records: LedgerRecord[], verdicts: Awaited<ReturnType<typeof verifyAll>>) {
  console.log(`\n${title}`);
  for (const record of records) {
    const v = verdicts.get(record.event.envelope.eventId)!;
    const said = record.payload.state === "present" ? JSON.stringify(record.payload.stored) : "(sealed)";
    console.log(
      `  signature ${v.signatureValid ? "valid" : "INVALID"} | payload ${v.payloadState.padEnd(8)} | ` +
        `${v.identity.name} (${v.identity.assurance}) | ${said}`
    );
    for (const d of v.differences) console.log(`      changed: ${d.path}, was ${JSON.stringify(d.expected)}, now ${JSON.stringify(d.actual)}`);
  }
}

async function reviewerChecks(link: string) {
  // Bring the shape of your own records; anything else in the link is refused.
  const decoded = await decodeChain(link, { [SCHEMA_ORDER_NOTE]: OrderNote });
  const { records, registrations } = splitHandoff(decoded);
  const context = buildIdentityContext(registrationsIn(registrations));

  console.log(`Received ${records.length} records and ${registrations.length} identity claim.`);
  console.log(`Chain intact: ${validateChain(records.map((r) => r.event)).valid}`);
  show("1. As sent:", records, await verifyAll(records, context));

  // Somebody edits the stored amount. The signature never covered the copy
  // they are holding, so it cannot follow the edit.
  const edited = records.map((r, i) =>
    i === 1 && r.payload.state === "present"
      ? { ...r, payload: { ...r.payload, stored: { ...(r.payload.stored as OrderNote), quantity: 500 } } }
      : r
  );
  show("2. After someone changes the quantity from 470 to 500:", edited, await verifyAll(edited, context));

  // The supplier chooses not to show the note text. That is not a forgery.
  const sealed = redactChain(records, [records[0]!.event.envelope.eventId]);
  show("3. With the second record withheld:", sealed, await verifyAll(sealed, context));
  console.log(`Chain still intact with a payload withheld: ${validateChain(sealed.map((r) => r.event)).valid}`);

  console.log(
    "\nWhat this shows: the records were not changed after signing, in this order, by this key.\n" +
      "What it does not: that 470 is the true quantity, or that \"Example Supplier Ltd\" is who it says.\n" +
      "That name is self asserted; a vouch from someone you trust is what would raise it."
  );
}

await reviewerChecks(await supplierSends());
