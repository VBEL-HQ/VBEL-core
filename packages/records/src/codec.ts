/**
 * Serializes a chain of records into a compact, URL-safe string so a signed
 * record can travel between devices as a link, with no server and no
 * database. The URL fragment never reaches a server, which is the same
 * claim the verifier makes: nobody has to be trusted to hold this.
 *
 * Shape: JSON -> gzip (CompressionStream) -> base64url, unpadded.
 */
import { DisclosurePayloadSchema, SCHEMA_DISCLOSURE, SignedEventSchema } from "@vbel/core";
import {
  AcceptancePayloadSchema,
  DispatchPayloadSchema,
  SettlementPayloadSchema,
  SCHEMA_ACCEPTED,
  SCHEMA_DISPATCHED,
  SCHEMA_SETTLED,
} from "@vbel/domain-delivery";
import {
  DisputePayloadSchema,
  ExecutionPayloadSchema,
  IrregularityPayloadSchema,
  MandatePayloadSchema,
  ObligationPayloadSchema,
  RefundPayloadSchema,
  ResolutionPayloadSchema,
  SCHEMA_DISPUTE,
  SCHEMA_EXECUTED,
  SCHEMA_IRREGULARITY,
  SCHEMA_MANDATE,
  SCHEMA_OBLIGATION,
  SCHEMA_REFUND,
  SCHEMA_RESOLUTION,
} from "@vbel/domain-payment";
import { disclosedPayload, withheldPayload, type LedgerRecord, type PayloadSlot } from "./types";

/**
 * Every schema this app will decode, and the shape each one must satisfy.
 * A record arriving in a URL is hostile input; an envelope naming a schema
 * that is not in this table is rejected rather than passed through, so a
 * new event type cannot reach the UI until someone has decided what valid
 * looks like for it.
 */
const PAYLOAD_SCHEMAS = {
  [SCHEMA_DISPATCHED]: DispatchPayloadSchema,
  [SCHEMA_ACCEPTED]: AcceptancePayloadSchema,
  [SCHEMA_SETTLED]: SettlementPayloadSchema,
  [SCHEMA_OBLIGATION]: ObligationPayloadSchema,
  [SCHEMA_MANDATE]: MandatePayloadSchema,
  [SCHEMA_EXECUTED]: ExecutionPayloadSchema,
  [SCHEMA_REFUND]: RefundPayloadSchema,
  [SCHEMA_IRREGULARITY]: IrregularityPayloadSchema,
  [SCHEMA_DISPUTE]: DisputePayloadSchema,
  [SCHEMA_RESOLUTION]: ResolutionPayloadSchema,
  [SCHEMA_DISCLOSURE]: DisclosurePayloadSchema,
} as const;

/**
 * Thrown when an encoded chain cannot be decoded into fully valid records.
 * Decoding is all-or-nothing: a partially valid chain is never returned.
 */
export class ChainDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainDecodeError";
  }
}

/**
 * QR byte mode caps out near 2953 bytes at the lowest error correction
 * level. Past it the handoff is copy-link only, with no QR fallback.
 *
 * Measured, not assumed, for the seven-record payment arc (obligation,
 * mandate, drawn payment, irregularity, dispute, resolution, refund):
 *
 *   full chain                          3662   over
 *   redacted, one payload revealed      2840   under
 *   redacted, nothing revealed          2670   under
 *   redacted plus its cover sheet       3394   over
 *
 * So redaction does clear the ceiling and the cover sheet puts it back over,
 * and the two cannot be separated: a cover sheet chains to the disclosed
 * head, so verified without that chain it reports a dangling predecessor.
 * QR is therefore available for a redacted chain and not for a disclosure of
 * one, at this size.
 *
 * The cost is dominated by envelopes rather than payloads, which is why
 * redacting a three-record chain saves only about a sixth: each envelope
 * carries two UUIDs, a 64-character public key and a 128-character
 * signature, all hex. Moving those to base64 is the available win if a
 * disclosure ever has to fit in a QR code.
 */
export const QR_BYTE_CEILING = 2953;

/**
 * The budget a delivery-only chain is held to. Deliberately under
 * QR_BYTE_CEILING so a scan works on a phone camera at a loading bay rather
 * than only in ideal conditions.
 *
 * Neither number is enforced at encode time. They are budgets to measure
 * against, not limits to fail on, because a chain too large to scan is still
 * a perfectly good chain to send as a link.
 */
export const MAX_ENCODED_LENGTH = 2000;

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlToBytes(base64url: string): Uint8Array {
  if (typeof base64url !== "string" || base64url.length === 0) {
    throw new ChainDecodeError("Encoded chain string must not be empty");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(base64url)) {
    throw new ChainDecodeError("Invalid base64url characters in encoded chain");
  }
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  let binary: string;
  try {
    binary = atob(base64);
  } catch (err) {
    throw new ChainDecodeError(
      `Failed to decode base64: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function gzipCompress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new ReadableStream<BufferSource>({
    start(controller) {
      controller.enqueue(bytes as unknown as BufferSource);
      controller.close();
    },
  }).pipeThrough(new CompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

async function gzipDecompress(bytes: Uint8Array): Promise<Uint8Array> {
  try {
    const stream = new ReadableStream<BufferSource>({
      start(controller) {
        controller.enqueue(bytes as unknown as BufferSource);
        controller.close();
      },
    }).pipeThrough(new DecompressionStream("gzip"));
    const buffer = await new Response(stream).arrayBuffer();
    return new Uint8Array(buffer);
  } catch (err) {
    throw new ChainDecodeError(
      `Failed to decompress gzip stream: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Strips every payload except the ones named, keeping every envelope.
 *
 * This is the whole of selective disclosure, and it needed no new
 * cryptography: an envelope commits to its payload by hash and never
 * contains it, so removing payloads leaves every signature verifiable,
 * every previousEventHash link intact, and the ordering provable. Only "what
 * did this record say" goes away, and only for the records left out.
 *
 * The anchor receipt travels with a withheld record on purpose. It is a
 * transaction on a public chain carrying the eventHash, which is already
 * present in the envelope, so it discloses nothing further and it is what
 * lets a recipient date a record they cannot read.
 */
export function redactChain(records: LedgerRecord[], revealEventIds: Iterable<string>): LedgerRecord[] {
  const reveal = new Set(revealEventIds);
  return records.map((record) =>
    reveal.has(record.event.envelope.eventId) ? record : { ...record, payload: withheldPayload() }
  );
}

export async function encodeChain(records: LedgerRecord[]): Promise<string> {
  const json = JSON.stringify(records);
  const jsonBytes = new TextEncoder().encode(json);
  const compressed = await gzipCompress(jsonBytes);
  return bytesToBase64Url(compressed);
}

/**
 * Input arrives from a URL a stranger can edit, so it is treated as hostile:
 * every record is validated against SignedEventSchema and the matching
 * payload schema before it is returned.
 *
 * Note that the issuer copy in a present slot rides along purely so the UI
 * can name which field changed. It is not a security input — the envelope's
 * signed payloadHash is what actually detects tampering — so no trust
 * decision may be derived from it here.
 *
 * @throws {ChainDecodeError}
 */
export async function decodeChain(encoded: string): Promise<LedgerRecord[]> {
  const compressedBytes = base64UrlToBytes(encoded);
  const decompressedBytes = await gzipDecompress(compressedBytes);

  let jsonText: string;
  try {
    jsonText = new TextDecoder("utf-8", { fatal: true }).decode(decompressedBytes);
  } catch (err) {
    throw new ChainDecodeError(
      `Failed to decode UTF-8 text: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    throw new ChainDecodeError(
      `Invalid JSON payload: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (!Array.isArray(parsed)) {
    throw new ChainDecodeError("Decoded payload is not an array of records");
  }

  const records: LedgerRecord[] = [];

  for (let i = 0; i < parsed.length; i++) {
    const raw = parsed[i];
    if (typeof raw !== "object" || raw === null) {
      throw new ChainDecodeError(`Record at index ${i} is not an object`);
    }

    if (typeof (raw as { label?: unknown }).label !== "string") {
      throw new ChainDecodeError(`Record at index ${i} has invalid or missing label`);
    }

    const eventResult = SignedEventSchema.safeParse((raw as { event?: unknown }).event);
    if (!eventResult.success) {
      const issues = eventResult.error.issues
        .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
        .join(", ");
      throw new ChainDecodeError(`Record at index ${i} has invalid signed event: ${issues}`);
    }
    const event = eventResult.data;

    const payloadSchema = PAYLOAD_SCHEMAS[event.envelope.schema as keyof typeof PAYLOAD_SCHEMAS];
    if (!payloadSchema) {
      throw new ChainDecodeError(
        `Record at index ${i} has unrecognized envelope schema "${event.envelope.schema}"`
      );
    }

    /**
     * Withheld is a *declared* state, never an inferred one. A record whose
     * payload is simply missing, or whose slot claims to be present without
     * one, still throws exactly as before — so a chain stripped in transit
     * and a chain redacted on purpose are distinguishable at the point of
     * parsing, and only the second is accepted.
     */
    const rawSlot = (raw as { payload?: unknown }).payload;
    if (typeof rawSlot !== "object" || rawSlot === null) {
      throw new ChainDecodeError(`Record at index ${i} has no payload slot`);
    }
    const slotState = (rawSlot as { state?: unknown }).state;

    let payload: PayloadSlot;
    if (slotState === "withheld") {
      payload = withheldPayload();
    } else if (slotState === "present") {
      const storedResult = payloadSchema.safeParse((rawSlot as { stored?: unknown }).stored);
      if (!storedResult.success) {
        const issues = storedResult.error.issues
          .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
          .join(", ");
        throw new ChainDecodeError(`Record at index ${i} has invalid stored payload: ${issues}`);
      }

      const issuerResult = payloadSchema.safeParse((rawSlot as { issuer?: unknown }).issuer);
      if (!issuerResult.success) {
        const issues = issuerResult.error.issues
          .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
          .join(", ");
        throw new ChainDecodeError(`Record at index ${i} has invalid issuer payload: ${issues}`);
      }

      payload = disclosedPayload(storedResult.data, issuerResult.data);
    } else {
      throw new ChainDecodeError(
        `Record at index ${i} has an unrecognised payload state ${JSON.stringify(slotState)}`
      );
    }

    const anchor = (raw as { anchor?: unknown }).anchor ?? null;
    if (anchor !== null && (typeof anchor !== "object" || anchor === null)) {
      throw new ChainDecodeError(`Record at index ${i} has invalid anchor`);
    }

    const chainVerification = (raw as { chainVerification?: unknown }).chainVerification ?? null;
    if (chainVerification !== null && (typeof chainVerification !== "object" || chainVerification === null)) {
      throw new ChainDecodeError(`Record at index ${i} has invalid chainVerification`);
    }

    records.push({
      label: (raw as { label: string }).label,
      event,
      payload,
      anchor: anchor as LedgerRecord["anchor"],
      chainVerification: chainVerification as LedgerRecord["chainVerification"],
    });
  }

  return records;
}
