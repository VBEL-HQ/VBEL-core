/**
 * Serializes a chain of records into a compact, URL-safe string so a signed
 * record can travel between devices as a link, with no server and no
 * database. The URL fragment never reaches a server, which is the same
 * claim the verifier makes: nobody has to be trusted to hold this.
 *
 * Shape: JSON -> gzip (CompressionStream) -> base64url, unpadded.
 */
import { SignedEventSchema } from "@vbel/core";
import {
  AcceptancePayloadSchema,
  DispatchPayloadSchema,
  SCHEMA_ACCEPTED,
  SCHEMA_DISPATCHED,
} from "@vbel/domain-delivery";
import type { LedgerRecord } from "./types";

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
 * The encoded string has to fit in a QR code, which caps out near 2953
 * bytes. A three-record chain must stay under this or the handoff falls
 * back to copy-link only.
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
 * Note that `LedgerRecord.issuerPayload` rides along purely so the UI can
 * name which field changed. It is not a security input — the envelope's
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

    let payloadSchema;
    if (event.envelope.schema === SCHEMA_DISPATCHED) {
      payloadSchema = DispatchPayloadSchema;
    } else if (event.envelope.schema === SCHEMA_ACCEPTED) {
      payloadSchema = AcceptancePayloadSchema;
    } else {
      throw new ChainDecodeError(
        `Record at index ${i} has unrecognized envelope schema "${event.envelope.schema}"`
      );
    }

    const storedResult = payloadSchema.safeParse((raw as { storedPayload?: unknown }).storedPayload);
    if (!storedResult.success) {
      const issues = storedResult.error.issues
        .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
        .join(", ");
      throw new ChainDecodeError(`Record at index ${i} has invalid storedPayload: ${issues}`);
    }
    const storedPayload = storedResult.data;

    const issuerResult = payloadSchema.safeParse((raw as { issuerPayload?: unknown }).issuerPayload);
    if (!issuerResult.success) {
      const issues = issuerResult.error.issues
        .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
        .join(", ");
      throw new ChainDecodeError(`Record at index ${i} has invalid issuerPayload: ${issues}`);
    }
    const issuerPayload = issuerResult.data;

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
      storedPayload,
      issuerPayload,
      anchor: anchor as LedgerRecord["anchor"],
      chainVerification: chainVerification as LedgerRecord["chainVerification"],
    });
  }

  return records;
}
