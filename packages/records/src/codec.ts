/**
 * CONTRACT ONLY — implementation lands on `feat/record-codec`.
 *
 * Serializes a chain of records into a compact, URL-safe string so a signed
 * record can travel between devices as a link, with no server and no
 * database. The URL fragment never reaches a server, which is the same
 * claim the verifier makes: nobody has to be trusted to hold this.
 *
 * Shape: JSON -> gzip (CompressionStream) -> base64url, unpadded.
 */
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

export async function encodeChain(_records: LedgerRecord[]): Promise<string> {
  throw new Error("encodeChain not implemented — see feat/record-codec");
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
export async function decodeChain(_encoded: string): Promise<LedgerRecord[]> {
  throw new ChainDecodeError("decodeChain not implemented — see feat/record-codec");
}
