import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { toCanonicalBytes } from "./canonicalize.js";

export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

/** Canonicalizes, hashes, and prefixes — the `sha256:<hex>` shape used throughout the envelope. */
export function hashCanonical(value: unknown): string {
  return `sha256:${sha256Hex(toCanonicalBytes(value))}`;
}

/** payloadHash: the off-chain business document, hashed the same way as the envelope. */
export function hashPayload(payload: unknown): string {
  return hashCanonical(payload);
}
