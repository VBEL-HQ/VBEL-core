import type { Envelope } from "./envelope.js";
import { hashPayload } from "./hash.js";

export interface PayloadVerification {
  valid: boolean;
  /** The hash the signed envelope committed to. */
  expected: string;
  /** The hash the payload actually produces now. */
  actual: string;
}

/**
 * The envelope commits to a payload it never contains. This is the check
 * that closes that gap: recompute the hash of the stored document and
 * compare it to what was signed. A mismatch means the stored copy was
 * changed after the fact — which is precisely the failure the whole system
 * exists to make visible.
 */
export function verifyPayload(payload: unknown, envelope: Envelope): PayloadVerification {
  const actual = hashPayload(payload);
  return { valid: actual === envelope.payloadHash, expected: envelope.payloadHash, actual };
}

export interface FieldDifference {
  /** JSON path, e.g. `$.lines[0].quantityAccepted`. */
  path: string;
  expected: unknown;
  actual: unknown;
}

/**
 * Names the fields that differ between two payloads. A hash mismatch alone
 * proves tampering but says nothing about what changed; this answers that,
 * and needs a trusted reference copy to compare against — the hash by
 * itself can never reveal it.
 */
export function diffPayloads(expected: unknown, actual: unknown, path = "$"): FieldDifference[] {
  if (Object.is(expected, actual)) return [];

  const bothArrays = Array.isArray(expected) && Array.isArray(actual);
  const bothObjects =
    !bothArrays &&
    typeof expected === "object" &&
    typeof actual === "object" &&
    expected !== null &&
    actual !== null;

  if (bothArrays) {
    const differences: FieldDifference[] = [];
    const length = Math.max(expected.length, actual.length);
    for (let i = 0; i < length; i++) {
      differences.push(...diffPayloads(expected[i], actual[i], `${path}[${i}]`));
    }
    return differences;
  }

  if (bothObjects) {
    const differences: FieldDifference[] = [];
    const keys = new Set([
      ...Object.keys(expected as Record<string, unknown>),
      ...Object.keys(actual as Record<string, unknown>),
    ]);
    for (const key of keys) {
      differences.push(
        ...diffPayloads(
          (expected as Record<string, unknown>)[key],
          (actual as Record<string, unknown>)[key],
          `${path}.${key}`
        )
      );
    }
    return differences;
  }

  return [{ path, expected, actual }];
}
