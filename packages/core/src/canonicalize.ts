import { canonicalize } from "json-canonicalize";

export class CanonicalizeError extends Error {}

/**
 * RFC 8785 (JSON Canonicalization Scheme) via json-canonicalize, plus the
 * guards TECHNICAL-BRIEF.md §4.2 calls out: no undefined, no unsafe
 * integers, no NaN/Infinity, no lone surrogates. Two implementations of
 * this function, in any language, must produce byte-identical output for
 * the same object or every verification downstream is meaningless.
 */
export function toCanonicalBytes(value: unknown): Uint8Array {
  assertCanonicalizable(value);
  const json = canonicalize(value as never);
  return new TextEncoder().encode(json);
}

export function toCanonicalString(value: unknown): string {
  assertCanonicalizable(value);
  return canonicalize(value as never);
}

function assertCanonicalizable(value: unknown, path = "$"): void {
  if (value === undefined) {
    throw new CanonicalizeError(`undefined is not canonicalizable at ${path}`);
  }
  if (typeof value === "number") {
    if (Number.isNaN(value)) {
      throw new CanonicalizeError(`NaN is not canonicalizable at ${path}`);
    }
    if (!Number.isFinite(value)) {
      throw new CanonicalizeError(`Infinity is not canonicalizable at ${path}`);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new CanonicalizeError(
        `unsafe integer at ${path} — encode large integers as strings before canonicalizing`
      );
    }
  }
  if (typeof value === "string") {
    assertNoLoneSurrogates(value, path);
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertCanonicalizable(item, `${path}[${i}]`));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      assertCanonicalizable(item, `${path}.${key}`);
    }
  }
}

function assertNoLoneSurrogates(value: string, path: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        throw new CanonicalizeError(`lone high surrogate at ${path}[${i}]`);
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new CanonicalizeError(`lone low surrogate at ${path}[${i}]`);
    }
  }
}
