import { describe, expect, it } from "vitest";
import { CanonicalizeError, toCanonicalString } from "../src/canonicalize.js";
import { hashCanonical } from "../src/hash.js";
import vector from "../fixtures/canonicalization-vector.json" with { type: "json" };

describe("canonicalize", () => {
  it("orders keys, drops insertion order dependence", () => {
    const a = toCanonicalString({ b: 1, a: 2 });
    const b = toCanonicalString({ a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1}');
  });

  it("rejects undefined", () => {
    expect(() => toCanonicalString({ a: undefined })).toThrow(CanonicalizeError);
  });

  it("rejects NaN and Infinity", () => {
    expect(() => toCanonicalString({ a: Number.NaN })).toThrow(CanonicalizeError);
    expect(() => toCanonicalString({ a: Number.POSITIVE_INFINITY })).toThrow(CanonicalizeError);
  });

  it("rejects unsafe integers — callers must encode them as strings", () => {
    expect(() => toCanonicalString({ a: Number.MAX_SAFE_INTEGER + 1 })).toThrow(CanonicalizeError);
    expect(() => toCanonicalString({ a: String(Number.MAX_SAFE_INTEGER + 1) })).not.toThrow();
  });

  it("rejects lone surrogates", () => {
    expect(() => toCanonicalString({ a: "\uD800" })).toThrow(CanonicalizeError);
  });

  it("accepts valid surrogate pairs (emoji)", () => {
    expect(() => toCanonicalString({ a: "🥦" })).not.toThrow();
  });

  /**
   * Committed cross-language test vector: fixed input -> fixed hex hash.
   * Any future implementation of the envelope in another language reproduces
   * this exact hash for this exact object, or it does not agree with core.
   */
  it("reproduces the committed cross-language hash vector", () => {
    expect(hashCanonical(vector.input)).toBe(vector.expectedHash);
  });
});
