import * as ed25519 from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { SignedEventSchema, type SignedEvent } from "./envelope.js";
import type { KeyPair } from "./keys.js";
import { verifyCounterSignature, verifyEnvelopeSignature } from "./sign.js";

/**
 * Who may ask a server to spend money anchoring a record.
 *
 * Anchoring costs the operator a transaction fee, so an open endpoint is a
 * tap anybody can leave running. There is no account here and there must not
 * be one, so the request proves the one thing this system already runs on:
 * possession of a key that signed the record.
 *
 * The caller sends the signed event itself, not just its hash, and signs a
 * short statement of what it is asking for. The server then knows three
 * things without holding any state about the caller:
 *
 *  - the record is real: its hash is recomputed from the envelope and its
 *    issuer signature verifies, so the chain never receives a hash that
 *    belongs to nothing
 *  - the caller holds a key that signed it, as issuer or as counter-signer,
 *    so a link that has been forwarded around cannot be used to spend
 *  - the request is fresh, so a captured request cannot be replayed later
 *
 * What this does not do is decide whether the key is worth anything. Anyone
 * can make a key and sign a record with it, so this is what ties a spend to
 * a real signed act and gives rate limiting a thing to count; it is not a
 * substitute for the rate limit. See the server guard for the other half.
 */

/** How far a request's clock may sit from the server's, either way. */
export const ANCHOR_PROOF_WINDOW_MS = 5 * 60 * 1000;

export type AnchorChainName = "solana" | "ethereum";

export interface AnchorProof {
  /** Hex ed25519 public key of the signer. Must be a key that signed the record. */
  publicKey: string;
  /** ISO 8601 instant the caller signed at. */
  signedAt: string;
  /** Hex signature over `anchorRequestMessage(...)`. */
  signature: string;
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * The exact bytes the caller signs. Every field that decides what is being
 * paid for is in it, so a proof for one record on one chain cannot be reused
 * for another record or on the other chain. The domain prefix keeps it from
 * being a signature over anything else in the product.
 */
export function anchorRequestMessage(eventHash: string, chain: AnchorChainName, signedAt: string): string {
  return `vbel-anchor/v1\n${eventHash}\n${chain}\n${signedAt}`;
}

export async function signAnchorRequest(params: {
  eventHash: string;
  chain: AnchorChainName;
  signer: KeyPair;
  now?: Date;
}): Promise<AnchorProof> {
  const signedAt = (params.now ?? new Date()).toISOString();
  const message = anchorRequestMessage(params.eventHash, params.chain, signedAt);
  const signature = await ed25519.signAsync(utf8(message), params.signer.privateKey);
  return { publicKey: params.signer.publicKeyHex, signedAt, signature: bytesToHex(signature) };
}

/**
 * Whether `keys` include one that may ask for this record to be anchored.
 * The client uses it to decide which records to offer the button on, so the
 * console never shows an action the server would refuse.
 */
export function anchorAuthority(event: SignedEvent, keys: readonly KeyPair[]): KeyPair | null {
  const allowed = new Set([event.signature.publicKey, event.counterSignature?.publicKey].filter(Boolean));
  return keys.find((key) => allowed.has(key.publicKeyHex)) ?? null;
}

export type AnchorAuthRefusal =
  | "MALFORMED_EVENT"
  | "EVENT_INVALID"
  | "NOT_A_SIGNER"
  | "STALE"
  | "FROM_THE_FUTURE"
  | "BAD_PROOF";

export type AnchorAuthResult =
  | { ok: true; eventHash: string; signedAs: "issuer" | "counter-signer" }
  | { ok: false; refusal: AnchorAuthRefusal };

/**
 * Checks an anchor request, holding no state and consulting nothing. It is
 * pure so the same function runs in the server route and in tests, and so a
 * refusal is a value the route maps to a status rather than an exception it
 * has to classify.
 */
export async function authoriseAnchorRequest(params: {
  event: unknown;
  chain: AnchorChainName;
  proof: AnchorProof;
  now?: Date;
}): Promise<AnchorAuthResult> {
  const parsed = SignedEventSchema.safeParse(params.event);
  if (!parsed.success) return { ok: false, refusal: "MALFORMED_EVENT" };
  const event = parsed.data;

  let eventValid = false;
  try {
    // Recomputes the hash from the envelope and checks the issuer's
    // signature over it, so the hash sent alongside cannot be a different one.
    eventValid = await verifyEnvelopeSignature(event);
  } catch {
    eventValid = false;
  }
  if (!eventValid) return { ok: false, refusal: "EVENT_INVALID" };

  const isIssuer = params.proof.publicKey === event.signature.publicKey;
  const isCounterSigner =
    !isIssuer &&
    event.counterSignature !== null &&
    params.proof.publicKey === event.counterSignature.publicKey &&
    (await verifyCounterSignature(event));
  if (!isIssuer && !isCounterSigner) return { ok: false, refusal: "NOT_A_SIGNER" };

  const signedAtMs = Date.parse(params.proof.signedAt);
  if (Number.isNaN(signedAtMs)) return { ok: false, refusal: "BAD_PROOF" };
  const skew = (params.now ?? new Date()).getTime() - signedAtMs;
  if (skew > ANCHOR_PROOF_WINDOW_MS) return { ok: false, refusal: "STALE" };
  if (skew < -ANCHOR_PROOF_WINDOW_MS) return { ok: false, refusal: "FROM_THE_FUTURE" };

  let proofValid = false;
  try {
    proofValid = await ed25519.verifyAsync(
      hexToBytes(params.proof.signature),
      utf8(anchorRequestMessage(event.eventHash, params.chain, params.proof.signedAt)),
      hexToBytes(params.proof.publicKey)
    );
  } catch {
    proofValid = false;
  }
  if (!proofValid) return { ok: false, refusal: "BAD_PROOF" };

  return { ok: true, eventHash: event.eventHash, signedAs: isIssuer ? "issuer" : "counter-signer" };
}
