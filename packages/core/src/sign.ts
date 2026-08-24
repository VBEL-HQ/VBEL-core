import * as ed25519 from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  EnvelopeSchema,
  SignedEventSchema,
  type Envelope,
  type SignatureBlock,
  type SignedEvent,
} from "./envelope.js";
import { hashCanonical } from "./hash.js";
import type { KeyPair } from "./keys.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

/** eventHash = sha256(canonicalize(envelope)) — the signature is attached alongside, never inside the hashed region. */
export function computeEventHash(envelope: Envelope): string {
  EnvelopeSchema.parse(envelope);
  return hashCanonical(envelope);
}

/** The issuer signs their own event. Every event has exactly one of these. */
export async function signEnvelope(params: {
  envelope: Envelope;
  signer: KeyPair;
  signerId: string;
}): Promise<SignedEvent> {
  const { envelope, signer, signerId } = params;
  const eventHash = computeEventHash(envelope);
  const signatureBytes = await ed25519.signAsync(utf8(eventHash), signer.privateKey);

  return SignedEventSchema.parse({
    envelope,
    eventHash,
    signature: {
      signerId,
      publicKey: signer.publicKeyHex,
      signature: bytesToHex(signatureBytes),
    },
    counterSignature: null,
  });
}

export async function verifyEnvelopeSignature(signed: SignedEvent): Promise<boolean> {
  if (computeEventHash(signed.envelope) !== signed.eventHash) return false;
  return verifySignatureBlock(signed.eventHash, signed.signature);
}

/**
 * Counter-signing (TECHNICAL-BRIEF.md §8 decision 1, resolved: counter-sign).
 * The counter-signer attests to the event they are chaining to — signed over
 * previousEventHash, not over this event's own eventHash — so the claim is
 * "I have seen and agree with exactly that prior content", independent of
 * whatever this new event itself goes on to say.
 */
export async function counterSignPreviousEvent(params: {
  signed: SignedEvent;
  counterSigner: KeyPair;
  signerId: string;
}): Promise<SignedEvent> {
  const { signed, counterSigner, signerId } = params;
  const previousEventHash = signed.envelope.previousEventHash;
  if (!previousEventHash) {
    throw new Error("cannot counter-sign: envelope.previousEventHash is null");
  }
  const signatureBytes = await ed25519.signAsync(utf8(previousEventHash), counterSigner.privateKey);

  const counterSignature: SignatureBlock = {
    signerId,
    publicKey: counterSigner.publicKeyHex,
    signature: bytesToHex(signatureBytes),
  };

  return SignedEventSchema.parse({ ...signed, counterSignature });
}

export async function verifyCounterSignature(signed: SignedEvent): Promise<boolean> {
  if (!signed.counterSignature) return false;
  if (!signed.envelope.previousEventHash) return false;
  return verifySignatureBlock(signed.envelope.previousEventHash, signed.counterSignature);
}

async function verifySignatureBlock(message: string, block: SignatureBlock): Promise<boolean> {
  try {
    return await ed25519.verifyAsync(
      hexToBytes(block.signature),
      utf8(message),
      hexToBytes(block.publicKey)
    );
  } catch {
    return false;
  }
}

export interface VerificationResult {
  valid: boolean;
  issues: string[];
}

/** Full verification of one event: hash integrity, issuer signature, and counter-signature if present. */
export async function verifyEvent(signed: SignedEvent): Promise<VerificationResult> {
  const issues: string[] = [];

  const parsed = SignedEventSchema.safeParse(signed);
  if (!parsed.success) {
    return { valid: false, issues: [`schema: ${parsed.error.message}`] };
  }

  if (computeEventHash(signed.envelope) !== signed.eventHash) {
    issues.push("eventHash does not match canonicalize(envelope) — payload was tampered with");
  }

  if (!(await verifySignatureBlock(signed.eventHash, signed.signature))) {
    issues.push(`issuer signature invalid for signerId ${signed.signature.signerId}`);
  }

  if (signed.counterSignature) {
    if (!signed.envelope.previousEventHash) {
      issues.push("counterSignature present but envelope.previousEventHash is null");
    } else if (!(await verifySignatureBlock(signed.envelope.previousEventHash, signed.counterSignature))) {
      issues.push(`counter-signature invalid for signerId ${signed.counterSignature.signerId}`);
    }
  }

  return { valid: issues.length === 0, issues };
}
