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
import {
  attestationSigningRegion,
  checkAttestationWindow,
  type IdentityResolver,
  type IssuerAttestation,
} from "./identity.js";
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

/** Exported so identity implementations can check attestations with the same primitive events use. */
export async function verifySignatureBlock(message: string, block: SignatureBlock): Promise<boolean> {
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

/** Same shape as an event hash: sign over the digest, never over the raw structure. */
export function computeAttestationHash(attestation: IssuerAttestation): string {
  return hashCanonical(attestationSigningRegion(attestation));
}

/** Produces a relayable attestation — one that survives leaving the resolver that issued it. */
export async function signAttestation(params: {
  attestation: IssuerAttestation;
  signer: KeyPair;
  signerId: string;
}): Promise<IssuerAttestation> {
  const { attestation, signer, signerId } = params;
  const hash = computeAttestationHash(attestation);
  const signatureBytes = await ed25519.signAsync(utf8(hash), signer.privateKey);

  return {
    ...attestation,
    signature: { signerId, publicKey: signer.publicKeyHex, signature: bytesToHex(signatureBytes) },
  };
}

/**
 * Machine-readable outcomes. An auditor consuming this needs to branch on
 * what failed, not parse English — and the string messages here are for
 * humans reading a log, never for code to match on.
 */
export type VerificationIssueCode =
  | "SCHEMA_INVALID"
  | "EVENT_HASH_MISMATCH"
  | "ISSUER_SIGNATURE_INVALID"
  | "COUNTER_SIGNATURE_INVALID"
  | "COUNTER_SIGNATURE_ORPHANED"
  | "ISSUER_UNKNOWN"
  | "ISSUER_KEY_MISMATCH"
  | "ATTESTATION_NOT_YET_VALID"
  | "ATTESTATION_EXPIRED"
  | "ATTESTATION_SIGNATURE_INVALID";

export interface VerificationIssue {
  code: VerificationIssueCode;
  message: string;
  detail?: Record<string, string>;
}

export interface VerificationResult {
  valid: boolean;
  issues: VerificationIssue[];
  /**
   * False when no resolver was supplied. Distinguishing "identity confirmed"
   * from "identity never checked" matters: without it, a caller reading
   * `valid: true` would reasonably conclude the issuer is who they claim,
   * which internal consistency alone never established.
   */
  identityChecked: boolean;
  /** The attestation identity was checked against, when one was found. */
  attestation: IssuerAttestation | null;
}

/**
 * Full verification of one event: hash integrity, issuer signature,
 * counter-signature if present, and — when a resolver is supplied — that the
 * signing key actually belongs to the issuer it claims to be.
 *
 * The resolver is optional because verification must keep working with no
 * network and no configuration; that property is what lets anyone check a
 * record without our cooperation. What it costs is that the unresolved case
 * proves less, which `identityChecked` reports rather than hides.
 */
export async function verifyEvent(
  signed: SignedEvent,
  resolver?: IdentityResolver
): Promise<VerificationResult> {
  const issues: VerificationIssue[] = [];

  const parsed = SignedEventSchema.safeParse(signed);
  if (!parsed.success) {
    return {
      valid: false,
      issues: [{ code: "SCHEMA_INVALID", message: parsed.error.message }],
      identityChecked: false,
      attestation: null,
    };
  }

  if (computeEventHash(signed.envelope) !== signed.eventHash) {
    issues.push({
      code: "EVENT_HASH_MISMATCH",
      message: "eventHash does not match canonicalize(envelope) — the record was altered after signing",
    });
  }

  if (!(await verifySignatureBlock(signed.eventHash, signed.signature))) {
    issues.push({
      code: "ISSUER_SIGNATURE_INVALID",
      message: `issuer signature invalid for signerId ${signed.signature.signerId}`,
      detail: { signerId: signed.signature.signerId },
    });
  }

  if (signed.counterSignature) {
    if (!signed.envelope.previousEventHash) {
      issues.push({
        code: "COUNTER_SIGNATURE_ORPHANED",
        message: "counterSignature present but envelope.previousEventHash is null",
      });
    } else if (
      !(await verifySignatureBlock(signed.envelope.previousEventHash, signed.counterSignature))
    ) {
      issues.push({
        code: "COUNTER_SIGNATURE_INVALID",
        message: `counter-signature invalid for signerId ${signed.counterSignature.signerId}`,
        detail: { signerId: signed.counterSignature.signerId },
      });
    }
  }

  let attestation: IssuerAttestation | null = null;
  if (resolver) {
    attestation = await verifyIssuerIdentity({
      resolver,
      issuerId: signed.envelope.issuerId,
      publicKey: signed.signature.publicKey,
      at: signed.envelope.issuedAt,
      issues,
    });
  }

  return { valid: issues.length === 0, issues, identityChecked: resolver !== undefined, attestation };
}

async function verifyIssuerIdentity(params: {
  resolver: IdentityResolver;
  issuerId: string;
  publicKey: string;
  at: string;
  issues: VerificationIssue[];
}): Promise<IssuerAttestation | null> {
  const { resolver, issuerId, publicKey, at, issues } = params;

  const attestation = await resolver.resolve(issuerId, at);
  if (!attestation) {
    issues.push({
      code: "ISSUER_UNKNOWN",
      message: `no attestation binds a key to issuer ${issuerId}`,
      detail: { issuerId },
    });
    return null;
  }

  if (attestation.publicKey !== publicKey) {
    issues.push({
      code: "ISSUER_KEY_MISMATCH",
      message: `event was signed with a key not attested for issuer ${issuerId}`,
      detail: { issuerId, attestedKey: attestation.publicKey, signingKey: publicKey },
    });
  }

  const window = checkAttestationWindow(attestation, at);
  if (window === "NOT_YET_VALID") {
    issues.push({
      code: "ATTESTATION_NOT_YET_VALID",
      message: `event issued at ${at}, before the attestation became valid at ${attestation.validFrom}`,
      detail: { issuerId, issuedAt: at, validFrom: attestation.validFrom },
    });
  } else if (window === "EXPIRED") {
    issues.push({
      code: "ATTESTATION_EXPIRED",
      message: `event issued at ${at}, after the attestation expired at ${attestation.validUntil}`,
      detail: { issuerId, issuedAt: at, validUntil: attestation.validUntil ?? "" },
    });
  }

  // An unsigned attestation is not an error: it means the resolver vouches
  // directly and trust came from configuring it. See identity.ts.
  if (attestation.signature) {
    const hash = computeAttestationHash(attestation);
    if (!(await verifySignatureBlock(hash, attestation.signature))) {
      issues.push({
        code: "ATTESTATION_SIGNATURE_INVALID",
        message: `attestation for ${issuerId} carries a signature that does not verify`,
        detail: { issuerId, attestedBy: attestation.attestedBy },
      });
    }
  }

  return attestation;
}
