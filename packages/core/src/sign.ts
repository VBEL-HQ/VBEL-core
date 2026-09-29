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
import {
  buildSigningMessage,
  parseSigningMessage,
  SIGNATURE_SCHEME_EVENT_HASH,
  SIGNATURE_SCHEME_MESSAGE_V1,
  type MessageEntry,
  type SigningMessageRequest,
} from "./message.js";
import { normalizeSigner, type Signer } from "./signer.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * The lines every readable message carries, whoever is signing and whatever
 * they were told they were doing. Composed here rather than by the caller so a
 * signer cannot be shown a message that omits which record it binds them to.
 */
function envelopeContext(envelope: Envelope): MessageEntry[] {
  const context: MessageEntry[] = [
    { label: "Record", value: envelope.schema },
    { label: "Subject", value: envelope.subjectId },
    { label: "Issuer", value: envelope.issuerId },
    { label: "Issued at", value: envelope.issuedAt },
  ];
  if (envelope.previousEventHash) {
    context.push({ label: "Chains to", value: envelope.previousEventHash });
  }
  return context;
}

/**
 * Produces one signature block, under whichever scheme the call implies:
 * a readable message when the caller supplied one, the bare digest otherwise.
 * Both paths sign bytes through the same `Signer`, so a wallet and a held key
 * are interchangeable at every call site.
 */
async function produceSignature(params: {
  signer: Signer;
  signerId: string;
  /** The digest this signature binds to. Computed here, never accepted from a caller. */
  commitsTo: string;
  request: SigningMessageRequest | undefined;
  context: MessageEntry[];
}): Promise<SignatureBlock> {
  const { signer, signerId, commitsTo, request, context } = params;

  if (!request) {
    const bytes = await signer.sign(utf8(commitsTo));
    return {
      signerId,
      publicKey: signer.publicKeyHex,
      signature: bytesToHex(bytes),
      scheme: SIGNATURE_SCHEME_EVENT_HASH,
      message: null,
    };
  }

  const message = buildSigningMessage({
    action: request.action,
    entries: [...(request.entries ?? []), ...context],
    commitsTo,
  });
  const bytes = await signer.sign(utf8(message));
  return {
    signerId,
    publicKey: signer.publicKeyHex,
    signature: bytesToHex(bytes),
    scheme: SIGNATURE_SCHEME_MESSAGE_V1,
    message,
  };
}

/** eventHash = sha256(canonicalize(envelope)) — the signature is attached alongside, never inside the hashed region. */
export function computeEventHash(envelope: Envelope): string {
  EnvelopeSchema.parse(envelope);
  return hashCanonical(envelope);
}

/**
 * The issuer signs their own event. Every event has exactly one of these.
 *
 * `signer` takes a held `KeyPair` or anything satisfying `Signer`, which is how
 * a wallet signs without ever exposing a key. `message` is what turns an opaque
 * digest into a screen a human can read before approving; omit it and the
 * signature is over the digest exactly as it always was.
 */
export async function signEnvelope(params: {
  envelope: Envelope;
  signer: KeyPair | Signer;
  signerId: string;
  message?: SigningMessageRequest;
}): Promise<SignedEvent> {
  const { envelope, signerId } = params;
  const eventHash = computeEventHash(envelope);

  const signature = await produceSignature({
    signer: normalizeSigner(params.signer),
    signerId,
    commitsTo: eventHash,
    request: params.message,
    context: envelopeContext(envelope),
  });

  return SignedEventSchema.parse({ envelope, eventHash, signature, counterSignature: null });
}

export async function verifyEnvelopeSignature(signed: SignedEvent): Promise<boolean> {
  if (computeEventHash(signed.envelope) !== signed.eventHash) return false;
  return verifySignatureBlock(signed.eventHash, signed.signature);
}

/**
 * Counter-signing.
 * The counter-signer attests to the event they are chaining to — signed over
 * previousEventHash, not over this event's own eventHash — so the claim is
 * "I have seen and agree with exactly that prior content", independent of
 * whatever this new event itself goes on to say.
 */
export async function counterSignPreviousEvent(params: {
  signed: SignedEvent;
  counterSigner: KeyPair | Signer;
  signerId: string;
  message?: SigningMessageRequest;
}): Promise<SignedEvent> {
  const { signed, signerId } = params;
  const previousEventHash = signed.envelope.previousEventHash;
  if (!previousEventHash) {
    throw new Error("cannot counter-sign: envelope.previousEventHash is null");
  }

  /**
   * The context here describes the event being attested to, not the one
   * carrying the attestation: a counter-signer is agreeing with prior content,
   * and a message naming the new event would misstate what they signed.
   */
  const counterSignature = await produceSignature({
    signer: normalizeSigner(params.counterSigner),
    signerId,
    commitsTo: previousEventHash,
    request: params.message,
    context: [{ label: "Subject", value: signed.envelope.subjectId }],
  });

  return SignedEventSchema.parse({ ...signed, counterSignature });
}

export async function verifyCounterSignature(signed: SignedEvent): Promise<boolean> {
  if (!signed.counterSignature) return false;
  if (!signed.envelope.previousEventHash) return false;
  return verifySignatureBlock(signed.envelope.previousEventHash, signed.counterSignature);
}

/**
 * Why a signature did not hold. A bad signature and a signature over text that
 * commits to a different record are both failures, and reporting them as one
 * would hide the only case a reader needs to act on differently: the second
 * means somebody was shown one thing and bound to another.
 */
export type SignatureFailure =
  | "SIGNATURE_INVALID"
  | "MESSAGE_ABSENT"
  | "MESSAGE_MALFORMED"
  | "MESSAGE_DIGEST_MISMATCH";

/** Null when the signature holds. Exported so identity implementations check attestations with the same primitive events use. */
export async function checkSignatureBlock(
  committedTo: string,
  block: SignatureBlock
): Promise<SignatureFailure | null> {
  let signedText = committedTo;

  if (block.scheme === SIGNATURE_SCHEME_MESSAGE_V1) {
    if (block.message === null) return "MESSAGE_ABSENT";
    const parsed = parseSigningMessage(block.message);
    if (!parsed) return "MESSAGE_MALFORMED";
    // The digest is read off the final line rather than searched for, so text
    // elsewhere in the message cannot stand in for it.
    if (parsed.commitsTo !== committedTo) return "MESSAGE_DIGEST_MISMATCH";
    signedText = block.message;
  }

  try {
    const held = await ed25519.verifyAsync(
      hexToBytes(block.signature),
      utf8(signedText),
      hexToBytes(block.publicKey)
    );
    return held ? null : "SIGNATURE_INVALID";
  } catch {
    return "SIGNATURE_INVALID";
  }
}

export async function verifySignatureBlock(message: string, block: SignatureBlock): Promise<boolean> {
  return (await checkSignatureBlock(message, block)) === null;
}

/** Same shape as an event hash: sign over the digest, never over the raw structure. */
export function computeAttestationHash(attestation: IssuerAttestation): string {
  return hashCanonical(attestationSigningRegion(attestation));
}

/** Produces a relayable attestation — one that survives leaving the resolver that issued it. */
export async function signAttestation(params: {
  attestation: IssuerAttestation;
  signer: KeyPair | Signer;
  signerId: string;
}): Promise<IssuerAttestation> {
  const { attestation, signerId } = params;

  /**
   * Digest scheme only. An attestation is read by resolvers rather than
   * approved on a screen, so the readable form would add a surface to verify
   * and nothing for anyone to read.
   */
  const signature = await produceSignature({
    signer: normalizeSigner(params.signer),
    signerId,
    commitsTo: computeAttestationHash(attestation),
    request: undefined,
    context: [],
  });

  return { ...attestation, signature };
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
  /**
   * The signature is over readable text whose final line names a different
   * record than the one it is attached to, or text that is not a well formed
   * message at all. Distinct from an invalid signature: the key really did
   * sign, which means a party was shown one thing and bound to another.
   */
  | "SIGNED_MESSAGE_MISMATCH"
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

  const issuerFailure = await checkSignatureBlock(signed.eventHash, signed.signature);
  if (issuerFailure) {
    issues.push(signatureIssue(issuerFailure, "ISSUER_SIGNATURE_INVALID", signed.signature));
  }

  if (signed.counterSignature) {
    if (!signed.envelope.previousEventHash) {
      issues.push({
        code: "COUNTER_SIGNATURE_ORPHANED",
        message: "counterSignature present but envelope.previousEventHash is null",
      });
    } else {
      const failure = await checkSignatureBlock(
        signed.envelope.previousEventHash,
        signed.counterSignature
      );
      if (failure) {
        issues.push(signatureIssue(failure, "COUNTER_SIGNATURE_INVALID", signed.counterSignature));
      }
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

/**
 * A cryptographic failure and a mismatched message are different findings, so
 * the invalid-signature code is used only when the key genuinely did not sign.
 */
function signatureIssue(
  failure: SignatureFailure,
  invalidCode: "ISSUER_SIGNATURE_INVALID" | "COUNTER_SIGNATURE_INVALID",
  block: SignatureBlock
): VerificationIssue {
  const role = invalidCode === "ISSUER_SIGNATURE_INVALID" ? "issuer signature" : "counter-signature";

  if (failure === "SIGNATURE_INVALID") {
    return {
      code: invalidCode,
      message: `${role} invalid for signerId ${block.signerId}`,
      detail: { signerId: block.signerId },
    };
  }

  const explanation =
    failure === "MESSAGE_ABSENT"
      ? "the signed text is missing, so there is nothing to verify the signature over"
      : failure === "MESSAGE_MALFORMED"
        ? "the signed text is not a well formed vbel-message-v1"
        : "the signed text commits to a different record than the one it is attached to";

  return {
    code: "SIGNED_MESSAGE_MISMATCH",
    message: `${role} for signerId ${block.signerId}: ${explanation}`,
    detail: { signerId: block.signerId, failure },
  };
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
