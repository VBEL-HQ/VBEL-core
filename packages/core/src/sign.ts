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
 * The lines every readable message carries, whoever is signing. Composed here
 * rather than by the caller so a signer cannot be shown a message that omits
 * which record it binds them to.
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

/** eventHash = sha256(canonicalize(envelope)). The signature sits beside the envelope, never inside the hashed region. */
export function computeEventHash(envelope: Envelope): string {
  EnvelopeSchema.parse(envelope);
  return hashCanonical(envelope);
}

/**
 * The issuer signs their own event. Every event has exactly one of these.
 *
 * `signer` takes a held `KeyPair` or anything satisfying `Signer`, which is how
 * a wallet signs without exposing a key. `message` turns an opaque digest into
 * text a person can read before approving; omit it and the signature is over
 * the digest itself.
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
 * Counter-signing. The counter-signer attests to the event they are chaining
 * to: the signature is over previousEventHash, not over this event's own
 * eventHash. The claim is "I have seen and agree with exactly that prior
 * content", independent of what the new event itself says.
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

  // The context describes the event being attested to, not the one carrying
  // the attestation, because that is what the counter-signer is agreeing with.
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
 * commits to a different record are kept apart because the second means
 * somebody was shown one thing and bound to another, which a reader has to act
 * on differently.
 */
export type SignatureFailure =
  | "SIGNATURE_INVALID"
  | "MESSAGE_ABSENT"
  | "MESSAGE_MALFORMED"
  | "MESSAGE_DIGEST_MISMATCH";

/** Null when the signature holds. Exported so identity implementations check attestations with the same primitive that events use. */
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

/** Produces a relayable attestation: one that stays verifiable after leaving the resolver that issued it. */
export async function signAttestation(params: {
  attestation: IssuerAttestation;
  signer: KeyPair | Signer;
  signerId: string;
}): Promise<IssuerAttestation> {
  const { attestation, signerId } = params;

  // Digest scheme only: resolvers read an attestation, nobody approves it on a
  // screen, so a readable message would add a surface to verify for no reader.
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
 * Machine-readable outcomes. Branch on the code; the message strings are for
 * people reading a log and are not a stable interface.
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
   * message. Distinct from an invalid signature: the key did sign, so a party
   * was shown one thing and bound to another.
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
   * False when no resolver was supplied. Separates "identity confirmed" from
   * "identity never checked": `valid: true` on its own says the record is
   * internally consistent, not that the issuer is who they claim.
   */
  identityChecked: boolean;
  /** The attestation identity was checked against, when one was found. */
  attestation: IssuerAttestation | null;
}

/**
 * Full verification of one event: hash integrity, issuer signature,
 * counter-signature if present, and, when a resolver is supplied, that the
 * signing key belongs to the issuer it claims to be.
 *
 * The resolver is optional so verification works with no network and no
 * configuration. The unresolved case proves less, and `identityChecked`
 * reports that.
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

/** The invalid-signature code is used only when the key did not sign; a mismatched message is a different finding. */
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

  // An unsigned attestation is not an error: the resolver vouches directly and
  // trust comes from how it was configured. See identity.ts.
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
