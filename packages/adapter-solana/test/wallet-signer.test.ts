import { describe, expect, it } from "vitest";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import {
  computeEventHash,
  parseSigningMessage,
  signEnvelope,
  verifyEvent,
  type Envelope,
} from "@vbel/core";
import {
  base58FromPublicKeyHex,
  publicKeyHexFromBase58,
  seedFromSolanaSecretKey,
  solanaWalletSigner,
} from "../src/wallet-signer.js";

/**
 * The gate this package exists to clear: a Solana key, signing the way a wallet
 * signs, produces a record core accepts.
 *
 * The signature is produced by tweetnacl and verified by @noble, deliberately.
 * A test where one implementation checks its own output proves the arithmetic is
 * self-consistent and nothing about interoperating with a wallet, which is the
 * only risk worth a test here. tweetnacl is also what Phantom's own
 * documentation verifies signatures with, so it is the closest stand-in
 * available without an extension in the room.
 *
 * What stays unproven until a real wallet signs once: whether the extension
 * hands the raw bytes to ed25519 or wraps them in Solana's off-chain message
 * envelope first. No test here can settle that.
 */

/** Exactly what a wallet does: detached ed25519 over the bytes handed in, nothing wrapped around them. */
function walletFor(keypair: Keypair) {
  const seed = seedFromSolanaSecretKey(keypair.secretKey);
  return {
    address: keypair.publicKey.toBase58(),
    signMessage: async (message: Uint8Array) => ({
      signature: nacl.sign.detached(message, nacl.sign.keyPair.fromSeed(seed).secretKey),
    }),
  };
}

function envelopeFor(issuerId: string): Envelope {
  return {
    schema: "urn:vbel:event:advance:v1",
    eventId: "11111111-1111-4111-8111-111111111111",
    subjectId: "urn:vbel:obligation:INV-2026-0412",
    issuerId,
    issuedAt: "2026-09-29T10:12:03.000Z",
    previousEventHash: null,
    payloadHash: `sha256:${"a".repeat(64)}`,
    status: "ACTIVE",
    supersedes: null,
    supersedeReason: null,
    revokes: null,
    revokeReason: null,
    policyId: "urn:vbel:policy:v1",
    privacy: "off-chain",
    nonce: "22222222-2222-4222-8222-222222222222",
  };
}

describe("a Solana wallet as a VBEL signer", () => {
  it("signs an envelope that core verifies, with the signature made by a different ed25519 implementation", async () => {
    const keypair = Keypair.generate();
    const signed = await signEnvelope({
      envelope: envelopeFor("financier-c"),
      signer: solanaWalletSigner(walletFor(keypair)),
      signerId: "financier-c",
    });

    const result = await verifyEvent(signed);
    expect(result.issues).toEqual([]);
    expect(result.valid).toBe(true);
    // Identity was never checked, and a caller must be able to tell that apart
    // from an issuer who was confirmed.
    expect(result.identityChecked).toBe(false);
  });

  it("records the wallet's key in the hex form the record format uses", async () => {
    const keypair = Keypair.generate();
    const signed = await signEnvelope({
      envelope: envelopeFor("financier-c"),
      signer: solanaWalletSigner(walletFor(keypair)),
      signerId: "financier-c",
    });

    expect(signed.signature.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(base58FromPublicKeyHex(signed.signature.publicKey)).toBe(keypair.publicKey.toBase58());
  });

  it("signs a message a human can read, whose last line commits to this record", async () => {
    const keypair = Keypair.generate();
    const envelope = envelopeFor("financier-c");
    const signed = await signEnvelope({
      envelope,
      signer: solanaWalletSigner(walletFor(keypair)),
      signerId: "financier-c",
      message: {
        action: "Advance funds against this receivable",
        entries: [
          { label: "Amount", value: "1.287,80 EUR" },
          { label: "Beneficiary", value: "Supplier A" },
        ],
      },
    });

    expect(signed.signature.scheme).toBe("vbel-message-v1");
    const parsed = parseSigningMessage(signed.signature.message ?? "");
    expect(parsed?.commitsTo).toBe(computeEventHash(envelope));
    expect(parsed?.entries).toContainEqual({ label: "Amount", value: "1.287,80 EUR" });
    // The record's own identity is in the text too, not only the caller's facts.
    expect(parsed?.entries).toContainEqual({
      label: "Subject",
      value: "urn:vbel:obligation:INV-2026-0412",
    });

    expect((await verifyEvent(signed)).valid).toBe(true);
  });

  it("rejects a signature made over a different record", async () => {
    const keypair = Keypair.generate();
    const signed = await signEnvelope({
      envelope: envelopeFor("financier-c"),
      signer: solanaWalletSigner(walletFor(keypair)),
      signerId: "financier-c",
    });

    const elsewhere = await signEnvelope({
      envelope: { ...envelopeFor("financier-c"), nonce: "33333333-3333-4333-8333-333333333333" },
      signer: solanaWalletSigner(walletFor(keypair)),
      signerId: "financier-c",
    });

    const swapped = { ...signed, signature: elsewhere.signature };
    const result = await verifyEvent(swapped);
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain("ISSUER_SIGNATURE_INVALID");
  });
});

describe("the encodings that fail quietly", () => {
  it("round-trips a public key between base58 and hex", () => {
    const address = Keypair.generate().publicKey.toBase58();
    expect(base58FromPublicKeyHex(publicKeyHexFromBase58(address))).toBe(address);
  });

  it("takes the seed from a 64-byte secret key, not the whole thing", () => {
    const keypair = Keypair.generate();
    const seed = seedFromSolanaSecretKey(keypair.secretKey);
    expect(seed).toHaveLength(32);
    // The seed has to be the half that regenerates this exact public key.
    expect(nacl.sign.keyPair.fromSeed(seed).publicKey).toEqual(keypair.publicKey.toBytes());
  });

  it("refuses a secret key of the wrong length rather than signing with the wrong half", () => {
    expect(() => seedFromSolanaSecretKey(new Uint8Array(32))).toThrow(/64-byte/);
  });

  it("refuses a signature that is not 64 bytes", async () => {
    const signer = solanaWalletSigner({
      address: Keypair.generate().publicKey.toBase58(),
      signMessage: async () => new Uint8Array(32),
    });
    await expect(signer.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow(/32-byte signature/);
  });
});
