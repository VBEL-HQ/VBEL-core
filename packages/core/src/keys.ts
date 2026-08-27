import * as ed25519 from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privateKeyHex: string;
  publicKeyHex: string;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  return {
    privateKey,
    publicKey,
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
  };
}

export function publicKeyFromHex(hex: string): Uint8Array {
  return hexToBytes(hex);
}

export function privateKeyFromHex(hex: string): Uint8Array {
  return hexToBytes(hex);
}

/** Reconstructs a full KeyPair from a private key hex — a fixed seed rather than `randomPrivateKey()`. */
export async function keyPairFromPrivateHex(privateKeyHex: string): Promise<KeyPair> {
  const privateKey = hexToBytes(privateKeyHex);
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  return {
    privateKey,
    publicKey,
    privateKeyHex,
    publicKeyHex: bytesToHex(publicKey),
  };
}
