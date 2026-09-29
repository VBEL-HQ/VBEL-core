import { PublicKey } from "@solana/web3.js";
import type { Signer } from "@vbel/core";

/**
 * A Solana wallet as a VBEL `Signer`.
 *
 * The cryptography needs no bridging: core signs ed25519 over bytes, and a
 * wallet's `signMessage` signs ed25519 over the bytes it is handed. What needs
 * bridging is encoding, which fails quietly in three places:
 *
 *   A Solana public key is base58, while `SignatureBlock.publicKey` is 64
 *   lowercase hex characters. A base58 address written into that field produces
 *   a record that looks signed and verifies against nothing.
 *
 *   A `Keypair.secretKey` is 64 bytes: the 32-byte seed followed by the 32-byte
 *   public key. ed25519 implementations want the seed alone, and passing all 64
 *   bytes yields a valid-looking signature from the wrong key.
 *
 *   A signature is 64 bytes. Anything else means the wallet returned a
 *   different shape than assumed, and failing here beats a verification error
 *   with no clue where it came from.
 *
 * What this cannot settle is whether a given wallet signs the raw bytes or
 * wraps them first. Solana has a separate off-chain message format that prefixes
 * the payload, and a wallet using it would produce signatures that never verify
 * here. That depends on the wallet and can only be checked by signing something
 * in it.
 */

const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

/** The minimum a wallet has to expose. Kept structural so no wallet SDK becomes a dependency of the record layer. */
export interface SolanaMessageSigner {
  /** Base58 address of the signing key. */
  address: string;
  signMessage(message: Uint8Array): Promise<Uint8Array | { signature: Uint8Array }>;
}

export function publicKeyHexFromBase58(address: string): string {
  const bytes = new PublicKey(address).toBytes();
  if (bytes.length !== PUBLIC_KEY_BYTES) {
    throw new Error(`Solana address ${address} decodes to ${bytes.length} bytes, expected ${PUBLIC_KEY_BYTES}`);
  }
  return bytesToHex(bytes);
}

export function base58FromPublicKeyHex(publicKeyHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) {
    throw new Error(`expected 64 lowercase hex characters, got ${JSON.stringify(publicKeyHex)}`);
  }
  return new PublicKey(hexToBytes(publicKeyHex)).toBase58();
}

/**
 * The 32-byte ed25519 seed out of a 64-byte Solana secret key. Exported because
 * anything that loads a keypair needs it, and the slice is easy to get wrong.
 */
export function seedFromSolanaSecretKey(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 64) {
    throw new Error(`expected a 64-byte Solana secret key, got ${secretKey.length} bytes`);
  }
  return secretKey.slice(0, 32);
}

export function solanaWalletSigner(wallet: SolanaMessageSigner): Signer {
  return {
    publicKeyHex: publicKeyHexFromBase58(wallet.address),
    async sign(message) {
      const returned = await wallet.signMessage(message);
      const signature = returned instanceof Uint8Array ? returned : returned.signature;
      if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
        throw new Error(
          `wallet returned a ${signature instanceof Uint8Array ? `${signature.length}-byte` : typeof signature} signature, expected ${SIGNATURE_BYTES} bytes`
        );
      }
      return signature;
    },
  };
}

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from({ length: hex.length / 2 }, (_, i) => Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16));
