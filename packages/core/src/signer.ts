import * as ed25519 from "@noble/ed25519";
import type { KeyPair } from "./keys.js";

/**
 * Something that can produce an ed25519 signature without necessarily being
 * able to hand over the key that made it.
 *
 * A `KeyPair` assumes the private key is a value this process holds. A wallet
 * never gives that up: it exposes `signMessage(bytes)` and nothing else. Code
 * that holds a key can keep passing a `KeyPair`; this interface exists for the
 * case that cannot.
 *
 * The contract is deliberately narrow. A signer signs the bytes it is handed
 * and reports which public key verifies them. It knows nothing of envelopes or
 * chains, which is what lets a hardware key, a browser extension and a test
 * fixture all satisfy it.
 */
export interface Signer {
  /** Hex encoded ed25519 public key, matching `SignatureBlock.publicKey`. */
  publicKeyHex: string;
  /** Detached ed25519 signature over exactly these bytes. 64 bytes. */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export function signerFromKeyPair(keys: KeyPair): Signer {
  return {
    publicKeyHex: keys.publicKeyHex,
    sign: (message) => ed25519.signAsync(message, keys.privateKey),
  };
}

/**
 * Accepts either form at the call site. It checks for the `sign` capability
 * rather than for the absence of a private key, so an object that holds a key
 * and also signs is treated as the signer it is.
 */
export function normalizeSigner(signer: KeyPair | Signer): Signer {
  return "sign" in signer ? signer : signerFromKeyPair(signer);
}
