import * as ed25519 from "@noble/ed25519";
import type { KeyPair } from "./keys.js";

/**
 * Something that can produce an ed25519 signature, without necessarily being
 * able to hand over the key that made it.
 *
 * Until now signing took a `KeyPair`, which assumes the private key is a value
 * this process holds. A wallet never gives that up: it exposes
 * `signMessage(bytes)` and nothing else. Every other party in this system can
 * keep passing a `KeyPair`, so the interface exists to make the one case that
 * cannot possible, not to change the ones that already work.
 *
 * The contract is deliberately narrow. A signer signs bytes it is handed and
 * reports which public key will verify them. It does not know what an envelope
 * is, what a chain is, or why it is being asked, which is what lets a hardware
 * key, a browser extension and a test fixture all satisfy it.
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
 * Accepts either form at the call site. A `KeyPair` has no `sign`, which is
 * what distinguishes the two: the check is for the capability rather than for
 * the absence of a private key, so an implementation that happens to hold a
 * key and also signs is treated as the signer it is.
 */
export function normalizeSigner(signer: KeyPair | Signer): Signer {
  return "sign" in signer ? signer : signerFromKeyPair(signer);
}
