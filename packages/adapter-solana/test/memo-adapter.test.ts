import { describe, expect, it } from "vitest";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import type { SolanaConfig } from "@vbel/config";
import { MAX_MEMO_BYTES, SolanaMemoAdapter } from "../src/memo-adapter.js";

/**
 * No network access in this test file — it only exercises the guard that
 * fails fast before an RPC round trip. Anchoring/verifying against real
 * devnet is scripts/smoke-anchor.ts, run manually with a funded keypair.
 */
function testConfig(): SolanaConfig {
  const kp = Keypair.generate();
  return {
    rpcUrl: "https://api.devnet.solana.com",
    network: "devnet",
    issuerSecretKeyBase58: bs58.encode(kp.secretKey),
  };
}

describe("SolanaMemoAdapter", () => {
  it("reports its network from injected config, not from the environment", () => {
    const adapter = new SolanaMemoAdapter(testConfig());
    expect(adapter.network()).toBe("solana-devnet");
  });

  it("rejects an oversized memo payload before touching the network", async () => {
    const adapter = new SolanaMemoAdapter(testConfig());
    const oversized = "x".repeat(MAX_MEMO_BYTES);

    await expect(adapter.anchor("sha256:" + "0".repeat(64), { note: oversized })).rejects.toThrow(
      /over the .* conservative limit/
    );
  });
});
