import { describe, expect, it } from "vitest";
import { loadSolanaConfig } from "../src/solana.js";

describe("loadSolanaConfig", () => {
  it("parses a valid env source into typed config", () => {
    const config = loadSolanaConfig({
      SOLANA_RPC_URL: "https://api.devnet.solana.com",
      SOLANA_NETWORK: "devnet",
      SOLANA_ISSUER_SECRET_KEY: "fake-base58-key-for-test",
    } as NodeJS.ProcessEnv);

    expect(config).toEqual({
      rpcUrl: "https://api.devnet.solana.com",
      network: "devnet",
      issuerSecretKeyBase58: "fake-base58-key-for-test",
    });
  });

  it("defaults SOLANA_NETWORK to devnet when unset", () => {
    const config = loadSolanaConfig({
      SOLANA_RPC_URL: "https://api.devnet.solana.com",
      SOLANA_ISSUER_SECRET_KEY: "fake-base58-key-for-test",
    } as NodeJS.ProcessEnv);

    expect(config.network).toBe("devnet");
  });

  it("throws with every missing/invalid field named, not just the first", () => {
    expect(() => loadSolanaConfig({} as NodeJS.ProcessEnv)).toThrowError(
      /SOLANA_RPC_URL[\s\S]*SOLANA_ISSUER_SECRET_KEY|SOLANA_ISSUER_SECRET_KEY[\s\S]*SOLANA_RPC_URL/
    );
  });

  it("rejects a malformed URL", () => {
    expect(() =>
      loadSolanaConfig({
        SOLANA_RPC_URL: "not-a-url",
        SOLANA_ISSUER_SECRET_KEY: "fake-base58-key-for-test",
      } as NodeJS.ProcessEnv)
    ).toThrow();
  });
});
