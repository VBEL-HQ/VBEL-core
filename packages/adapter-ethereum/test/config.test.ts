import { describe, expect, it } from "vitest";
import { loadEthereumConfig } from "../src/ethereum.js";

const VALID_KEY = ("0x" + "1".repeat(64)) as `0x${string}`;

describe("loadEthereumConfig", () => {
  it("parses a valid env source into typed config", () => {
    const config = loadEthereumConfig({
      ETHEREUM_RPC_URL: "https://ethereum-sepolia-rpc.publicnode.com",
      ETHEREUM_NETWORK: "sepolia",
      ETHEREUM_ISSUER_PRIVATE_KEY: VALID_KEY,
    } as NodeJS.ProcessEnv);

    expect(config).toEqual({
      rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
      network: "sepolia",
      issuerPrivateKey: VALID_KEY,
    });
  });

  it("defaults ETHEREUM_NETWORK to sepolia when unset", () => {
    const config = loadEthereumConfig({
      ETHEREUM_RPC_URL: "https://ethereum-sepolia-rpc.publicnode.com",
      ETHEREUM_ISSUER_PRIVATE_KEY: VALID_KEY,
    } as NodeJS.ProcessEnv);

    expect(config.network).toBe("sepolia");
  });

  it("throws with every missing/invalid field named, not just the first", () => {
    expect(() => loadEthereumConfig({} as NodeJS.ProcessEnv)).toThrowError(
      /ETHEREUM_RPC_URL[\s\S]*ETHEREUM_ISSUER_PRIVATE_KEY|ETHEREUM_ISSUER_PRIVATE_KEY[\s\S]*ETHEREUM_RPC_URL/
    );
  });

  it("rejects a malformed URL", () => {
    expect(() =>
      loadEthereumConfig({
        ETHEREUM_RPC_URL: "not-a-url",
        ETHEREUM_ISSUER_PRIVATE_KEY: VALID_KEY,
      } as NodeJS.ProcessEnv)
    ).toThrow();
  });

  it("rejects a malformed private key", () => {
    expect(() =>
      loadEthereumConfig({
        ETHEREUM_RPC_URL: "https://ethereum-sepolia-rpc.publicnode.com",
        ETHEREUM_ISSUER_PRIVATE_KEY: "not-a-valid-hex-key",
      } as NodeJS.ProcessEnv)
    ).toThrow();
  });
});
