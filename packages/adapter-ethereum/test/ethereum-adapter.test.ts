import { describe, expect, it, vi } from "vitest";
import type { EthereumConfig } from "@vbel/config";
import type { AnchorReceipt } from "@vbel/core";
import {
  decodeCalldata,
  encodeCalldata,
  EthereumLedgerAdapter,
} from "../src/ethereum-adapter.js";

const VALID_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as const;

function testConfig(network: "sepolia" | "mainnet" = "sepolia"): EthereumConfig {
  return {
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    network,
    issuerPrivateKey: VALID_KEY,
  };
}

describe("EthereumLedgerAdapter", () => {
  it("reports its network from injected config, not from the environment", () => {
    const sepoliaAdapter = new EthereumLedgerAdapter(testConfig("sepolia"));
    expect(sepoliaAdapter.network()).toBe("ethereum-sepolia");

    const mainnetAdapter = new EthereumLedgerAdapter(testConfig("mainnet"));
    expect(mainnetAdapter.network()).toBe("ethereum-mainnet");
  });

  describe("calldata encoding and round-tripping", () => {
    it("encodes payload to hex and decodes back to the same event hash and metadata", () => {
      const eventHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      const metadata = { note: "delivery-note", sequence: 42, isFinal: true };

      const encoded = encodeCalldata(eventHash, metadata);
      expect(encoded.startsWith("0x")).toBe(true);

      const decoded = decodeCalldata(encoded);
      expect(decoded.h).toBe(eventHash);
      expect(decoded.note).toBe("delivery-note");
      expect(decoded.sequence).toBe(42);
      expect(decoded.isFinal).toBe(true);
    });

    it("round-trips minimal payload with hash only", () => {
      const eventHash = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
      const encoded = encodeCalldata(eventHash);
      const decoded = decodeCalldata(encoded);
      expect(decoded).toEqual({ h: eventHash });
    });
  });

  describe("verify", () => {
    const validHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const otherHash = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const dummyRef = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    it("collects issue when receipt network mismatches adapter network", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-mainnet",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // Mock getTransaction to fail gracefully (simulating tx not found)
      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue(null);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain(
        "receipt is for network ethereum-mainnet, adapter is on ethereum-sepolia"
      );
    });

    it("collects issue when receipt anchoredHash mismatches expected eventHash", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: otherHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue(null);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain(`receipt anchors ${otherHash}, expected ${validHash}`);
    });

    it("collects issue when transaction is not found on chain", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue(null);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain(`transaction ${dummyRef} not found on sepolia`);
    });

    it("collects issue when transaction RPC lookup throws an error", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockRejectedValue(new Error("RPC timeout"));

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain(`transaction ${dummyRef} not found on sepolia`);
    });

    it("collects issue when transaction carries no calldata", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue({
        input: "0x",
      } as any);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain(`transaction ${dummyRef} carries no calldata`);
    });

    it("collects issue when on-chain calldata is not valid JSON", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue({
        input: "0x123456", // not valid utf-8 json
      } as any);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain("on-chain calldata is not valid JSON");
    });

    it("collects issue when on-chain calldata hash mismatches expected eventHash", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue({
        input: encodeCalldata(otherHash),
      } as any);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain(
        `on-chain calldata hash ${otherHash} does not match expected ${validHash}`
      );
    });

    it("successfully verifies valid receipt matching on-chain calldata", async () => {
      const adapter = new EthereumLedgerAdapter(testConfig("sepolia"));
      const receipt: AnchorReceipt = {
        network: "ethereum-sepolia",
        reference: dummyRef,
        block: 12345,
        timestamp: new Date().toISOString(),
        anchoredHash: validHash,
      };

      // @ts-expect-error accessing private publicClient for mock
      vi.spyOn(adapter.publicClient, "getTransaction").mockResolvedValue({
        input: encodeCalldata(validHash, { source: "test" }),
      } as any);

      const result = await adapter.verify(receipt, validHash);
      expect(result.valid).toBe(true);
      expect(result.issues).toHaveLength(0);
    });
  });
});
