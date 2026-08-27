import {
  createPublicClient,
  createWalletClient,
  hexToString,
  http,
  stringToHex,
  type Account,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";
import { mainnet, sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import type {
  AnchorReceipt,
  LedgerAdapter,
  LedgerNetwork,
  LedgerVerificationResult,
  PublicMetadata,
} from "@vbel/core";
import type { EthereumConfig } from "@vbel/config";

/**
 * Encodes the event hash and optional public metadata into a JSON string,
 * then converts it to UTF-8 hex calldata.
 */
export function encodeCalldata(eventHash: string, metadata: PublicMetadata = {}): Hex {
  const payload = JSON.stringify({ h: eventHash, ...metadata });
  return stringToHex(payload);
}

/**
 * Decodes UTF-8 hex calldata back into a JSON object containing the `h` field.
 */
export function decodeCalldata(calldata: Hex | string): { h?: string; [key: string]: unknown } {
  const hex = calldata.startsWith("0x") ? (calldata as Hex) : (`0x${calldata}` as Hex);
  const jsonStr = hexToString(hex);
  return JSON.parse(jsonStr);
}

export class EthereumLedgerAdapter implements LedgerAdapter {
  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;
  private readonly account: Account;
  private readonly net: "sepolia" | "mainnet";

  constructor(config: EthereumConfig) {
    this.net = config.network;
    const chain = config.network === "mainnet" ? mainnet : sepolia;
    const transport = http(config.rpcUrl);
    this.account = privateKeyToAccount(config.issuerPrivateKey);
    this.publicClient = createPublicClient({ chain, transport });
    this.walletClient = createWalletClient({ chain, transport, account: this.account });
  }

  network(): LedgerNetwork {
    return this.net === "sepolia" ? "ethereum-sepolia" : "ethereum-mainnet";
  }

  async anchor(eventHash: string, metadata: PublicMetadata = {}): Promise<AnchorReceipt> {
    const calldata = encodeCalldata(eventHash, metadata);

    const hash = await this.walletClient.sendTransaction({
      account: this.account,
      to: this.account.address,
      value: 0n,
      data: calldata,
      chain: this.walletClient.chain,
    });

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    return {
      network: this.network(),
      reference: hash,
      block: receipt.blockNumber !== null && receipt.blockNumber !== undefined ? Number(receipt.blockNumber) : null,
      timestamp: new Date().toISOString(),
      anchoredHash: eventHash,
    };
  }

  async verify(receipt: AnchorReceipt, eventHash: string): Promise<LedgerVerificationResult> {
    const issues: string[] = [];

    if (receipt.network !== this.network()) {
      issues.push(`receipt is for network ${receipt.network}, adapter is on ${this.network()}`);
    }
    if (receipt.anchoredHash !== eventHash) {
      issues.push(`receipt anchors ${receipt.anchoredHash}, expected ${eventHash}`);
    }

    let tx;
    try {
      tx = await this.publicClient.getTransaction({
        hash: receipt.reference as Hex,
      });
    } catch {
      issues.push(`transaction ${receipt.reference} not found on ${this.net}`);
      return { valid: false, issues };
    }

    if (!tx) {
      issues.push(`transaction ${receipt.reference} not found on ${this.net}`);
      return { valid: false, issues };
    }

    if (!tx.input || tx.input === "0x") {
      issues.push(`transaction ${receipt.reference} carries no calldata`);
      return { valid: false, issues };
    }

    let payload: { h?: string };
    try {
      payload = decodeCalldata(tx.input);
    } catch {
      issues.push("on-chain calldata is not valid JSON");
      return { valid: false, issues };
    }

    if (payload.h !== eventHash) {
      issues.push(`on-chain calldata hash ${payload.h} does not match expected ${eventHash}`);
    }

    return { valid: issues.length === 0, issues };
  }
}

export {
  EthereumLedgerAdapter as EthereumCalldataAdapter,
  EthereumLedgerAdapter as EthereumAdapter,
};
