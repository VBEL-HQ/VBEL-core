import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  type ParsedInstruction,
} from "@solana/web3.js";
import bs58 from "bs58";
import type {
  AnchorReceipt,
  LedgerAdapter,
  LedgerNetwork,
  LedgerVerificationResult,
  PublicMetadata,
} from "@vbel/core";
import type { SolanaConfig } from "@vbel/config";

const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

/**
 * Conservative estimate of the memo bytes that fit in one legacy Solana
 * transaction (1232-byte limit minus signature, header, account key and
 * blockhash overhead). The cluster is the real enforcer; this is a fast,
 * clear failure before spending an RPC round trip.
 */
export const MAX_MEMO_BYTES = 900;

export class SolanaMemoAdapter implements LedgerAdapter {
  private readonly connection: Connection;
  private readonly issuer: Keypair;
  private readonly net: "devnet" | "mainnet-beta";

  constructor(config: SolanaConfig) {
    this.connection = new Connection(config.rpcUrl, "confirmed");
    this.issuer = Keypair.fromSecretKey(bs58.decode(config.issuerSecretKeyBase58));
    this.net = config.network;
  }

  network(): LedgerNetwork {
    return this.net === "devnet" ? "solana-devnet" : "solana-mainnet";
  }

  async anchor(eventHash: string, metadata: PublicMetadata = {}): Promise<AnchorReceipt> {
    const memoPayload = JSON.stringify({ h: eventHash, ...metadata });
    const bytes = new TextEncoder().encode(memoPayload);
    if (bytes.length > MAX_MEMO_BYTES) {
      throw new Error(
        `memo payload is ${bytes.length} bytes, over the ${MAX_MEMO_BYTES}-byte conservative limit for one transaction`
      );
    }

    const instruction = new TransactionInstruction({
      keys: [],
      programId: MEMO_PROGRAM_ID,
      data: Buffer.from(bytes),
    });

    const transaction = new Transaction().add(instruction);
    const signature = await sendAndConfirmTransaction(this.connection, transaction, [this.issuer]);
    const slot = await this.connection.getSlot("confirmed");

    return {
      network: this.network(),
      reference: signature,
      block: slot,
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

    const parsedTx = await this.connection.getParsedTransaction(receipt.reference, {
      maxSupportedTransactionVersion: 0,
    });
    if (!parsedTx) {
      issues.push(`transaction ${receipt.reference} not found on ${this.net}`);
      return { valid: false, issues };
    }

    const memoInstruction = parsedTx.transaction.message.instructions.find(
      (ix): ix is ParsedInstruction => "program" in ix && ix.program === "spl-memo"
    );
    if (!memoInstruction) {
      issues.push(`transaction ${receipt.reference} carries no memo instruction`);
      return { valid: false, issues };
    }

    let memoPayload: { h?: string };
    try {
      memoPayload = JSON.parse(memoInstruction.parsed as string);
    } catch {
      issues.push("on-chain memo is not valid JSON");
      return { valid: false, issues };
    }

    if (memoPayload.h !== eventHash) {
      issues.push(`on-chain memo hash ${memoPayload.h} does not match expected ${eventHash}`);
    }

    return { valid: issues.length === 0, issues };
  }
}
