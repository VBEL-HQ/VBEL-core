/**
 * The chain-neutral contract every ledger adapter implements
 * (TECHNICAL-BRIEF.md §6). Pure types, no I/O — this file is why an adapter
 * can depend on core without core ever depending back on an adapter.
 */

export type LedgerNetwork =
  | "solana-devnet"
  | "solana-mainnet"
  | "ethereum-sepolia"
  | "ethereum-mainnet";

export type PublicMetadata = Record<string, string | number | boolean>;

export interface AnchorReceipt {
  network: LedgerNetwork;
  /** Transaction signature (Solana) or transaction hash (Ethereum). */
  reference: string;
  /** Slot (Solana) or block number (Ethereum). Null if not yet known. */
  block: string | number | null;
  /** ISO 8601 — when the adapter observed confirmation, not necessarily block time. */
  timestamp: string;
  /** The eventHash that was anchored, "sha256:<hex>". */
  anchoredHash: string;
}

export interface LedgerVerificationResult {
  valid: boolean;
  issues: string[];
}

export interface LedgerAdapter {
  network(): LedgerNetwork;
  anchor(eventHash: string, metadata?: PublicMetadata): Promise<AnchorReceipt>;
  verify(receipt: AnchorReceipt, eventHash: string): Promise<LedgerVerificationResult>;
  revoke?(receipt: AnchorReceipt, reasonHash: string): Promise<AnchorReceipt>;
}
