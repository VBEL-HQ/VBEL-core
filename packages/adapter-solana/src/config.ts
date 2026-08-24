import { z } from "zod";
import { parseEnv } from "./load.js";

export const SolanaEnvSchema = z.object({
  SOLANA_RPC_URL: z.string().url(),
  SOLANA_NETWORK: z.enum(["devnet", "mainnet-beta"]).default("devnet"),
  /** Base58-encoded secret key of the issuing keypair. Never committed — see .env.example. */
  SOLANA_ISSUER_SECRET_KEY: z.string().min(1),
});
export type SolanaEnv = z.infer<typeof SolanaEnvSchema>;

export interface SolanaConfig {
  rpcUrl: string;
  network: "devnet" | "mainnet-beta";
  issuerSecretKeyBase58: string;
}

/**
 * Call once, at the process entry point (app bootstrap or a CLI script).
 * Execution code (adapters, apps) receives the resulting SolanaConfig as a
 * parameter — it never reads process.env itself.
 */
export function loadSolanaConfig(source: NodeJS.ProcessEnv = process.env): SolanaConfig {
  const env = parseEnv(SolanaEnvSchema, source, "Solana");
  return {
    rpcUrl: env.SOLANA_RPC_URL,
    network: env.SOLANA_NETWORK,
    issuerSecretKeyBase58: env.SOLANA_ISSUER_SECRET_KEY,
  };
}
