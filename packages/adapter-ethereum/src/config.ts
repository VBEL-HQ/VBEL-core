import { z } from "zod";
import { parseEnv } from "./load.js";

export const EthereumEnvSchema = z.object({
  ETHEREUM_RPC_URL: z.string().url(),
  ETHEREUM_NETWORK: z.enum(["sepolia", "mainnet"]).default("sepolia"),
  /** 0x-prefixed 64-hex private key of the issuing account. Never committed — see .env.example. */
  ETHEREUM_ISSUER_PRIVATE_KEY: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
});
export type EthereumEnv = z.infer<typeof EthereumEnvSchema>;

export interface EthereumConfig {
  rpcUrl: string;
  network: "sepolia" | "mainnet";
  issuerPrivateKey: `0x${string}`;
}

/**
 * Call once, at the process entry point (app bootstrap or a CLI script).
 * Execution code (adapters, apps) receives the resulting EthereumConfig as a
 * parameter — it never reads process.env itself.
 */
export function loadEthereumConfig(source: NodeJS.ProcessEnv = process.env): EthereumConfig {
  const env = parseEnv(EthereumEnvSchema, source, "Ethereum");
  return {
    rpcUrl: env.ETHEREUM_RPC_URL,
    network: env.ETHEREUM_NETWORK,
    issuerPrivateKey: env.ETHEREUM_ISSUER_PRIVATE_KEY as `0x${string}`,
  };
}
