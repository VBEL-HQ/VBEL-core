/**
 * Manual smoke test against real Ethereum Sepolia testnet — not part of `pnpm test`.
 * Needs a funded Sepolia private key (e.g. from https://www.alchemy.com/faucets/ethereum-sepolia).
 *
 * Run: set -a && source .env && set +a && pnpm --filter @vbel/adapter-ethereum smoke:anchor
 */
import { loadEthereumConfig } from "@vbel/config";
import { hashCanonical } from "@vbel/core";
import { EthereumLedgerAdapter } from "../src/ethereum-adapter.js";

async function main() {
  const config = loadEthereumConfig();
  const adapter = new EthereumLedgerAdapter(config);

  const eventHash = hashCanonical({ smokeTest: true, at: new Date().toISOString() });
  console.log(`anchoring ${eventHash} on ${adapter.network()}...`);

  const receipt = await adapter.anchor(eventHash, { source: "smoke-anchor" });
  console.log("receipt:", receipt);
  console.log(`https://sepolia.etherscan.io/tx/${receipt.reference}`);

  const result = await adapter.verify(receipt, eventHash);
  console.log("verify:", result);

  if (!result.valid) {
    console.error("smoke test FAILED — anchored receipt did not verify");
    process.exit(1);
  }
  console.log("smoke test passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
