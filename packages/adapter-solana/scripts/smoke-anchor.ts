/**
 * Manual smoke test against real Solana devnet — not part of `pnpm test`.
 * Needs a funded devnet keypair (airdrop via `solana airdrop 1 <pubkey> --url devnet`).
 *
 * Run: pnpm --filter @vbel/adapter-solana smoke:anchor
 */
import { loadSolanaConfig } from "@vbel/config";
import { hashCanonical } from "@vbel/core";
import { SolanaMemoAdapter } from "../src/memo-adapter.js";

async function main() {
  const config = loadSolanaConfig();
  const adapter = new SolanaMemoAdapter(config);

  const eventHash = hashCanonical({ smokeTest: true, at: new Date().toISOString() });
  console.log(`anchoring ${eventHash} on ${adapter.network()}...`);

  const receipt = await adapter.anchor(eventHash, { source: "smoke-anchor" });
  console.log("receipt:", receipt);
  console.log(`https://explorer.solana.com/tx/${receipt.reference}?cluster=devnet`);

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
