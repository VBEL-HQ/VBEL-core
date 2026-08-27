/**
 * Bootstraps a devnet issuer keypair so a teammate can go from a fresh clone
 * to a working anchor. Writes the key into .env at the repo root (gitignored)
 * and then tries to fund it.
 *
 * The public devnet faucet is aggressively rate-limited and frequently
 * returns 429 or an internal error. When that happens this is not a failure
 * worth debugging — fund the printed address by hand at
 * https://faucet.solana.com (GitHub login, works fine from a phone) and
 * re-run with --check to confirm the balance landed.
 *
 * Devnet only. The key it writes is play money; never reuse it on mainnet.
 *
 * Run: pnpm --filter @vbel/adapter-solana init:devnet
 *      pnpm --filter @vbel/adapter-solana init:devnet -- --check
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { Connection, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import bs58 from "bs58";

const RPC_URL = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const ENV_PATH = resolve(import.meta.dirname, "../../../.env");
const KEY_VAR = "SOLANA_ISSUER_SECRET_KEY";
const AIRDROP_SOL = 1;

function readExistingKey(): string | null {
  if (!existsSync(ENV_PATH)) return null;
  const line = readFileSync(ENV_PATH, "utf8")
    .split("\n")
    .find((l) => l.startsWith(`${KEY_VAR}=`));
  const value = line?.slice(KEY_VAR.length + 1).trim();
  return value && value.length > 0 ? value : null;
}

function persistKey(secretBase58: string): void {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  const withoutKey = existing
    .split("\n")
    .filter((l) => !l.startsWith(`${KEY_VAR}=`))
    .join("\n")
    .replace(/\n+$/, "");
  const next = `${withoutKey ? `${withoutKey}\n` : ""}${KEY_VAR}=${secretBase58}\n`;
  writeFileSync(ENV_PATH, next, { mode: 0o600 });
}

async function main() {
  if (!RPC_URL.includes("devnet")) {
    console.error(`refusing to run against ${RPC_URL} — this script is devnet-only`);
    process.exit(1);
  }

  const connection = new Connection(RPC_URL, "confirmed");

  // Reuse the existing key when there is one, so re-running never orphans a
  // keypair someone already funded by hand.
  const existingKey = readExistingKey();
  const keypair = existingKey ? Keypair.fromSecretKey(bs58.decode(existingKey)) : Keypair.generate();
  const address = keypair.publicKey.toBase58();

  if (existingKey) {
    console.log(`reusing issuer from .env: ${address}`);
  } else {
    persistKey(bs58.encode(keypair.secretKey));
    console.log(`generated devnet issuer: ${address}`);
    console.log(`wrote ${KEY_VAR} to .env (gitignored)`);
  }

  const startingBalance = await connection.getBalance(keypair.publicKey);
  if (startingBalance > 0) {
    console.log(`already funded — balance ${startingBalance / LAMPORTS_PER_SOL} SOL`);
    return;
  }

  if (process.argv.includes("--check")) {
    console.log("balance is still 0 — fund it and re-run");
    process.exit(1);
  }

  try {
    console.log(`requesting ${AIRDROP_SOL} SOL airdrop...`);
    const signature = await connection.requestAirdrop(keypair.publicKey, AIRDROP_SOL * LAMPORTS_PER_SOL);
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature, ...latest }, "confirmed");
    const balance = await connection.getBalance(keypair.publicKey);
    console.log(`funded — balance ${balance / LAMPORTS_PER_SOL} SOL`);
  } catch {
    console.log("\nautomatic airdrop unavailable (the public faucet rate-limits by IP).");
    console.log("fund this address manually, then re-run with --check:\n");
    console.log(`  ${address}\n`);
    console.log("  https://faucet.solana.com  (GitHub login; works from a phone)");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
