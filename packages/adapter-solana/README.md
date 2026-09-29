# @vbel/adapter-solana

Anchors a record's hash on Solana through the SPL Memo program, with no custom program, and turns a Solana
wallet into a `Signer` so a person can read what they approve.

```bash
pnpm add @vbel/adapter-solana
```

## Anchor a hash

```ts
import { SolanaMemoAdapter, loadSolanaConfig } from "@vbel/adapter-solana";

// Read the environment once, at your entry point. The adapter itself never touches process.env.
const adapter = new SolanaMemoAdapter(loadSolanaConfig());

const receipt = await adapter.anchor(event.eventHash); // { network, reference, block, timestamp, anchoredHash }
const check = await adapter.verify(receipt, event.eventHash); // { valid, issues }
```

`loadSolanaConfig` reads `SOLANA_RPC_URL`, `SOLANA_NETWORK` (`devnet` or `mainnet-beta`) and
`SOLANA_ISSUER_SECRET_KEY`. The memo carries the hash and a little public metadata, at most
`MAX_MEMO_BYTES` (900) in all. The account that pays is the issuer key, which is not a signer of your
records.

## Sign with a wallet

```ts
import { solanaWalletSigner } from "@vbel/adapter-solana";

// Anything with an `address` and `signMessage(bytes)`, such as a browser wallet.
const signer = solanaWalletSigner(wallet);
```

The returned `Signer` goes wherever `@vbel/core` accepts a key, and the wallet shows the person a message
they can read rather than a bare hash.

An anchor proves a hash existed by the time of the transaction. It says nothing about what the record
means.

## Part of VBEL

Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public
chain. The [repository readme](https://github.com/VBEL-HQ/VBEL-core#readme) says what that does and
does not prove.

Apache-2.0.
