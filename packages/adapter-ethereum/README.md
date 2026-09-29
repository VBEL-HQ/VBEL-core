# @vbel/adapter-ethereum

Anchors a record's hash in the calldata of a zero-value transaction on an EVM chain.

```bash
pnpm add @vbel/adapter-ethereum
```

## Anchor a hash

```ts
import { EthereumLedgerAdapter, loadEthereumConfig } from "@vbel/adapter-ethereum";

// Read the environment once, at your entry point. The adapter itself never touches process.env.
const adapter = new EthereumLedgerAdapter(loadEthereumConfig());

const receipt = await adapter.anchor(event.eventHash);
const check = await adapter.verify(receipt, event.eventHash); // { valid, issues }
```

`loadEthereumConfig` reads `ETHEREUM_RPC_URL`, `ETHEREUM_NETWORK` (`sepolia` or `mainnet`) and
`ETHEREUM_ISSUER_PRIVATE_KEY`. `encodeCalldata` and `decodeCalldata` are exported for anyone who wants to
read an anchor without this adapter.

Both chain adapters implement the same `LedgerAdapter` interface from `@vbel/core`, so changing chain is
changing one constructor.

An anchor proves a hash existed by the time of the transaction. It says nothing about what the record
means.

## Part of VBEL

Signed, hash-chained records that anyone can check for changes, with optional anchoring on a public
chain. The [repository readme](https://github.com/VBEL-HQ/VBEL-core#readme) says what that does and
does not prove.

Apache-2.0.
