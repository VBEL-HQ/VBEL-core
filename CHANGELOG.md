# Changelog

## 0.2.0

Applies to every `@vbel/*` package, which are versioned together from here.

- Dependencies: `zod` 3 to 4. The `pnpm audit` findings (zod DoS, stream-json and uuid through `@solana/web3.js`, and the vitest toolchain) are fixed.
- Because zod is a major bump, this is a minor release under 0.x. If you pass your own zod schemas to `@vbel/records` (`decodeChain` payload schemas), use zod 4 in your app too.
- No change to record formats, signatures or hashes. The canonicalization test vector is unchanged.

## 0.1.x

First public releases.
