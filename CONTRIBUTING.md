# Contributing

Issues and pull requests are welcome. Before a larger change, open an issue to
agree the shape of it.

```bash
pnpm install
pnpm build
pnpm typecheck
pnpm test
```

Rules that keep the library trustworthy:

- `@vbel/core` imports nothing from any other package, and does no I/O.
- The envelope (`packages/core/src/envelope.ts`) is frozen at v0.1. A change to
  it changes what every existing signature means. A new version is a new
  schema and a new type.
- A withheld payload is not a forged one. Any code that reads a payload has to
  say what it means by absence.
- Tests describe behaviour a reader could rely on, including the failure cases.
  Say what an example does not prove as clearly as what it does.
