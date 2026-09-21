# Contributing

Run the complete gate before opening a pull request:

```sh
bun install
bun run check
bun run build
bun run pack:check
```

Do not add real malicious URLs, customer URLs, provider payloads, API keys, or
personal data. Use reserved domains such as `.test` and `.invalid` for public fixtures.

Changes to result semantics, corpus matching, provider parsing, or security boundaries
require focused regression tests and a changeset.
