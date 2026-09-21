# Nifra Link Safety

Local-first, fail-closed URL risk classification for TypeScript applications.

Nifra Link Safety combines deterministic URL analysis, a user-owned reputation
corpus, and an optional Jev/TypeSafe classifier. It returns a typed recommendation
for `allow`, `review`, or `block`; it never fetches, redirects, or changes a URL.

The project deliberately does not ship a malicious-domain database. Users provide
their own corpus or reputation feed, and the corpus remains in their trust boundary.

## Packages

- `@nifrajs/link-safety` - URL normalization, deterministic signals, corpus interfaces,
  and the scanner.
- `@nifrajs/link-safety-typesafe` - optional Jev/TypeSafe System One classifier built
  on `@nifrajs/decision`.
- `@nifrajs/link-safety-cli` - JSONL-friendly CLI for scans and evaluations.

## Quick start

```ts
import {
  createLinkSafetyScanner,
  createMemoryCorpus,
} from "@nifrajs/link-safety";

const corpus = createMemoryCorpus(
  [
    {
      id: "internal-phishing-001",
      indicatorType: "hostname",
      indicator: "phish.example.invalid",
      label: "malicious",
      category: "credential_phishing",
    },
  ],
  { version: "internal-feed-2026-09" },
);

const scanner = createLinkSafetyScanner({ corpus });
const result = await scanner.scan("https://phish.example.invalid/login", {
  policy: { allowAct: true },
});

if (result.ok && result.recommendedAction === "block") {
  // The host application owns the actual redirect, quarantine, or block.
}
```

## Jev classifier

The TypeSafe adapter sends only normalized URL features and a bounded set of
corpus evidence. It never sends query-string values or URL fragments. Keep the
API key in server-side secret storage:

```ts
import { createLinkSafetyScanner } from "@nifrajs/link-safety";
import { createTypeSafeLinkClassifier } from "@nifrajs/link-safety-typesafe";

const scanner = createLinkSafetyScanner({
  classifier: createTypeSafeLinkClassifier({
    apiKey: (() => {
      const apiKey = process.env.TYPESAFE_API_KEY;
      if (!apiKey) throw new Error("TYPESAFE_API_KEY is required");
      return apiKey;
    })(),
    model: "jev-1.13.0",
  }),
});
```

The model is advisory evidence. Invalid output, provider failure, timeout,
cancellation, low confidence, or conflicting signals all remain in review.

## CLI

```sh
bunx nifra-link-safety scan https://example.com
bunx nifra-link-safety scan --corpus ./corpus.jsonl --stdin
bunx nifra-link-safety evaluate \
  --corpus ./fixtures/synthetic-corpus.jsonl \
  --fixtures ./fixtures/synthetic-evaluation.jsonl
```

Use `--typesafe` only when `TYPESAFE_API_KEY` and `TYPESAFE_MODEL` are configured.
The CLI does not include the input URL in output unless `--include-input` is set.

## Security boundary

The scanner does not perform network fetches. A future fetcher must be a separately
sandboxed component with private-IP blocking, DNS-rebinding protection, redirect and
response limits, no cookies, and no authorization headers. See [SECURITY.md](SECURITY.md)
and [docs/threat-model.md](docs/threat-model.md).

## Development

```sh
bun install
bun run check
bun run build
bun run pack:check
bun run evaluate
```

The TypeSafe package depends on the public `@nifrajs/decision` packages. During
local development before those packages are published, use the sibling
`nifra-decisions` checkout or install the packages from their packed artifacts.

## License

MIT. The repository contains no proprietary reputation corpus, model weights, or
provider implementation.
