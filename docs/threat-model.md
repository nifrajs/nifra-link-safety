# Threat model

## Assets

- URLs and URL-derived features
- User-provided reputation entries
- Provider credentials
- Tenant-specific corpus labels and operational policies

## Trust boundaries

1. The caller supplies an untrusted URL.
2. The corpus provider supplies untrusted reputation data.
3. The optional TypeSafe provider returns untrusted model output.
4. The host application decides whether to act on the recommendation.

The public packages do not persist any of these values and do not perform network fetches.

## Controls

- URL length, path length, corpus size, and example counts are bounded.
- Credentials and fragments are rejected or omitted from provider state.
- Query values are never sent to the semantic classifier.
- Provider output is validated by `@nifrajs/decision`.
- Provider errors, timeouts, cancellations, and low confidence fail to review.
- Automatic action is disabled by default.
- The CLI omits input URLs unless explicitly requested.

## Explicit non-goals

- This package is not an antivirus engine.
- A model result is not authorization.
- The package does not guarantee that a URL is safe.
- The package does not fetch pages or execute content.

## Future fetcher requirements

Any future URL fetcher must be physically separate from the classifier and must block
loopback, link-local, private, and cloud metadata addresses after every DNS resolution.
It must limit redirects, response bytes, duration, content types, and egress destinations,
and must never forward caller cookies or authorization headers.
