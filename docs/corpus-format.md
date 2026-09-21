# Corpus format

The corpus is user-owned. Nifra Link Safety does not ship a default reputation database.

JSONL entries use these fields:

```json
{
  "id": "case-001",
  "indicatorType": "hostname",
  "indicator": "bad.example.invalid",
  "label": "malicious",
  "category": "credential_phishing",
  "source": "internal-feed",
  "updatedAt": "2026-09-21T00:00:00Z"
}
```

Supported indicator types are `hostname`, `hostname_path_prefix`, and `url_prefix`.
Labels are `benign`, `suspicious`, and `malicious`.

The parser validates every line, rejects duplicate IDs, bounds total bytes and entries,
and treats conflicting labels as a review signal rather than silently picking one.
