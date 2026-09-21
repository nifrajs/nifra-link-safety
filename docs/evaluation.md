# Evaluation

Public fixtures use only reserved domains. Private users can pass a local corpus and
fixture file to the CLI without uploading either file.

Track at least:

- Precision and recall for each label
- False-positive rate for benign URLs
- Unknown and review rate
- Provider failure and timeout rate
- p50 and p95 latency
- Cost per 1,000 semantic evaluations
- Results by corpus version and decision version

Do not promote automatic action based on aggregate accuracy alone. Set per-category
thresholds, inspect false negatives, and keep a human-review lane for unresolved cases.
