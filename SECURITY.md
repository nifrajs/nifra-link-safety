# Security policy

Please report suspected vulnerabilities privately to the maintainers with a minimal
reproduction, affected version, impact, and safe contact path. Do not include real
customer URLs, credentials, tokens, or personal data.

Nifra Link Safety is intentionally a non-fetching classifier. It treats corpus entries,
provider output, and URLs as untrusted input. Host applications remain responsible for
authentication, authorization, tenant isolation, retention, consent, and the final
redirect, quarantine, or blocking action.

Known limitations and the threat model are documented in [docs/threat-model.md](docs/threat-model.md).
