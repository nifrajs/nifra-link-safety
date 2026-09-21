# Security policy

Please report suspected vulnerabilities privately through the repository's GitHub
Security Advisory form:

https://github.com/nifrajs/nifra-link-safety/security/advisories/new

Include a minimal reproduction, affected package and version, and impact. If the
advisory form is unavailable, contact the maintainers through a private channel
rather than sharing sensitive details in a public issue. Do not include real
customer URLs, credentials, tokens, or personal data.

Nifra Link Safety is intentionally a non-fetching classifier. It treats corpus entries,
provider output, and URLs as untrusted input. Host applications remain responsible for
authentication, authorization, tenant isolation, retention, consent, and the final
redirect, quarantine, or blocking action.

Known limitations and the threat model are documented in [docs/threat-model.md](docs/threat-model.md).
