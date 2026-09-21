# Architecture

Nifra Link Safety is deliberately split into a deterministic core, an optional semantic
classifier, and a CLI.

```text
caller input
  -> normalizeLink()
  -> corpus lookup
  -> deterministic signals
  -> optional LinkClassifier
  -> confidence and policy gate
  -> typed recommendation
```

The core package has no network dependency. A `LinkCorpus` is an interface so applications
can use an in-memory list, a file, a database, or a hosted reputation service without
putting storage or tenant state into the public package.

The TypeSafe package translates the safe, normalized feature surface into the existing
Nifra decision contract. `@nifrajs/decision` validates the provider response and applies
the confidence gate. The host application remains responsible for the final action.

## Release order

The foundation packages in `nifra-decisions` must be published before publishing the
TypeSafe package from this repository. The workspace uses local Bun link overrides only
for development while those packages are unpublished. The package manifests themselves
retain public semver dependencies.

Before the first public release:

1. Publish the foundation packages at the versions declared here.
2. Remove the root development overrides and regenerate `bun.lock` from the registry.
3. Run the clean consumer and CI gates from a checkout that has no sibling repositories.
4. Publish the three Link Safety packages in dependency order.
