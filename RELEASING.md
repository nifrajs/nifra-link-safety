# Releasing Nifra Link Safety

Nifra Link Safety publishes three public npm packages:

- `@nifrajs/link-safety`
- `@nifrajs/link-safety-typesafe`
- `@nifrajs/link-safety-cli`

## Dependency gate

The TypeSafe package depends on the public `@nifrajs/decision` and
`@nifrajs/decision-typesafe` packages. Those foundation packages must be published
before this repository can be installed from a clean public checkout.

Until that happens, the root `package.json` contains local-only Bun overrides for
development. Do not treat a checkout containing `link:@nifrajs/decision` or
`link:@nifrajs/decision-typesafe` as the final public release state.

After the foundation packages are available from npm:

1. Remove the root `overrides` block.
2. Run `bun install` from a checkout that has no sibling repository available.
3. Review and commit the regenerated `bun.lock`.
4. Run the complete release gate and confirm no local `link:` entries remain.

## Release gate

From a clean checkout:

```sh
bun install --frozen-lockfile
bun run release:check
```

The gate runs linting, typechecking, tests, the build, package metadata checks,
synthetic evaluation fixtures, and the dependency audit. Run a dry-run publish from
each package directory as a final file-list check:

```sh
bun publish --dry-run
```

The tarballs must not contain credentials, customer URLs, local paths, reputation
corpus data, or `*.tsbuildinfo` files.

## Publish order

Publish in dependency order:

1. `@nifrajs/link-safety`
2. `@nifrajs/link-safety-typesafe`
3. `@nifrajs/link-safety-cli`

Use public access and publish only from a clean, reviewed commit. The repository
does not ship a malicious-domain corpus; users provide their own corpus within their
own trust boundary.

## npm trusted publishing

The repository includes `.github/workflows/publish.yml` for tokenless npm publishing
through GitHub Actions OIDC. It uses Node 24, npm 11+, `id-token: write`, and the
`npm-publish` GitHub environment. It does not use an `NPM_TOKEN` or other long-lived
publish secret. npm generates provenance automatically for this public repository
and public packages.

For each package on npm, add a GitHub Actions trusted publisher with these exact
values:

- Organization or user: `nifrajs`
- Repository: `nifra-link-safety`
- Workflow filename: `publish.yml`
- Environment name: `npm-publish`
- Allowed action: `npm publish`

Create the `npm-publish` GitHub environment and require a maintainer reviewer for
the strongest release gate. After the first successful trusted publish, set npm
Publishing access to **Require two-factor authentication and disallow tokens**, and
revoke obsolete automation tokens. See the [npm trusted publishing
documentation](https://docs.npmjs.com/trusted-publishers).

New package names may require one interactive maintainer bootstrap publish before
the npm package settings page exists. Do not create a bypass-2FA automation token;
use an interactive, 2FA-protected publish only for that one-time bootstrap, then
configure trusted publishing and use the workflow for all subsequent versions.
