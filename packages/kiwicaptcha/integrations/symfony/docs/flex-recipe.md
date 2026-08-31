# Flex recipe (PR-ready package)

## Current status

A pull request carrying this env-form recipe is open in
`symfony/recipes-contrib` (PR #2038). Its merge is blocked on Packagist
publication of `bel-consulting/kiwicaptcha-symfony`: the recipes-contrib
validation installs a published package, so the recipe can only land
after the bundle exists on Packagist. Publication on Packagist is an
external maintainer action (packagist.org, outside this repository); the
PR is not silently claimed done — until both land, the manual equivalent
below applies.

This repository carries the Symfony Flex recipe for
`bel-consulting/kiwicaptcha-symfony` in the exact
`symfony/recipes-contrib` layout under
`recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0/`. A published
recipe lets a plain `composer require bel-consulting/kiwicaptcha-symfony`
register the bundle, install the routes, drop in a starter configuration
(protection profile, env-managed secret, origin and Redis DSN), and
add the environment placeholders. The package is **PR-ready**: a
maintainer copies the version directory into a fork of
`symfony/recipes-contrib` and opens the pull request (the steps below).
The recipe is not published yet, so until the merge the manual
equivalent applies.

The recipe package is validated by
`packages/kiwicaptcha/integrations/symfony/tests/RecipePackageValidationTest.php`.
The manifest is checked for coherence with the config placeholders. The
recipe config is processed through the bundle's `Configuration` with the
`%env()` placeholders resolved to test values, and a kernel booted with
the recipe's exact config values passes `kiwicaptcha:doctor` and serves
a full challenge round trip. The new-integrator experience is covered
end to end by `tests/NewIntegratorSmokeTest.php`.

## What the package contains

| Path | Purpose |
|------|---------|
| `manifest.json` | The recipe manifest: the bundle registration (`bundles`), the files copied into the app (`copy-from-recipe`) and the environment placeholders (`env`): the generated `KIWI_SECRET_KEY` plus the `KIWI_REDIS_DSN` and `KIWI_PUBLIC_URL` defaults Flex writes into `.env`. |
| `config/packages/kiwicaptcha.yaml` | Starter configuration: `protection_profile: balanced`, the `%env()` secret, origin and DSN placeholders (twelve-factor: credentials and endpoints live in the environment), and the commented advanced service-id escape hatches. The bundle validates the resolved DSN (redis:// or rediss:// with a host, fail-closed) when the client is constructed; a literal override in the config file is still possible. |
| `config/routes/kiwicaptcha.yaml` | Explicit import of the bundle's routes (the extension also auto-prepends them on apps that never configured `framework.router` themselves). |
| `.env` | The `KIWI_SECRET_KEY` placeholder and the `KIWI_REDIS_DSN` / `KIWI_PUBLIC_URL` localhost defaults as a reference for manual setups (the recipe itself declares them in `manifest.json` under `env`). |
| `tests/Fixtures/composer.json` | The minimal fixture application the recipes-contrib validation installs the recipe into (framework-bundle + Flex + the package + predis), proving the recipe applies to a fresh app. |

## Publishing to symfony/recipes-contrib (maintainer action)

Publishing is a maintainer action — an unreviewed bot pull request to
the symfony organization is not appropriate, so this repository never
opens that PR itself. The steps:

1. Fork `https://github.com/symfony/recipes-contrib` and create a
   branch.
2. Copy the version directory
   `recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0/` from this
   repository (the whole directory: `manifest.json`, `config/`, `.env`,
   `tests/Fixtures/`) into the fork at the same path. The manifest is
   complete: bundle registration for every environment,
   `copy-from-recipe` for `config/`, and the three environment
   placeholders (`KIWI_SECRET_KEY` generated, `KIWI_REDIS_DSN` and
   `KIWI_PUBLIC_URL` with localhost defaults the integrator replaces).
3. Open the pull request with a title like
   `[bel-consulting/kiwicaptcha-symfony] Add recipe for v1.0`. The
   recipes-contrib CI (Symfony Bot) validates the manifest and installs
   the recipe into the fixture app; the `tests/Fixtures/composer.json`
   is the skeleton that install proves.
4. Mention in the PR description that the package is
   `type: symfony-bundle` with the PSR-4 namespace
   `BelConsulting\KiwiCaptchaBundle\`, and that `predis/predis` is a
   direct dependency of the package (the `redis_dsn` starter config
   works out of the box).
5. Keep the version directory in sync with package releases: a new
   recipe version is only needed when the files or the env keys change.

Recipes are reviewed by the Symfony maintainers. Until publication, the
recipe's effect is the same as the manual steps below.

## Bundle auto-registration

The bundle does not need a composer `extra` key for registration. Flex
generates an "auto-generated recipe" for bundles without a published
recipe: it scans the package's PSR-4 namespaces and registers the class
`BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle` (a file named
`KiwiCaptchaBundle.php` in `src/` extending
`Symfony\Component\HttpKernel\Bundle\Bundle`). The published recipe
declares the same registration explicitly in `manifest.json`, which is
the canonical route once the recipe exists.

## Verified install flow

The smoke suite proves this exact sequence on a fresh kernel. Boot the
container with only `protection_profile`, `secret_key`,
`public_base_url` and `redis_dsn`. Run `kiwicaptcha:doctor` and expect
exit 0 with `[PASS] Redis reachability` and `[PASS] Storage atomicity`.
Issue a challenge over HTTP, solve it, and verify it through the
DSN-built services. Serve the widget include from `Resources/public`.
The `high_abuse` profile boots on the same DSN with the risk state
store, and an explicit `storage` service id still wins over the
DSN-built storage.

What the recipe automates:

- `composer require` registers the bundle in `config/bundles.php`
  (explicitly via the recipe once published, via the auto-generated
  recipe until then).
- The recipe copies `config/packages/kiwicaptcha.yaml` and
  `config/routes/kiwicaptcha.yaml` into the app.
- The manifest writes `KIWI_SECRET_KEY` (a generated random value),
  `KIWI_REDIS_DSN` and `KIWI_PUBLIC_URL` (localhost defaults) into
  `.env`.

What remains manual:

- Replace the generated secret with a fresh one if the generated value
  is unsuitable, and point the `KIWI_REDIS_DSN` / `KIWI_PUBLIC_URL`
  environment values at the deployment's real Redis endpoint and
  canonical origin. Credentials and endpoints stay out of source
  control; a literal override in the config file is still possible.
- Predis is a direct dependency of the bundle; the DSN path needs no
  separate install.
- Import the recipe routes manually if the app configures
  `framework.router` itself (the recipe copies the import file; the
  extension also auto-prepends the routes on a fresh app).
- Include the widget on a form or in a template; see
  [getting-started.md](getting-started.md).
- Run `bin/console kiwicaptcha:doctor`; a failed check must be resolved
  before going live.

## Manual equivalent

Without the recipe, the steps are the same as
[docs/getting-started.md](getting-started.md):

1. `composer require bel-consulting/kiwicaptcha-symfony`
   (adds the bundle and its direct Predis dependency; Flex registers
   it via the auto-generated recipe).
2. Add `KIWI_SECRET_KEY` to your `.env` and set a real random value
   (`openssl rand -hex 32`), then add `KIWI_REDIS_DSN` (your Redis
   connection) and `KIWI_PUBLIC_URL` (your canonical https origin).
3. Copy `config/packages/kiwicaptcha.yaml` into your app, or write the
   configuration by hand. Choose a `protection_profile`, point
   `secret_key` at `%env(KIWI_SECRET_KEY)%`, `public_base_url` at
   `%env(KIWI_PUBLIC_URL)%` and `redis_dsn` at `%env(KIWI_REDIS_DSN)%`
   — or use literals: a literal `redis://` or `rediss://` URL is
   validated at container build time, and a literal origin must be a
   clean https URL. The bundle then builds the Redis-backed services
   itself, and an explicit `storage` / `redis_service` /
   `risk.redis_service` service id wins over the DSN for its knob.
4. Import the routes (`config/routes/kiwicaptcha.yaml`) if your app
   configures `framework.router` itself.
5. Include the widget on a form or in a template
   (see getting-started).
6. Run `bin/console kiwicaptcha:doctor` and resolve every failed check before
   going live.
