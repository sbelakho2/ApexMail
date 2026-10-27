# Contributing to ApexMail

This root guide is the fast entry point for contributors working in the monorepo.
The full contributor handbook lives in `docs/development/contributing.md`.

## Quick Start

```bash
cp .env.example .env
docker compose up -d postgres redis
cargo test --manifest-path services/mail-server/Cargo.toml
```

If you touch the marketing site, regenerate it with:

```bash
zola --root apps/marketing-zola build
```

## Before Opening a Pull Request

1. Run the focused tests for the code you changed.
2. Run `bash tools/check-forbidden-patterns.sh` before pushing.
3. Update docs and changelog entries when behavior or public contracts change.
4. Keep generated files in sync with their sources when the source of truth changes.

## Test-Scope Rule (REQUIRED)

**Never run tests on cold code or code your change does not affect.**

- Scope test runs to the crates you touched: `cargo nextest run -p <crate>` —
  never a bare `cargo nextest run --workspace` as a routine gate. A full
  workspace pass compiles and links every binary from cold and burns tens of
  minutes of the host for results the diff cannot change; it is reserved for
  explicit release-verification requests, never a habit.
- Within a touched crate, filter to the affected families first
  (`-E 'test(<family>)'`) and widen only when a failure surprises you.
- Tests that need `TEST_DATABASE_URL` / `TEST_REDIS_URL` must not be
  provisioned for changes that cannot reach the database; unit-scoped checks
  run without infra.
- The CI pipeline already scopes its lanes; this rule governs local and
  agent-driven runs, where an unscoped full-suite invocation on cold code is
  the expensive accident waiting to happen.

## Working Agreements

- Prefer small, reviewable pull requests.
- Keep public API, SDK, and deployment changes documented.
- Do not commit secrets or environment-specific local overrides.
- Avoid floating container image tags; the self-hosted pipeline (`ci/pipeline.sh`) records a SHA256 digest manifest for every built image — never pin services to external `vX.Y.Z` tags.

## Detailed Guidance

See the full handbook for workflow details, ADR expectations, testing guidance, and review policy:

- `docs/development/contributing.md`
