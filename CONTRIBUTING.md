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
zola build --root apps/marketing-zola
```

## Before Opening a Pull Request

1. Run the focused tests for the code you changed.
2. Run `bash tools/check-forbidden-patterns.sh` before pushing.
3. Update docs and changelog entries when behavior or public contracts change.
4. Keep generated files in sync with their sources when the source of truth changes.

## Working Agreements

- Prefer small, reviewable pull requests.
- Keep public API, SDK, and deployment changes documented.
- Do not commit secrets or environment-specific local overrides.
- Avoid floating container image tags; the self-hosted pipeline (`ci/pipeline.sh`) records a SHA256 digest manifest for every built image — never pin services to external `vX.Y.Z` tags.

## Detailed Guidance

See the full handbook for workflow details, ADR expectations, testing guidance, and review policy:

- `docs/development/contributing.md`
