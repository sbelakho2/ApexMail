# Legacy Evaluation Specs — Aspirational / Unimplemented

> **These documents describe deployment & rollout mechanisms that were never
> implemented. They are preserved as historical/aspirational specs only.**

## What lives here

- `staging-environment.md` — a spec for a separate staging environment
  (dedicated Hetzner host, `*.staging.apexmail.dev` DNS, a separate
  `docker-compose.staging.yml`). **Never built.** ApexMail has no staging
  environment today; pre-production validation happens via the CI workflows in
  `.github/workflows/` and the repo-local compose smoke
  (`./tools/run-compose-smoke.sh`).
- `canary-deployment.md` — a spec for percentage-based canary rollouts with
  traffic splitting at the reverse proxy. **Never implemented.** Production
  rollouts are all-or-nothing `docker compose pull` + `up -d` of `:latest`
  images (see [`../DEPLOYMENT.md`](../DEPLOYMENT.md)).

## Canonical deployment reference

The **single source of truth** for how ApexMail deploys is
[`../DEPLOYMENT.md`](../DEPLOYMENT.md): Docker Compose + GHCR images via
GitHub Actions to the Hetzner host. Do not treat anything in this directory as
a description of how the platform actually deploys today.

Rollback, when needed, follows [`../rollback-plan.md`](../rollback-plan.md)
(git-SHA based), not the staged promotion model described in
`canary-deployment.md`.
