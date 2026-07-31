# Legacy Kubernetes Deployment — SUPERSEDED

> **⚠️ This deployment model is NOT canonical. It is preserved for historical
> reference only.**

## Canonical path

ApexMail is deployed via **Docker Compose + GHCR images over SSH (Hetzner)**.
See [`../DEPLOYMENT.md`](../DEPLOYMENT.md) for the single supported deploy flow.

## Why this was archived

Three mutually-exclusive deploy models coexisted in this repository:

1. Docker Compose + GHCR (the Hetzner SSH path), and
2. Bare-metal systemd (`deploy.sh`), and
3. Kubernetes (the manifests in this directory).

All three claimed to be "the" deployment path, but they defined different
service names, resource shapes, and secrets plumbing — so a deploy would
silently pick up the wrong one. The "clashing paths" production failures were
caused by this ambiguity. The decision (see `docs/adr/`) is to unify on the
compose/GHCR model for the foreseeable future.

## Contents

- `k8s/` — raw Kubernetes manifests.
- `kustomize/` — Kustomize overlays.
- `helm/` — Helm chart.

## If you ever need to revive Kubernetes

These manifests reference the **canonical GHCR image names** (`api-server`,
`mta`, `worker`, `enterprise`, `tracking-service`, `observability`,
`marketing`) under the `ghcr.io/<namespace>/apexmail/` path, so they remain
compatible with the images produced by `deploy.yml`. If you re-enable this
path, validate it against the canonical image-name list documented in
[`../DEPLOYMENT.md`](../DEPLOYMENT.md) and add a drift guard before relying on
it.
