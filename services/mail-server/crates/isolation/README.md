# isolation

Tenant isolation — namespace separation, resource limits, data partitioning.

> **STATUS — DEPLOYED (docker target `isolation`, compose service `isolation`)**
> The `isolation-server` binary runs as a first-class compose service in the dev
> and production topologies (docs/development/topology-manifest.json), bound to
> `0.0.0.0:$ISOLATION_PORT` (default 4500) with `GET /health` as the
> unauthenticated liveness probe used by the Dockerfile and compose healthchecks.
> Production REQUIRES `TENANT_ENCRYPTION_KEY` and `ISOLATION_INTERNAL_API_KEY`
> (the binary exits 78 without them; both are mounted as Docker secrets by the
> prod compose overlay). The `iso_*` tables live in the main application
> database (canonical migration chain). Honest scope: the isolation SERVICE is
> deployed; the always-on application-layer tenant separation that protects
> customer data remains the api-server's query-level tenancy and does not depend
> on this service. Declared gap: no scrapeable `/metrics` endpoint yet, so no
> Prometheus alert exists (see the topology manifest notes).

## Overview

The `isolation` crate enforces strict multi-tenant isolation within ApexMail. It manages namespace separation, per-tenant resource limits, and data partitioning to ensure that one tenant's workload, data, and configuration cannot affect or be accessed by another.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
isolation = { path = "../isolation" }
```

## Development

```sh
cargo test -p isolation
cargo clippy -p isolation
```
