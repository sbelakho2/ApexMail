# ha

High Availability service — health checks, failover, backup, replication.

> **STATUS — DEPLOYED (docker target `ha`, compose service `ha`)**
> The `ha-server` binary runs as a first-class compose service in the dev and
> production topologies (docs/development/topology-manifest.json), bound to
> `0.0.0.0:$HA_PORT` (default 4300) with `GET /health` as the unauthenticated
> liveness probe used by the Dockerfile and compose healthchecks. Startup is
> loud-fail: it aborts unless the HA tables exist (migration 194
> `ha_health_checks`), so the migrator must run first. Failback defaults to
> MANUAL (`FAILBACK_ENABLED=false`, G.8); chaos engineering stays off
> (`CHAOS_ENABLED=false`). Honest scope: single-host health-checked services
> with automatic restart — multi-region active-active is NOT live. Declared
> gap: no scrapeable `/metrics` endpoint yet, so no Prometheus alert exists
> (see the topology manifest notes).

## Overview

The `ha` crate implements high-availability infrastructure for ApexMail. It provides health-check endpoints, automated failover orchestration, scheduled backup routines, and data replication logic to ensure the mail-server remains operational and consistent during node failures or maintenance windows.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ha = { path = "../ha" }
```

## Development

```sh
cargo test -p ha
cargo clippy -p ha
```
