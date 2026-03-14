# observability-service

ApexMail observability service — Prometheus metrics, distributed tracing, log aggregation, alerting, SLO monitoring, and health check dashboards.

## Overview

The `observability-service` crate provides full-stack observability for the ApexMail platform. It exports Prometheus metrics, correlates distributed traces across services, aggregates structured logs, evaluates alerting rules, monitors SLO budgets, and powers health-check dashboards to keep operators informed of system state.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
observability-service = { path = "../observability-service" }
```

## Development

```sh
cargo test -p observability-service
cargo clippy -p observability-service
```
