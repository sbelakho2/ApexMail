# ops-service

ApexMail operations service — health checks, incidents, SLO monitoring, status pages, IP warmup, and trust scoring.

## Overview

The `ops-service` crate centralizes operational concerns for ApexMail. It runs health checks, manages incident workflows, monitors SLO compliance, publishes status pages, orchestrates IP warmup schedules for new sending IPs, and maintains sender trust scores to optimize deliverability.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ops-service = { path = "../ops-service" }
```

## Development

```sh
cargo test -p ops-service
cargo clippy -p ops-service
```
