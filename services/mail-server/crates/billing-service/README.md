# billing-service

ApexMail billing service — usage metering, plan management, quota enforcement, invoices.

## Overview

The `billing-service` crate handles all monetization concerns for ApexMail. It meters per-tenant usage, manages subscription plans and upgrades, enforces quota limits, and generates invoices. It integrates with external payment providers and exposes billing data to the API and dashboard.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
billing-service = { path = "../billing-service" }
```

## Development

```sh
cargo test -p billing-service
cargo clippy -p billing-service
```
