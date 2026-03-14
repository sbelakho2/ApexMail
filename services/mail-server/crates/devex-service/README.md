# devex-service

ApexMail Developer Experience service — API versioning, SDK management, webhook testing, OpenAPI docs, onboarding.

## Overview

The `devex-service` crate powers the developer experience layer of ApexMail. It manages API versioning and deprecation, SDK release coordination, interactive webhook testing tools, auto-generated OpenAPI documentation, and guided onboarding flows to help integrators adopt the platform quickly.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
devex-service = { path = "../devex-service" }
```

## Development

```sh
cargo test -p devex-service
cargo clippy -p devex-service
```
