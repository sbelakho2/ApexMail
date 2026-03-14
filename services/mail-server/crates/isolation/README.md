# isolation

Tenant isolation — namespace separation, resource limits, data partitioning.

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
