# apexmail-db

ApexMail database layer — connection pool, repositories, transactions.

## Overview

The `apexmail-db` crate provides the shared database layer used throughout the ApexMail mail-server. It manages connection pooling, exposes repository abstractions for each domain entity, and handles transaction management to ensure data consistency across services.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
apexmail-db = { path = "../apexmail-db" }
```

## Development

```sh
cargo test -p apexmail-db
cargo clippy -p apexmail-db
```
