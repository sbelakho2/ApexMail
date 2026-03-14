# queue-provider

Postgres-backed job queue with SKIP LOCKED and fair scheduling.

## Overview

The `queue-provider` crate implements a reliable, Postgres-backed job queue for ApexMail. It leverages `SELECT ... FOR UPDATE SKIP LOCKED` for contention-free dequeuing and applies fair-scheduling policies so that no single tenant monopolizes worker capacity.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
queue-provider = { path = "../queue-provider" }
```

## Development

```sh
cargo test -p queue-provider
cargo clippy -p queue-provider
```
