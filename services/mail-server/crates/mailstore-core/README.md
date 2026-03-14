# mailstore-core

Mailstore Core.

## Overview

The `mailstore-core` crate implements the core email storage engine for ApexMail. It handles message persistence, indexing, retrieval, and lifecycle management, providing a reliable and efficient backend for mailbox operations across all tenants.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
mailstore-core = { path = "../mailstore-core" }
```

## Development

```sh
cargo test -p mailstore-core
cargo clippy -p mailstore-core
```
