# ha

High Availability service — health checks, failover, backup, replication.

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
