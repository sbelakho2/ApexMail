# outbound-queue

Outbound email queue — delivery scheduling, retry logic, priority routing.

## Overview

The `outbound-queue` crate manages the outbound email delivery pipeline for ApexMail. It schedules messages for dispatch, implements exponential-backoff retry logic for transient failures, and applies priority-based routing rules to ensure time-sensitive messages are delivered first.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
outbound-queue = { path = "../outbound-queue" }
```

## Development

```sh
cargo test -p outbound-queue
cargo clippy -p outbound-queue
```
