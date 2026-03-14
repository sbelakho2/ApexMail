# tracking-service

ApexMail high-performance email tracking service (open pixel, click, unsubscribe).

## Overview

The `tracking-service` crate implements ApexMail's high-performance email engagement tracking. It serves open-tracking pixels, processes click-through redirects, and handles one-click unsubscribe requests, recording all events into the analytics pipeline with minimal latency overhead.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
tracking-service = { path = "../tracking-service" }
```

## Development

```sh
cargo test -p tracking-service
cargo clippy -p tracking-service
```
