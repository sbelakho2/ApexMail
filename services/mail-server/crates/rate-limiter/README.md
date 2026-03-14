# rate-limiter

Reusable rate-limiting primitives for ApexMail.

## Overview

The `rate-limiter` crate provides reusable rate-limiting strategies for the ApexMail platform. It includes a governor-based in-memory limiter, sliding-window counters, and token-bucket algorithms that can be applied to SMTP connections, API endpoints, and per-tenant sending quotas.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
rate-limiter = { path = "../rate-limiter" }
```

## Development

```sh
cargo test -p rate-limiter
cargo clippy -p rate-limiter
```
