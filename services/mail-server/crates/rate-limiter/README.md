# rate-limiter

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT WIRED INTO PRODUCTION as a middleware: the api-server uses its own middleware (api-server/src/middleware/rate_limiter.rs). This crate is a library and test target only.

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
