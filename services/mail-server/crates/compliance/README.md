# compliance

Compliance enforcement — GDPR, HIPAA, SOC 2, content scanning.

## Overview

The `compliance` crate enforces regulatory and policy compliance across ApexMail. It implements GDPR data-subject rights, HIPAA safeguards, SOC 2 audit controls, automated content scanning, and DSAR rate limiting to ensure that email processing and storage meet industry and legal requirements.

## DSAR Rate Limiting

The crate includes a dedicated DSAR (Data Subject Access Request) rate limiter at [`src/dsar_rate_limit.rs`](src/dsar_rate_limit.rs) implementing the following limits:

| Limit Type | Value | Scope |
|-----------|-------|-------|
| Per-user submission | 1/24h | Email address |
| Per-tenant submission | 100/24h | Tenant ID |
| Per-IP submission | 5/1h | IP address |
| Verification attempts | 5/token/1h | Token hash |

The rate limiter supports dual-mode operation: Redis-backed (primary) with in-memory `moka` cache fallback.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
compliance = { path = "../compliance" }
```

## Development

```sh
cargo test -p compliance
cargo clippy -p compliance
```
