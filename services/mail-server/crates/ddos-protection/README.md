# ddos-protection

Multi-layer DDoS protection for ApexMail.

## Overview

The `ddos-protection` crate provides multi-layer denial-of-service mitigation for the ApexMail HTTP surface. It implements connection-rate limiting, traffic anomaly detection, and automatic mitigation policies; `api-server` constructs the `DdosProtector` and evaluates every request through it.

**Scope honesty — SMTP:** the SMTP-side module (`smtp_protection`) is NOT wired into any listener. The only SMTP servers in this repository are in the `mta` crate, which does not depend on this crate; the MTA enforces SMTP admission, idle/DATA timeouts and the session error cap itself (see `mta/src/servers/inbound.rs`). See the module docs for the consolidation plan before adopting it.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ddos-protection = { path = "../ddos-protection" }
```

## Development

```sh
cargo test -p ddos-protection
cargo clippy -p ddos-protection
```
