# ddos-protection

Multi-layer DDoS protection for ApexMail.

## Overview

The `ddos-protection` crate provides multi-layer distributed denial-of-service mitigation for the ApexMail infrastructure. It implements connection-rate limiting, traffic anomaly detection, and automatic mitigation policies to keep SMTP and HTTP endpoints available under volumetric and application-layer attacks.

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
