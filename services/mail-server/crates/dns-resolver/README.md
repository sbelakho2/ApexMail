# dns-resolver

Reusable DNS resolver with caching, MX/SPF/DKIM/DMARC lookups.

## Overview

The `dns-resolver` crate provides a shared, high-performance DNS resolution layer for ApexMail. It caches query results, performs MX, SPF, DKIM, and DMARC lookups, and is used by the MTA, spam filter, and authentication modules to validate sender domains and route outbound mail.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
dns-resolver = { path = "../dns-resolver" }
```

## Development

```sh
cargo test -p dns-resolver
cargo clippy -p dns-resolver
```
