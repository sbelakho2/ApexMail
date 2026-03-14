# smtp-edge

SMTP edge server — inbound connection handling, TLS termination, rate limiting.

## Overview

The `smtp-edge` crate implements the outermost SMTP entry point for ApexMail. It accepts inbound connections, terminates TLS, applies per-IP and per-sender rate limits, and forwards authenticated sessions to the MTA for further processing. It acts as the first line of defense against abuse and overload.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
smtp-edge = { path = "../smtp-edge" }
```

## Development

```sh
cargo test -p smtp-edge
cargo clippy -p smtp-edge
```
