# submission

Message submission service — RFC 5321 SMTP submission with authentication.

## Overview

The `submission` crate implements the RFC 5321-compliant message submission endpoint for ApexMail. It handles authenticated SMTP submission from mail clients, validates sender identity, applies outbound policies, and enqueues accepted messages into the delivery pipeline.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
submission = { path = "../submission" }
```

## Development

```sh
cargo test -p submission
cargo clippy -p submission
```
