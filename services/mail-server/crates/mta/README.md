# mta

ApexMail MTA — inbound SMTP, bounce processing, feedback loops, and email authentication.

## Overview

The `mta` crate is the Mail Transfer Agent at the heart of ApexMail. It handles inbound SMTP reception, bounce classification and processing, feedback-loop (FBL) ingestion, and email authentication via SPF, DKIM, and DMARC. It orchestrates message flow from acceptance through to delivery or rejection.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
mta = { path = "../mta" }
```

## Development

```sh
cargo test -p mta
cargo clippy -p mta
```
