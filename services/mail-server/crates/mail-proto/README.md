# mail-proto

Mail Protocol Definitions.

## Overview

The `mail-proto` crate defines the wire-level protocol types and parsing logic for email standards used in ApexMail. It provides structured representations of SMTP commands, MIME parts, and RFC-compliant message headers that other crates consume for mail processing and validation.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
mail-proto = { path = "../mail-proto" }
```

## Development

```sh
cargo test -p mail-proto
cargo clippy -p mail-proto
```
