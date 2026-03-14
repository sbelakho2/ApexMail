# apexmail-lib

ApexMail shared library — crypto, logging, caching, IDs, validation, HTTP client, error codes.

## Overview

The `apexmail-lib` crate is the foundational shared library for the ApexMail mail-server workspace. It provides common utilities including cryptographic helpers, structured logging, caching primitives, ID generation, input validation, an HTTP client wrapper, and standardized error codes used across all other crates.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
apexmail-lib = { path = "../apexmail-lib" }
```

## Development

```sh
cargo test -p apexmail-lib
cargo clippy -p apexmail-lib
```
