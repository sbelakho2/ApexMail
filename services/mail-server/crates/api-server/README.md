# api-server

ApexMail REST API server — routes, middleware, authentication.

## Overview

The `api-server` crate implements the primary REST API for ApexMail. It defines HTTP routes, request/response middleware, authentication and authorization logic, and serves as the main entry point for external clients and the web dashboard to interact with the mail-server backend.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
api-server = { path = "../api-server" }
```

## Development

```sh
cargo test -p api-server
cargo clippy -p api-server
```
