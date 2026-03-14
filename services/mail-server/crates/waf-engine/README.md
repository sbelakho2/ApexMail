# waf-engine

Pure-Rust Web Application Firewall: AST-based SQLi/XSS prevention, OWASP CRS-compatible rule engine, zero-copy payload inspection.

## Overview

The `waf-engine` crate provides a pure-Rust web application firewall for ApexMail's HTTP endpoints. It uses AST-based analysis to detect SQL injection and XSS payloads, supports OWASP Core Rule Set-compatible rules, and performs zero-copy payload inspection for minimal performance overhead at the edge.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
waf-engine = { path = "../waf-engine" }
```

## Development

```sh
cargo test -p waf-engine
cargo clippy -p waf-engine
```
