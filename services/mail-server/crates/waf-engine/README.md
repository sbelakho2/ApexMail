# waf-engine

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT WIRED INTO PRODUCTION: no service in this workspace (api-server, mta, worker, …) depends on this crate. It is a library and test target only — it inspects zero live traffic. Do not represent it as an active control.

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
