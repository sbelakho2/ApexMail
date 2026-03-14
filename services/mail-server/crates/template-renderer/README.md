# template-renderer

React-like email template rendering with sandboxed execution.

## Overview

The `template-renderer` crate provides a React-like component model for building and rendering email templates in ApexMail. It executes user-defined templates in a sandboxed environment to prevent code injection, producing standards-compliant HTML email output suitable for delivery across all major mail clients.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
template-renderer = { path = "../template-renderer" }
```

## Development

```sh
cargo test -p template-renderer
cargo clippy -p template-renderer
```
