# ui-foundation

Server-side UI rendering — design system primitives, HTML generation.

## Overview

The `ui-foundation` crate provides server-side UI rendering capabilities for ApexMail. It implements design-system primitives, reusable component abstractions, and HTML generation utilities used to produce consistent, branded pages such as unsubscribe confirmations, preference centers, and status pages.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ui-foundation = { path = "../ui-foundation" }
```

## Development

```sh
cargo test -p ui-foundation
cargo clippy -p ui-foundation
```
