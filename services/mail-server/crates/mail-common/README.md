# mail-common

Mail Common — shared types, configuration, and utilities.

## Overview

The `mail-common` crate contains shared types, configuration structures, and utility functions used across the ApexMail mail-server workspace. It provides the foundational data models and helpers that other mail-processing crates depend on to maintain consistency and reduce duplication.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
mail-common = { path = "../mail-common" }
```

## Development

```sh
cargo test -p mail-common
cargo clippy -p mail-common
```
