# edge-cases

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT DEPLOYED: this crate's server binary is not in the deployment Dockerfile or compose files. Compile/test target only.

ApexMail edge-cases — EAI validation, attachment scanning, calendar, delivery edge cases.

## Overview

The `edge-cases` crate handles non-standard and boundary scenarios in ApexMail's email processing pipeline. It covers Email Address Internationalization (EAI) validation, complex attachment scanning, calendar invitation handling, and unusual delivery situations that require special-case logic.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
edge-cases = { path = "../edge-cases" }
```

## Development

```sh
cargo test -p edge-cases
cargo clippy -p edge-cases
```
