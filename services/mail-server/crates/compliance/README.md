# compliance

Compliance enforcement — GDPR, HIPAA, SOC 2, content scanning.

## Overview

The `compliance` crate enforces regulatory and policy compliance across ApexMail. It implements GDPR data-subject rights, HIPAA safeguards, SOC 2 audit controls, and automated content scanning to ensure that email processing and storage meet industry and legal requirements.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
compliance = { path = "../compliance" }
```

## Development

```sh
cargo test -p compliance
cargo clippy -p compliance
```
