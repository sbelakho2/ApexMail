# dlp-engine

Data Loss Prevention engine — PII detection, sensitive data scanning, document watermarking, and outbound content policies.

## Overview

The `dlp-engine` crate prevents accidental or malicious data leakage from ApexMail. It detects personally identifiable information, scans attachments and message bodies for sensitive data patterns, applies document watermarks, and enforces outbound content policies before messages leave the system.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
dlp-engine = { path = "../dlp-engine" }
```

## Development

```sh
cargo test -p dlp-engine
cargo clippy -p dlp-engine
```
