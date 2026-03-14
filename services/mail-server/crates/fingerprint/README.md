# fingerprint

TLS and HTTP/2 fingerprinting for bot detection.

## Overview

The `fingerprint` crate extracts TLS (JA3/JA4) and HTTP/2 fingerprints from incoming connections to identify automated clients and bots. It feeds fingerprint signals into ApexMail's bot-detection and anti-abuse pipeline, helping distinguish legitimate mail clients from scrapers and credential-stuffing tools.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
fingerprint = { path = "../fingerprint" }
```

## Development

```sh
cargo test -p fingerprint
cargo clippy -p fingerprint
```
