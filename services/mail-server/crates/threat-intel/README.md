# threat-intel

Threat intelligence feed ingestion, IP/domain blocklist management, and reputation scoring.

## Overview

The `threat-intel` crate aggregates external threat intelligence feeds for ApexMail. It ingests IP and domain blocklists, maintains a reputation-scoring database, and provides lookup APIs that the spam filter, WAF, and IDS engine use to block or flag traffic from known-malicious sources.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
threat-intel = { path = "../threat-intel" }
```

## Development

```sh
cargo test -p threat-intel
cargo clippy -p threat-intel
```
