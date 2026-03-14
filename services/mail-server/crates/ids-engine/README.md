# ids-engine

Network-level Intrusion Detection/Prevention System: signature matching, anomaly detection, protocol analysis.

## Overview

The `ids-engine` crate provides a network-level intrusion detection and prevention system for ApexMail. It performs signature-based threat matching, statistical anomaly detection, and deep protocol analysis on SMTP and HTTP traffic to identify and block malicious activity before it reaches application logic.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ids-engine = { path = "../ids-engine" }
```

## Development

```sh
cargo test -p ids-engine
cargo clippy -p ids-engine
```
