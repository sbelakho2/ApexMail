# threat-intel

Threat intelligence feed ingestion, IP/domain blocklist management, and reputation scoring.

## Overview

The `threat-intel` crate aggregates external threat intelligence feeds for ApexMail. It ingests IP and domain blocklists, maintains a reputation-scoring database, and provides lookup APIs that the spam filter, WAF, and IDS engine use to block or flag traffic from known-malicious sources.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
threat-intel = { path = "../threat-intel" }
```


## Configuration

The api-server owns the production feed wiring
(`crates/api-server/src/threat_feeds.rs`):

- `THREAT_INTEL_FEED_URLS` — comma-separated feed URLs (plain domain-per-line
  or URL-per-line exports). Empty disables ingestion.
- `THREAT_INTEL_FEED_TTL_SECS` — entry lifetime (default 86400).
- `THREAT_INTEL_FEED_REFRESH_SECS` — refresh cadence (default 3600; the first
  refresh fires at startup).

Entries load into the SAME `DomainBlocklist` the grader uses, so a feed hit is
a reputation finding on the next request; expired entries are purged every
60 seconds. The STIX/TAXII transports remain unimplemented.

## Development

```sh
cargo test -p threat-intel
cargo clippy -p threat-intel
```
