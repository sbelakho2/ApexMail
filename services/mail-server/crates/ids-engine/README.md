# ids-engine

> **STATUS — WIRED INTO THE MTA INBOUND PATH**
> Since the content-security integration (`crates/mta/src/servers/content_security.rs`,
> gated by `MTA_IDS_ENABLED`), this crate inspects real inbound mail: SMTP
> signatures and protocol anomalies on every DATA payload, and connection
> tracking at session admission. Refusal (`MTA_IDS_REFUSE`) is a separate,
> default-off, operator opt-in. See "Wiring status" below for exactly what is
> and is not wired.

Network-level Intrusion Detection/Prevention System: signature matching, anomaly detection, protocol analysis.

## Overview

The `ids-engine` crate provides a network-level intrusion detection and prevention system for ApexMail. It performs signature-based threat matching, statistical anomaly detection, and deep protocol analysis on SMTP and HTTP traffic to identify and block malicious activity before it reaches application logic.

## Wiring status

**Wired (mta inbound):**

* **DATA payload inspection** — every accepted-after-auth DATA payload is run
  through `IdsEngine::inspect(ip, port, "smtp", payload)` in
  `crates/mta/src/servers/content_security.rs::ids_inspect_payload`. SMTP
  signatures (shellcode NOP sleds, etc.) and the SMTP protocol-anomaly
  analyser (`analyze_smtp`: oversized lines, pipelining abuse, RCPT bursts,
  null bytes, bare CR/LF, DATA-terminator smuggling) both fire. Verdicts are
  recorded on the stored message as `X-Apex-Ids-Verdict`; a Drop/Reject
  verdict refuses the message (550 5.7.1) only under `MTA_IDS_REFUSE=true`.
  Engine panics are contained and fail OPEN (treated as Pass, logged).
* **Session/connection layer** — every admitted inbound session feeds a
  `ConnectionTracker` (`record_syn` at admission, `record_established` after
  the greeting, `record_close` at session end; periodic
  `cleanup_all` is spawned from `InboundServer::start`). SYN-flood /
  port-scan / connection-flood anomalies refuse admission with
  `421 4.7.0` only under `MTA_IDS_REFUSE=true`; otherwise they are logged.
* **Configuration** — `MTA_IDS_ENABLED` (default false),
  `MTA_IDS_REFUSE` (default false), parsed in
  `crates/mta/src/config.rs::MtaConfig::from_env` into
  `IdsIntegrationConfig`.

**Deliberately NOT wired (and where it would belong):**

* **HTTP signatures** (`/etc/passwd`, `.env`, Log4Shell, …) — no HTTP traffic
  reaches the mta. Wiring them requires the api-server/edge reverse-proxy
  path calling `inspect(ip, port, "http", payload)`; that integration is
  owned by the api-server workstream.
* **DNS protocol validation** (`analyze_dns`) — the mta answers no DNS; a
  dns-resolver/authoritative-service integration would call
  `inspect(ip, port, "dns", payload)`.
* **TLS protocol validation** (`analyze_tls`) — would require feeding the
  handshake bytes (pre-encryption) from a TLS-terminating proxy; the mta's
  rustls stack does not expose them.
* **Inline network-mode (raw SYN/A-C packet capture)** — the engine is
  fed per-connection/per-message events by the mta, not tapped off the wire;
  a true network tap deployment remains future work.
* **AUTH brute-force detection** — handled natively by the mta's
  `AuthFailTracker` (per-IP/per-account lockout), not by this engine; the
  engine's connection tracker complements it at the connection layer.

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
