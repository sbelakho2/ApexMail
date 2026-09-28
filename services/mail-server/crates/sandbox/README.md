# sandbox

Secure attachment detonation sandbox using Linux namespaces, cgroups v2, and seccomp-bpf.

> **STATUS — STATIC ANALYSIS WIRED INTO THE MTA INBOUND PATH**
> Since the content-security integration (`crates/mta/src/servers/content_security.rs`,
> gated by `MTA_ATTACHMENT_SCAN_ENABLED`), every MIME attachment on the inbound
> DATA path is inspected by `SandboxEngine::analyze` (magic-byte typing,
> polyglot detection, macro/ActiveX indicators, encrypted archives, blocked
> extensions) and the verdict is stored as `X-Apex-Attachment-Scan` headers.
> Strip / reject actions are config gated (`MTA_ATTACHMENT_SCAN_MODE`,
> default `flag`). OS-level detonation (namespaces/cgroups/seccomp behind the
> `linux-sandbox` feature) remains available to embedders but is not exercised
> by the mail flow — the mail path uses the static + content-inspection layer.

## Overview

The `sandbox` crate provides a secure execution environment for detonating suspicious email attachments in ApexMail. It leverages Linux namespaces for filesystem and network isolation, cgroups v2 for resource constraints, and seccomp-bpf syscall filtering to safely analyze potentially malicious files without risk to the host system.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
sandbox = { path = "../sandbox" }
```

## Development

```sh
cargo test -p sandbox
cargo clippy -p sandbox
```
