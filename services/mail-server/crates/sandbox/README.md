# sandbox

Secure attachment detonation sandbox using Linux namespaces, cgroups v2, and seccomp-bpf.

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
