# pattern-matcher

Reusable multi-pattern matching engine built on Aho-Corasick.

## Overview

The `pattern-matcher` crate provides a high-performance, reusable multi-pattern matching engine for ApexMail. Built on the Aho-Corasick algorithm, it efficiently scans message content against large rule sets and is used by the spam filter, bot detector, and content-policy modules for fast pattern detection.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
pattern-matcher = { path = "../pattern-matcher" }
```

## Development

```sh
cargo test -p pattern-matcher
cargo clippy -p pattern-matcher
```
