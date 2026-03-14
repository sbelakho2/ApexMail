# analytics

ApexMail analytics — query engine, compaction, STO, churn, subject analysis, bot detection, etc.

## Overview

The `analytics` crate provides the analytics backbone for ApexMail, including a query engine for engagement data, compaction routines, send-time optimization, churn prediction, subject-line analysis, and bot-detection heuristics. It processes event streams and produces actionable metrics for dashboards and AI-driven features.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
analytics = { path = "../analytics" }
```

## Development

```sh
cargo test -p analytics
cargo clippy -p analytics
```
