# sales-autopilot

Sales automation — lead scoring, outreach campaigns, CRM integration.

## Overview

The `sales-autopilot` crate powers ApexMail's sales automation features. It scores inbound leads based on engagement signals, orchestrates multi-step outreach campaigns, and integrates with external CRM systems to keep pipeline data synchronized and actionable for sales teams.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
sales-autopilot = { path = "../sales-autopilot" }
```

## Development

```sh
cargo test -p sales-autopilot
cargo clippy -p sales-autopilot
```
