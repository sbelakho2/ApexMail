# ato-protection

Account Takeover Protection — behavioral biometrics, impossible travel detection, session fingerprinting, and adaptive MFA.

## Overview

The `ato-protection` crate defends ApexMail accounts against takeover attacks. It analyzes behavioral biometrics, detects impossible-travel anomalies, fingerprints sessions for consistency, and triggers adaptive multi-factor authentication when risk scores exceed configurable thresholds.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ato-protection = { path = "../ato-protection" }
```

## Development

```sh
cargo test -p ato-protection
cargo clippy -p ato-protection
```
