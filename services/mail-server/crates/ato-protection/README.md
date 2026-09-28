# ato-protection

> **STATUS — WIRED INTO THE API-SERVER LOGIN FLOWS**
> `crates/api-server` depends on this crate and evaluates every password login
> through `ato_protection::runtime::shared()` (`crates/api-server/src/routes/auth.rs`,
> `ato_evaluate_password_login`). Gate: `ATO_PROTECTION_ENABLED` — an explicit
> value always wins; unset, the runtime defaults ON for ENVIRONMENT=production /
> staging and OFF elsewhere (the production compose pins it `true`). Medium-risk
> logins step up to MFA (when enrolled), high-risk logins are refused; both write
> audit rows. The engine fails OPEN: a detector error allows the login with a
> loud log.

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
