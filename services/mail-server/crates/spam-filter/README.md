# spam-filter

> **STATUS — WIRED INTO THE MTA INBOUND PATH**
> Since the content-security integration (`crates/mta/src/servers/content_security.rs`,
> gated by `MTA_SPAM_FILTER_ENABLED`), every inbound DATA payload is scored by
> `SpamEngine` and the verdict is stored on the message as `X-Spam-Score` /
> `X-Spam-Verdict` headers. DATA-time refusal for REJECT-classified mail is a
> separate, default-off operator opt-in (`MTA_SPAM_REJECT_ENABLED`). The
> worker-processors/outbound-mta path does NOT re-score; only the inbound
> flow is wired.

Multi-layer spam & phishing detection: Bayesian classifier, URL reputation, header analysis, content scoring.

## Overview

The `spam-filter` crate provides ApexMail's multi-layer spam and phishing detection pipeline. It combines a Bayesian classifier, URL reputation checks, header anomaly analysis, and content-based scoring to assign threat levels to incoming messages and protect recipients from unwanted or dangerous email.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
spam-filter = { path = "../spam-filter" }
```

## Development

```sh
cargo test -p spam-filter
cargo clippy -p spam-filter
```
