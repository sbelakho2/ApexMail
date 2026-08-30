# spam-filter

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT WIRED INTO PRODUCTION: no delivery path (mta, worker-processors) depends on this crate. It is a library and test target only. Do not represent it as an active control.

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
