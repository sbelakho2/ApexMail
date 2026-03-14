# pdf-renderer

ApexMail PDF Renderer — Typst-powered document generation.

## Overview

The `pdf-renderer` crate generates PDF documents for ApexMail using the Typst typesetting engine. It produces invoices, data processing agreements (DPAs), compliance reports, and other formatted documents on demand, providing a fast and reliable rendering pipeline for business-critical output.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
pdf-renderer = { path = "../pdf-renderer" }
```

## Development

```sh
cargo test -p pdf-renderer
cargo clippy -p pdf-renderer
```
