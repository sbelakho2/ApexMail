# ai-embeddings

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT DEPLOYED: this crate's server binary is not in the deployment Dockerfile or compose files, and no production service depends on it. Compile/test target only.

AI text embeddings, vector store, and similarity search.

## Overview

The `ai-embeddings` crate provides text embedding generation, vector storage, and similarity search capabilities for ApexMail. It powers semantic matching features such as content deduplication, smart reply suggestions, and related-message retrieval across the platform.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ai-embeddings = { path = "../ai-embeddings" }
```

## Development

```sh
cargo test -p ai-embeddings
cargo clippy -p ai-embeddings
```
