# ai-service

ApexMail AI Intelligence Suite — analytics, assistant, bandits, content, inference, STO, training.

## Overview

The `ai-service` crate is the central AI intelligence layer for ApexMail. It integrates analytics-driven insights, a conversational assistant, multi-armed bandit optimization, content generation, model inference, send-time optimization (STO), and training pipelines into a unified service.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
ai-service = { path = "../ai-service" }
```

## Development

```sh
cargo test -p ai-service
cargo clippy -p ai-service
```
