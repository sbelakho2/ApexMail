+++
title = "SDKs"
description = "Official client libraries for common server-side languages and teams that prefer typed integrations over raw HTTP."
template = "prose.html"
weight = 3
+++

## Official SDK Coverage

This repository includes ApexMail SDKs for the following languages:

- Go
- Java
- PHP
- Python
- Ruby

## When To Use an SDK

- You want typed request and response models for common message flows.
- You need retry handling, client configuration, and shared auth setup in one place.
- Your application already standardizes on one of the supported server-side runtimes.

## When Raw HTTP Is Better

- You are integrating from a platform without an official SDK.
- You only need a small subset of endpoints and prefer a thinner dependency surface.
- You are building infrastructure or gateway code that already owns HTTP request signing and retries.

## Getting Started

Use the [API Reference](/docs/api/) for the wire contract, then choose the SDK that matches your runtime and rollout path. The [API Console](/api-console/) is the fastest place to validate payload shape before you move into typed client code.