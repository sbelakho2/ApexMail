# @apexmail/validator-native

Native Node.js addon for email address validation, built with [napi-rs](https://napi.rs).

## Overview

Validates email addresses per RFC 5321/6531 (EAI / internationalized), resolves MX records via trust-dns, and detects disposable domains (50+ pre-loaded, extensible at runtime via environment).

## Usage

```js
import { validateEmail, validateEmailWithMx } from '@apexmail/validator-native';

const result = validateEmail('user@example.com');
// { valid: true, localPart: 'user', domain: 'example.com', isEai: false, isDisposable: false }

const mx = await validateEmailWithMx('user@example.com');
// includes MX record check
```

## API

| Function | Description |
|---|---|
| `validateEmail(email)` | Synchronous RFC validation |
| `validateEmailWithMx(email)` | Async validation with MX record check |
| `validateEmailsBatch(emails)` | Async batch validation |
| `checkMx(domain)` | MX record lookup (`hasMx`, `mxRecords`, `hasAFallback`) |
| `isDisposableDomain(domain)` | Check against disposable domain list |
| `getDisposableDomains()` | Return all loaded disposable domains |
| `setDisposableDomains(domains, replace)` | Add or replace disposable domains |
| `normalizeEmail(email)` | Lowercase domain, trim whitespace |
| `initializeDnsResolver()` | One-time DNS resolver warmup (call at startup) |

## Build

Requires Rust toolchain.

```sh
pnpm install
```

## Internal

This is an internal package — not published to npm.
