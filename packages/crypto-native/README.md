# @apexmail/crypto-native

Native Node.js addon providing core cryptographic primitives, built with [napi-rs](https://napi.rs).

## Overview

All heavy cryptographic operations run off the JS event loop in Rust. Key material is automatically zeroized on drop.

## API

| Function | Description |
|---|---|
| `encryptAes128Gcm` / `decryptAes128Gcm` | AES-128-GCM authenticated encryption |
| `encryptAes256Gcm` / `decryptAes256Gcm` | AES-256-GCM authenticated encryption |
| `deriveKeyHkdf(masterKey, info)` | HKDF-SHA-256 key derivation (32-byte output) |
| `hmacSha256(key, data)` | HMAC-SHA-256 |
| `hashPassword(password)` | Argon2id password hashing (async) |
| `verifyPassword(hash, password)` | Argon2id password verification (async) |
| `generateDkimKeyPair(bits)` | RSA DKIM key-pair generation (`{ privateKey, publicKey }` DER) |
| `timingSafeEqual(a, b)` | Constant-time buffer comparison |
| `secureRandomBytes(length)` | OS RNG random bytes (max 1 MiB) |
| `bufToHex` / `hexToBuf` | Buffer ↔ hex encoding |
| `bufToBase64` / `base64ToBuf` | Buffer ↔ base64 encoding |

## Build

Requires Rust toolchain.

```sh
pnpm install
```

## Internal

This is an internal package — not published to npm.
