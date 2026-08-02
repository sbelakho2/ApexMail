# KiwiCaptcha

A native Rust, zero-dependency proof-of-work CAPTCHA engine.

**Owner**: Bel Consulting OÜ (registry 16588745, VAT EE102951727, Tallinn, Estonia)
**License**: MIT

## Features

- **No external services** — runs entirely in your infrastructure, no third-party calls, no iframes
- **No external JavaScript** — the browser widget uses only the native WebCrypto API (`crypto.subtle.deriveBits`)
- **CSP-compatible** — no `script-src` carve-outs needed; the widget is an inline nonce'd script
- **PBKDF2-HMAC-SHA256** proof-of-work — memory-hard-ish, GPU-resistant, tunable difficulty
- **Single-use tokens** — Redis-backed, HMAC-signed, IP-bound challenges prevent replay and relay attacks
- **Telemetry scoring** — detects headless browsers via webdriver flag, hardware concurrency, and interaction metrics
- **Scope isolation** — a challenge minted for "login" cannot be reused on "signup"
- **Dev-mode bypass** — compile-gated bypass for local development (`cfg!(debug_assertions)` gate)

## Protocol

```
┌──────────┐   POST /api/kcaptcha/challenge {scope}   ┌─────────────┐
│ Browser  │ ─────────────────────────────────────────▶│  Your App    │
│ (widget) │◀─── {nonce, challenge, salt, mKib, ...}──│              │
│          │                                           │ Redis SET    │
│ PBKDF2   │   POST /auth/login {kiwi__token}          │ kcaptcha:{   │
│ brute-   │ ─────────────────────────────────────────▶│   nonce} →   │
│ force    │                                           │ record       │
│ counter  │                                           │              │
│          │                                           │ verify.rs:   │
│          │                                           │ 1. HMAC check│
│          │                                           │ 2. TTL check │
│          │                                           │ 3. IP binding│
│          │                                           │ 4. PBKDF2 re-│
│          │                                           │    derivation │
└──────────┘                                           │ 5. Telemetry │
                                                       │    scoring   │
                                                       └─────────────┘
```

## Quick Start

```toml
[dependencies]
kiwicaptcha = { path = "packages/kiwicaptcha" }
```

### 1. Issue a Challenge

```rust
use kiwicaptcha::{ChallengeConfig, issue_challenge};

let config = ChallengeConfig {
    secret_key: "your-hmac-secret-key".into(),
    m_kib: 50_000,        // PBKDF2 iterations
    target_bits: 16,       // ~1-3s solve on commodity CPU
    ttl_secs: 120,
    ..Default::default()
};

let issued = issue_challenge(&config, "login", &client_ip, now_unix)?;

// Store issued.record in Redis keyed by nonce
// Send issued.challenge to the client
```

### 2. Render the Widget (Server-Side)

```rust
use kiwicaptcha::kiwi_widget_html;

// The widget handles challenge fetch + solving via inline script
// Just render it inside your login/signup form:
let html = kiwi_widget_html();
```

### 3. Verify the Solution

```rust
use kiwicaptcha::{VerifyContext, verify_solution};

let solution = SolutionToken::decode(&body.kiwi_token)?;
let record = redis.get(&format!("kcaptcha:{}", solution.nonce))?;

let ctx = VerifyContext {
    record: &record,
    secret_key: &config.secret_key,
    counter: solution.counter,
    duration_ms: solution.duration_ms,
    now_unix,
    min_duration_ms: 80,
    expected_scope: Some("login"),
};

match verify_solution(&ctx) {
    VerifyOutcome::Valid => { /* allow login */ }
    VerifyOutcome::Invalid(reason) => { /* reject */ }
}
```

## API Overview

| Type | Purpose |
|------|---------|
| `ChallengeConfig` | Difficulty parameters and HMAC secret |
| `issue_challenge()` | Mint a new HMAC-signed, IP-bound challenge |
| `IssuedChallenge` | The client-facing challenge (send as JSON) |
| `ChallengeRecord` | Server-side state (store in Redis) |
| `SolutionToken` | Client-submitted solution (from `kiwi__token`) |
| `VerifyContext` | Parameters for server-side verification |
| `verify_solution()` | Re-derive PBKDF2 hash and check leading zero bits |
| `score_telemetry()` | Detect headless/automated clients |
| `kiwi_widget_html()` | Inline HTML + JS widget for auth pages |
