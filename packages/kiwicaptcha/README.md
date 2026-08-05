# KiwiCaptcha

A quantum-safe SHA-256 proof-of-work CAPTCHA. No external services, no tracking, no WASM.

## Features

- **SHA-256 proof-of-work** — a hash function, not a factoring/discrete-log scheme, so it is quantum-safe.
- **HMAC-signed, single-use challenges** — every challenge is bound to a server secret, nonce, and timestamp, so a token can only be redeemed once.
- **IP-bound** — challenges are bound to the requesting client's IP hash, defeating relay attacks.
- **Inline widget, zero dependencies** — the browser solver ships as a self-contained inline `<script>`. No external JS, no iframes, no third-party hosts.
- **Telemetry scoring** — detects headless browsers via the `webdriver` flag, hardware signals, and interaction metrics.
- **Auto-tuning difficulty** — the target bits scale automatically with current solver load.

## Protocol

```
┌──────────┐   POST /api/kcaptcha/challenge {scope}   ┌─────────────┐
│ Browser  │ ─────────────────────────────────────────▶│  Your App    │
│ (widget) │◀─── {nonce, challenge, salt, targetBits}─│              │
│          │                                           │ Redis SET    │
│ SHA-256  │   POST /auth/login {kiwi__token}          │ kcaptcha:{   │
│ brute-   │ ─────────────────────────────────────────▶│   nonce} →   │
│ force    │                                           │ record       │
│ counter  │                                           │              │
│          │                                           │ verify.rs:   │
│          │                                           │ 1. HMAC check│
│          │                                           │ 2. TTL check │
│          │                                           │ 3. IP binding│
│          │                                           │ 4. SHA-256   │
│          │                                           │    re-hash   │
│ └─────────┘                                           │ 5. Telemetry │
│                                                       │    scoring   │
└───────────────────────────────────────────────────────┴──────────────┘
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
    target_bits: 16,      // ~1-3s solve on a commodity CPU
    ttl_secs: 120,
    ..Default::default()
};

let issued = issue_challenge(&config, "login", &client_ip, now_unix, 0)?;

// Store issued.record in Redis keyed by nonce.
// Send issued.challenge to the client.
```

### 2. Render the Widget

```rust
use kiwicaptcha::kiwi_widget_html;

// The inline widget fetches the challenge and solves it in-browser
// using the native WebCrypto SHA-256. Just render it inside your form:
let html = kiwi_widget_html();
```

### 3. Verify the Solution

```rust
use kiwicaptcha::{SolutionToken, VerifyContext, verify_solution, VerifyOutcome};

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

## API Reference

| Type | Purpose |
|------|---------|
| `ChallengeConfig` | Difficulty parameters and HMAC secret |
| `issue_challenge()` | Mint a new HMAC-signed, IP-bound challenge |
| `IssuedChallenge` | The client-facing challenge (send as JSON) |
| `ChallengeRecord` | Server-side state (store in Redis) |
| `SolutionToken` | Client-submitted solution (from `kiwi__token`) |
| `VerifyContext` | Parameters for server-side verification |
| `verify_solution()` | Re-derive the SHA-256 hash and check leading zero bits |
| `score_telemetry()` | Detect headless/automated clients |
| `kiwi_widget_html()` | Inline HTML + JS widget for auth pages |
