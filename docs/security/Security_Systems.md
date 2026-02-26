# ApexMail Security Systems
## Comprehensive Implementation Reference

**Date:** February 26, 2026 (Updated: June 2025)
**Status:** Implemented & Verified — 811+ tests passing
**Location:** `services/mail-server/crates/`
**Authors:** Security Architecture Team

---

## Executive Summary

ApexMail implements eight dedicated Rust security crates providing defense-in-depth across the entire email infrastructure. Every crate is a zero-dependency-on-runtime, thread-safe library designed for integration into the mail-server binary. Combined, they form an 8-layer security stack protecting against volumetric attacks, injection, intrusion, spam, malware, account takeover, data exfiltration, and known threat actors.

**Recent Enhancements (June 2025):**
- ✅ Fast-path Aho-Corasick pre-filter for WAF with expanded command injection patterns
- ✅ JSON/GraphQL structural parsing with MAX_DEPTH=128 DoS protection
- ✅ ML score caching with concurrent access optimization
- ✅ JA4-style TLS fingerprinting for bot detection
- ✅ Background purge task for threat intelligence TTL management
- ✅ Encrypted archive detection (ZIP/RAR password protection)

| # | System | Crate | Tests | Primary Threat |
|---|--------|-------|-------|----------------|
| 1 | DDoS Protection | `ddos-protection` | 520 | Volumetric & application-layer floods |
| 2 | Web Application Firewall | `waf-engine` | 122 | SQLi, XSS, path traversal, command injection |
| 3 | Intrusion Detection/Prevention | `ids-engine` | 13 | Network intrusion, port scans, protocol abuse |
| 4 | Spam & Phishing Filter | `spam-filter` | 23 | Spam, phishing, email fraud |
| 5 | Attachment Sandbox | `sandbox` | 25 | Malware, macro exploits, dangerous files |
| 6 | Account Takeover Protection | `ato-protection` | 49 | Credential stuffing, session hijacking |
| 7 | Data Loss Prevention | `dlp-engine` | 27 | PII leakage, secret exposure, policy violations |
| 8 | Threat Intelligence | `threat-intel` | 32 | Known malicious IPs, domains, botnets |
| | **Total** | **8 crates** | **811+** | |

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [System 1: DDoS Protection](#2-system-1-ddos-protection)
3. [System 2: Web Application Firewall](#3-system-2-web-application-firewall)
4. [System 3: Intrusion Detection / Prevention](#4-system-3-intrusion-detection--prevention)
5. [System 4: Spam & Phishing Filter](#5-system-4-spam--phishing-filter)
6. [System 5: Attachment Sandbox](#6-system-5-attachment-sandbox)
7. [System 6: Account Takeover Protection](#7-system-6-account-takeover-protection)
8. [System 7: Data Loss Prevention](#8-system-7-data-loss-prevention)
9. [System 8: Threat Intelligence](#9-system-8-threat-intelligence)
10. [Cross-System Integration](#10-cross-system-integration)
11. [Testing & Quality Assurance](#11-testing--quality-assurance)
12. [Monitoring & Metrics](#12-monitoring--metrics)

---

## 1. Architecture Overview

### Unified Security Pipeline

```
Inbound Request / Email
    │
    ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 1: NETWORK EDGE                                               │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │ ddos-protection │  │  threat-intel   │  │    ids-engine          │ │
│  │ XDP/eBPF filter │  │ IP/domain block │  │ signature + protocol   │ │
│  │ rate limiting   │  │ reputation      │  │ connection tracking    │ │
│  └────────────────┘  └────────────────┘  └────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 2: APPLICATION GATE                                           │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │  waf-engine     │  │ ato-protection  │  │    spam-filter         │ │
│  │ SQLi/XSS/RCE   │  │ impossible trvl │  │ Bayesian + headers     │ │
│  │ anomaly scoring │  │ device fingerpr │  │ URL + content scoring  │ │
│  └────────────────┘  └────────────────┘  └────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 3: CONTENT INSPECTION                                         │
│  ┌────────────────┐  ┌────────────────────────────────────────────┐ │
│  │   sandbox       │  │              dlp-engine                    │ │
│  │ file magic      │  │ PII detection (CC, SSN, phone, email)     │ │
│  │ macro detection │  │ entropy-based secret scanning              │ │
│  │ policy engine   │  │ content policy enforcement                 │ │
│  └────────────────┘  └────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
    │
    ▼
  Allow / Block / Challenge / Quarantine
```

### Shared Design Principles

All 8 crates follow consistent patterns:

- **Pure Rust** — no FFI, no C dependencies, zero `unsafe` blocks
- **Thread-safe** — all engines use `Arc`, `DashMap`, or `parking_lot::RwLock` for concurrent access
- **Configurable** — every crate has a `*Config` struct with `Default` implementation and `serde` (de)serialization
- **Testable** — comprehensive unit tests with realistic payloads; 230 tests total
- **Error handling** — dedicated `thiserror`-based error enums; `#![deny(clippy::unwrap_used)]` enforced on newer crates
- **Zero-copy where possible** — string slicing and reference-based analysis to minimize allocations

---

## 2. System 1: DDoS Protection

**Crate:** `ddos-protection` v0.1.0 — `crates/ddos-protection/`
**License:** MIT
**Tests:** 520

### Purpose

Multi-layered DDoS protection addressing volumetric attacks, protocol attacks, application-layer floods, and resource exhaustion attacks specific to email infrastructure.

### Feature Flags

| Flag | Contents | Default |
|------|----------|---------|
| `core` | Rate limiting + fingerprinting + session tracking | Yes |
| `ml` | Isolation Forest anomaly detection | No |
| `challenges` | PoW, JS, Cookie, CAPTCHA challenges | No |
| `coordinator` | Cross-region threat intel sharing (Redis Streams + CRDTs) | No |
| `xdp` | XDP/eBPF packet filtering (requires separate kernel module build) | No |
| `full` | core + ml + challenges + coordinator (excludes xdp) | No |

### Architecture — 5-Layer Pipeline

The `DdosProtector::evaluate()` method implements:

1. **Blocklist check** — immediate block if IP is on blocklist
2. **Fingerprint analysis** — TLS (JA4) fingerprint suspicion → reputation penalty
3. **Cost-based rate limiting** — per-tenant token bucket + system-wide atomic capacity check
4. **Session tracking + ML** — behavioral analysis, anomaly scoring, optional challenges
5. **Reputation-based decision** — block or challenge based on composite reputation score

### Module Map (15 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `DdosProtector`, `RequestContext`, `BlockEntry`, `AttackState` | Orchestrator; 4-layer evaluate pipeline |
| `config.rs` | `ProtectorConfig`, `ProtectorConfigBuilder` | Rate limits, reputation thresholds, session tracking, detection, challenges, coordination, cleanup intervals |
| `decision.rs` | `ProtectionDecision` (Allow/Challenge/RateLimit/Block), `Challenge` (None/Js/Pow/Cookie/Captcha/Blocked) | Decision types; `PowChallenge` with SHA-256 verification |
| `reputation.rs` | `ReputationScore` (0–100), `ReputationLevel` (Blocked/Suspicious/Normal/Trusted) | Per-IP scoring with request tracking, challenge pass/fail, rate limit hits |
| `cost_based.rs` | `CostBasedLimiter`, `RequestCost` (CPU/memory/IO/external), `CostDecision` | Endpoint cost registry; token-bucket per tenant + system-wide atomic budget |
| `session.rs` | `SessionTracker`, `Session` | IAT tracking, endpoint diversity, coefficient-of-variation computation |
| `adaptive.rs` | `AdaptiveRateLimiter`, `TrafficObservation` | Z-score anomaly detection, EMA threshold adjustment, cold-start protection |
| `bot_detection.rs` | `SessionBehavior`, `BotAssessment`, `BotSignals` | Timing regularity, periodicity (autocorrelation), endpoint concentration, Shannon entropy |
| `middleware.rs` | `DdosMiddlewareState`, `RequestContextBuilder`, `MiddlewareAction` | HTTP middleware integration; `extract_client_ip()` (X-Real-IP, X-Forwarded-For, CF-Connecting-IP) |
| `smtp_protection.rs` | `SmtpConnectionProtection`, `SmtpState` (full state machine), `SmtpCommand` | SMTP DDoS: slowloris detection, command rate limiting, recipient throttling, tarpitting |
| `metrics.rs` | 11 Prometheus metrics | `REQUESTS_TOTAL`, `BLOCKED_IPS`, `ANOMALY_SCORE`, `CHALLENGE_LATENCY`, `ACTIVE_SESSIONS`, etc. |
| `ml.rs` | `IsolationForest`, `FeatureVector` (10 dimensions) | Online-learning anomaly detection: request_rate, bytes_rate, connection_age, size_variance, iat_mean/variance, endpoint_diversity, error_rate, geo_distance, time_factor |
| `ml_cache.rs` | `MlScoreCache`, `CachedScore`, `CacheStats` | **NEW:** Thread-safe LRU cache for ML anomaly scores. Configurable TTL and capacity. Reduces redundant computations for repeated requests from same IP. Uses `parking_lot::RwLock` for concurrent reads |
| `challenges.rs` | `ChallengeManager`, `JsChallenge`, `PowChallenge`, `CookieChallenge` | Obfuscated JS, SHA-256 leading-zero-bits PoW (difficulty 24), HMAC-signed cookies (constant-time via `subtle`) |
| `coordinator.rs` | `ThreatIntelService`, `GCounter`, `PNCounter`, `ORSet<T>` | Redis Streams event propagation; CRDTs for eventually-consistent distributed state |

### SMTP Protection State Machine

```
Connected → EHLO/HELO → MAIL FROM → RCPT TO → DATA → Message → QUIT
    ↓           ↓            ↓           ↓        ↓
  rate-limit  validate    validate    throttle  size-check
  per-IP      hostname    sender      per-sender max-size
              greeting    address     recipients tarpit-slow
              delay       pipeline    limit      slowloris-detect
```

**SmtpCommand enum:** Ehlo, Helo, MailFrom, RcptTo, Data, Rset, Noop, Quit, Vrfy, Help, StartTls, Auth, Unknown

**SmtpProtectionError variants:** TooManyCommands, Timeout, InvalidSequence, TooManyRecipients, MessageTooLarge, SlowlorisDetected, ConnectionRateLimited, TooManyConcurrent

### Key Configuration (`ProtectorConfig`)

- Rate limiting thresholds (per-IP, per-tenant, global)
- Reputation score ranges for each `ReputationLevel`
- Session tracking intervals and behavioral anomaly thresholds
- ML parameters (Isolation Forest tree count, sample size, anomaly score threshold)
- Challenge difficulty parameters (PoW bit difficulty, JS complexity)
- Coordination settings (Redis URL, stream name, consumer group)
- Cleanup intervals (reputation decay, block expiry, session eviction)

---

## 3. System 2: Web Application Firewall

**Crate:** `waf-engine` v0.1.0 — `crates/waf-engine/`
**License:** PROPRIETARY
**Tests:** 122

### Purpose

Pure-Rust Web Application Firewall with AST-based SQL injection detection, HTML/JS token-level XSS analysis, path traversal prevention, command injection detection, fast-path pattern pre-filtering, JSON/GraphQL structural parsing, and OWASP CRS-compatible anomaly scoring.

### Feature Flags

| Flag | Contents | Default |
|------|----------|---------|
| `core` | SQL/XSS/path traversal detection + rule engine | Yes |
| `learning` | Adaptive false-positive learning | No |
| `full` | All of the above | No |

### Architecture

```
HTTP Request
    │
    ▼
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│   Decoder    │────▶│  Rule Engine  │────▶│  SQL AST      │
│   ─────────  │     │  ──────────── │     │  ─────────    │
│   URL-decode │     │  Aho-Corasick │     │  Token Parser │
│   HTML-decode│     │  Anomaly Score│     │  Structure Δ  │
│   Base64     │     │  Pattern Match│     │  Tautology    │
└─────────────┘     └──────────────┘     └───────────────┘
                                               │
                                               ▼
                    ┌──────────────┐     ┌───────────────┐
                    │   Decision    │◀───│  XSS Analyzer  │
                    │   ──────────  │     │  ─────────    │
                    │   Allow       │     │  HTML Lexer   │
                    │   Monitor     │     │  Event Attrs  │
                    │   Block       │     │  Script Tags  │
                    └──────────────┘     └───────────────┘
```

### Module Map (10 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `ParanoiaLevel` (Low/Medium/High/Paranoid), `WafVerdict` (Allow/Monitor/Block), `RuleMatch`, `AttackCategory`, `MatchLocation`, `WafError` | Public API types |
| `config.rs` | `WafConfig` (16 fields) | Paranoia level, blocking/detection thresholds, max sizes, enable flags per attack type, IP/path allowlists, max decode depth |
| `engine.rs` | `WafEngine`, `WafDecision` (Allow/Block/Monitor), `ThreatInfo`, `HttpRequest<'a>` | Orchestrator: decode → fast-path → JSON/GraphQL → path traversal → SQLi → XSS → query params → headers → body → protocol → score → decision |
| `decoder.rs` | `decode_payload()` | Recursive URL-decode, HTML entity decode, Base64 decode |
| `fast_path.rs` | `FastPathMatcher`, `FastPathResult` | **NEW:** Aho-Corasick pre-filter for O(n) suspicious pattern detection. Patterns include SQL keywords, XSS vectors, path traversal, command injection (`& whoami`, `sudo su -`, `\ncat `, `\ncurl `). Provides early exit for clean payloads |
| `json_graphql.rs` | `parse_json_body()`, `parse_graphql()`, `extract_graphql_operations()` | **NEW:** JSON/GraphQL structural parsing with **MAX_DEPTH=128** to prevent stack overflow DoS. Extracts `query`/`variables` from JSON, detects GraphQL introspection (`__schema`, `__type`), recognizes `fragment` keyword. Fallback parsing for raw GraphQL queries |
| `detection.rs` | `analyze_path_traversal()`, `analyze_command_injection()`, `analyze_protocol_anomalies()` | Path traversal (../), shell metacharacters (;, \|, &&, $(), backticks), protocol violation detection (TRACE method, oversized headers) |
| `sql_analyzer.rs` | `analyze_sqli()` | AST-based tokenizer → SQL token stream → tautology detection (1=1, 'a'='a'), UNION SELECT, stacked queries, blind/time-based injection (SLEEP, BENCHMARK, WAITFOR), comment evasion (UN/\*\*/ION), string termination logic, dangerous functions (LOAD_FILE, INTO OUTFILE). Case-insensitive keyword matching. Handles unterminated quotes (injection breakout) |
| `xss_analyzer.rs` | `analyze_xss()` | HTML tag detection (\<script\>, \<svg\>, \<img\>), event handler attributes (onerror, onload, onfocus), JavaScript URIs (javascript:), CSS expressions (expression()), data: URIs |
| `rules.rs` | `WafRule`, `RuleCategory` | OWASP CRS-compatible rule definitions with severity scoring |

### Key Types

```rust
pub enum AttackCategory {
    SqlInjection,       // OWASP CRS 942xxx
    Xss,                // OWASP CRS 941xxx
    PathTraversal,      // OWASP CRS 930xxx
    CommandInjection,
    Rce,
    ProtocolViolation,
    RequestAnomaly,
}

pub struct RuleMatch {
    pub rule_id: u32,           // e.g., 942100 for SQLi tautology
    pub category: AttackCategory,
    pub score: u32,             // Severity contribution to anomaly total
    pub message: String,
    pub location: MatchLocation, // Path, QueryParam, Body, Header, Cookie
    pub matched_data: String,   // Truncated payload snippet
}
```

### SQL Injection Detection Pipeline

1. **Tokenize** input into SQL tokens (string literals, number literals, keywords, operators, identifiers, comments)
2. **Tautology detection** — `1=1`, `'a'='a'`, always-true comparisons (`1<2`, `2>1`)
3. **UNION SELECT detection** — keyword pair scanning
4. **Stacked queries** — semicolon followed by SQL keyword
5. **Comment evasion** — inline `/**/` splitting keywords, MySQL conditional comments `/*!`
6. **Blind injection** — SLEEP, BENCHMARK, WAITFOR keywords
7. **String termination logic** — quote followed by OR/AND
8. **Dangerous functions** — LOAD_FILE, INTO OUTFILE, INFORMATION_SCHEMA

**Unterminated quote handling:** When a single quote has no closing match (e.g., `' OR 1=1 --`), the tokenizer recognizes this as a string breakout attack and re-parses the content after the quote, enabling tautology and keyword detection.

### Tested Attack Payloads

- `' OR 1=1 --` → SQLi tautology (rule 942100)
- `1 UNION SELECT username, password FROM users` → UNION injection (rule 942200)
- `1; DROP TABLE users` → stacked query (rule 942300)
- `UN/**/ION SE/**/LECT` → comment evasion (rule 942400)
- `1 OR SLEEP(5)` → blind injection (rule 942500)
- `<script>alert(1)</script>` → XSS script tag
- `<img onerror=alert(1)>` → XSS event handler
- `javascript:alert(1)` → XSS JS URI
- `../../etc/passwd` → path traversal
- `; cat /etc/passwd` → command injection

---

## 4. System 3: Intrusion Detection / Prevention

**Crate:** `ids-engine` v0.1.0 — `crates/ids-engine/`
**License:** PROPRIETARY
**Tests:** 13

### Purpose

Network-level IDS/IPS with Suricata/ET-compatible signature matching, protocol anomaly detection (SMTP, DNS, TLS), and stateful connection tracking for port scan and SYN flood detection.

### Feature Flags

| Flag | Contents | Default |
|------|----------|---------|
| `core` | Signature matching + protocol analysis + connection tracking | Yes |
| `deep_inspection` | Extended payload inspection | No |
| `full` | All features | No |

### Module Map (6 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `IdsError` (Signature/Config/Internal) | Error types |
| `config.rs` | `IdsConfig` (11 fields) | `inline_mode` (IPS vs IDS), `max_connections` (1M), `portscan_threshold` (20), `syn_flood_threshold` (100), `max_payload_inspect` (64KB), enable flags for SMTP/DNS/TLS, `alert_rate_limit` |
| `engine.rs` | `IdsEngine`, `Alert`, `AlertSeverity` (Info/Low/Medium/High/Critical), `IdsVerdict` (Pass/Alert/Drop/Reject) | Orchestrator: (1) signature scan, (2) protocol analysis, (3) connection tracking anomalies |
| `signature.rs` | `Signature`, `SignatureSet`, `SignatureAction` (Pass/Alert/Drop/Reject), `SigSeverity`, `builtin_mail_signatures()` | Aho-Corasick multi-pattern matching; builtin signatures for email-specific threats |
| `protocol_analyzer.rs` | `analyze_smtp()`, `analyze_dns()`, `analyze_tls()` | SMTP: bare LF detection, null byte injection. DNS: oversized responses. TLS: SSLv3 detection |
| `connection_tracker.rs` | `ConnectionTracker`, `ConnectionAnomaly` (PortScan/SynFlood/ConnectionFlood), `TrackedConnection`, `ConnState` | DashMap-based tracking; port scan detection (unique ports per IP in window), SYN flood (half-open count), connection flood (total per IP) |

### Inspection Pipeline

```
Packet arrives
    │
    ├─── 1. Signature Scan (Aho-Corasick)
    │        Pattern match against builtin mail signatures
    │        Returns: Vec<Alert> with severity + action
    │
    ├─── 2. Protocol Analysis
    │        SMTP: bare LF, null bytes
    │        DNS:  oversized responses
    │        TLS:  deprecated versions (SSLv3)
    │
    └─── 3. Connection Tracking (stateful)
             Port scan: >20 unique ports from same IP in window
             SYN flood: >100 half-open connections
             Conn flood: >max_connections total per IP
```

### IDS vs IPS Mode

- **IDS mode** (`inline_mode: false`): Alerts only — all verdicts are `Pass` or `Alert`, never `Drop`/`Reject`
- **IPS mode** (`inline_mode: true`): Active blocking — `Drop` and `Reject` verdicts are emitted and should be enforced by the calling code

---

## 5. System 4: Spam & Phishing Filter

**Crate:** `spam-filter` v0.1.0 — `crates/spam-filter/`
**License:** PROPRIETARY
**Tests:** 23

### Purpose

Multi-analyzer spam and phishing detection combining Bayesian classification, header authentication analysis, Aho-Corasick content pattern matching, and URL reputation scoring into a composite weighted verdict.

### Feature Flags

| Flag | Contents | Default |
|------|----------|---------|
| `core` | Bayesian + headers + content + URL analysis | Yes |
| `phishing` | Advanced phishing detection | No |
| `full` | All features | No |

### Module Map (7 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `SpamConfig`, `SpamEngine`, `SpamVerdict`, `SpamError` | Public re-exports |
| `config.rs` | `SpamConfig` (13 fields) | Thresholds: `ham_threshold` (3.0), `spam_threshold` (6.0), `reject_threshold` (10.0). Weights: `bayesian_weight` (0.3), `header_weight` (0.25), `url_weight` (0.25), `content_weight` (0.2). Enable flags. `max_urls_to_analyze` (50). 24 `dangerous_extensions` |
| `engine.rs` | `SpamEngine`, `SpamVerdict` (score, classification, bayesian_probability, header/content/url scores), `SpamClass` (Ham/Spam/Reject) | Orchestrator: (1) Bayesian classify, (2) header analysis, (3) content scoring, (4) URL analysis, (5) weighted composite, (6) classify. Also: `train_spam()`, `train_ham()` for online learning |
| `bayesian.rs` | `BayesianClassifier`, `BayesianModel` | Multinomial Naive Bayes with Laplace smoothing; thread-safe via `parking_lot::RwLock`; online incremental learning (`learn_spam()`, `learn_ham()`); log-sum-exp numerically stable classification; model export for persistence |
| `header_analyzer.rs` | `analyze_headers()`, `EmailHeaders`, `HeaderScore` | SPF/DKIM/DMARC result parsing, from/reply-to domain mismatch, missing Message-ID, suspicious Received chains |
| `content_scorer.rs` | `score_content()`, `ContentScore` | Aho-Corasick (case-insensitive) matching against 26 spam/phishing phrases: urgency (act now, limited time), financial lures (you have won, wire transfer, Nigerian prince), pharma (viagra, weight loss), phishing (verify your account, click here to login, update your payment), unsubscribe tricks. Also: ALL-CAPS ratio, invisible character detection (zero-width) |
| `url_analyzer.rs` | `analyze_urls()`, `extract_urls()`, `UrlScore` | URL extraction (http/https), URL shortener detection (bit.ly, tinyurl, t.co, goo.gl, ow.ly, is.gd), IP-address URLs, suspicious TLDs (.tk, .ml, .ga, .cf, .gq, .xyz, .top, .buzz), data: URI schemes, mixed-script/IDN homograph detection, excessive URL count |

### Composite Scoring Formula

```
composite = (bayesian_probability × 10.0 × bayesian_weight)
          + (header_score × header_weight)
          + (content_score × content_weight)
          + (url_score × url_weight)

if composite >= reject_threshold (10.0) → REJECT
if composite >= spam_threshold (6.0)    → SPAM
else                                    → HAM
```

### Online Learning

The Bayesian classifier supports online (incremental) training without full retraining:

```rust
engine.train_spam("Buy viagra now! Million dollars free lottery");
engine.train_ham("Hi team, please review the quarterly report");
```

Internally, `learn_spam()` / `learn_ham()` acquire a write lock on the `BayesianModel`, update word frequencies and class counts, then release the lock — allowing concurrent `classify()` reads.

---

## 6. System 5: Attachment Sandbox

**Crate:** `sandbox` v0.1.0 — `crates/sandbox/`
**License:** MIT
**Tests:** 25

### Purpose

Secure attachment analysis using static file inspection — file magic detection, SHA-256 hashing, extension validation, OLE2/macro detection, encrypted archive detection, and configurable policy engine.

### Module Map (5 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `SandboxError` (Io/FileTooLarge/NestingDepthExceeded/PolicyViolation/AnalysisError) | Error types |
| `config.rs` | `SandboxConfig` (12 fields) | `max_file_size` (25MB), `max_nesting_depth` (3), `max_archive_entries` (1000), 42 `dangerous_extensions`, 14 `blocked_extensions` (.exe, .scr, .bat, .cmd, .com, .pif, .vbs, .cpl, .ps1, .msi, .dll, .hta, .vbe, .wsf), 4 `blocked_mime_types`, `suspicious_threshold` (5.0), `reject_threshold` (10.0), `analysis_timeout_secs` (30) |
| `engine.rs` | `SandboxEngine`, `SandboxVerdict` (analysis_id, sha256, size, file_type, filename, decision, risk_score, reasons, findings, timestamp), `VerdictFinding` (id, description, risk) | Orchestrator: (1) file size check, (2) static file inspection, (3) policy evaluation, (4) build verdict. Also: `analyze_batch()`, `is_rejected()`, `any_rejected()` |
| `file_inspector.rs` | `inspect_file()`, `FileInspection`, `FileType`, `is_zip_encrypted()`, `is_rar_encrypted()` | File magic detection (PE/MZ, ELF, PDF, ZIP/PK, OLE2/CFB, HTML), SHA-256 hash computation, extension validation, double extension attack detection (e.g., `invoice.pdf.exe`), OLE2 macro indicators (`VBA`, `AutoOpen`, `Document_Open`), malicious PDF indicators (`/JavaScript`, `/JS`, `/OpenAction`, `/Launch`), **encrypted archive detection** (ZIP password-protected via general purpose bit flag, RAR encrypted headers via flags byte) |
| `policy.rs` | `evaluate_policy()`, `PolicyResult`, `PolicyDecision` (Allow/Flag/Reject) | Policy rules: blocked extensions → Reject, blocked MIME types → Reject, oversized files → Reject, executable file types (PE/ELF) → Reject, dangerous extensions → Flag, macros detected → Flag, extension mismatch → Flag, malicious indicators → Flag, **encrypted archives → Flag (ARCHIVE_ENCRYPTED indicator)** |

### File Type Detection

```
Magic bytes → FileType:
  MZ (0x4D5A)        → PE (Windows executable)
  \x7fELF             → ELF (Linux executable)
  %PDF                → PDF
  PK\x03\x04          → ZIP/Archive (+ bit 0 of general purpose flag → encrypted)
  RAR!\x1a\x07        → RAR/Archive (+ flags byte check for encryption)
  \xD0\xCF\x11\xE0   → OLE2 (Office macro container)
  <html, <HTML, <!DOCTYPE → HTML
  (none matched)      → PlainText
```

### Policy Decision Matrix

| Condition | Decision | Risk |
|-----------|----------|------|
| Blocked extension (.exe, .scr, .bat, .cpl, .vbe, .wsf, etc.) | **Reject** | 10.0 |
| Blocked MIME type | **Reject** | 10.0 |
| File > max_file_size (25MB) | **Reject** | 10.0 |
| PE or ELF file type | **Reject** | 10.0 |
| Dangerous extension | Flag | 5.0 |
| OLE2 macros detected | Flag | 6.0 |
| Extension mismatch (e.g., .pdf is actually PE) | Flag | 4.0 |
| Malicious PDF indicators | Flag | 5.0 |
| Double extension attack | Flag | 4.0 |

---

## 7. System 6: Account Takeover Protection

**Crate:** `ato-protection` v0.1.0 — `crates/ato-protection/`
**License:** MIT
**Tests:** 49

### Purpose

Account takeover prevention using Haversine impossible-travel detection, device fingerprinting, TLS fingerprinting (JA4-style), failed-attempt lockout, and time-of-day behavioral profiling.

### Module Map (7 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `AtoError` (SessionNotFound/NoHistory/Internal) | Error types |
| `config.rs` | `AtoConfig` (11 fields) | `max_travel_speed_kmh` (900.0 — commercial jet), `mfa_threshold` (5.0), `block_threshold` (9.0), `max_failed_attempts` (5), `lockout_duration_secs` (900), `failed_attempt_window_secs` (300), `max_history_per_user` (100), weights: `weight_geo` (1.0), `weight_device` (1.0), `weight_time` (1.0), `weight_failures` (1.0) |
| `engine.rs` | `AtoEngine`, `AtoVerdict` (risk_score 0–10, action, new_device, impossible_travel, factors), `AtoAction` (Allow/RequireMfa/Block), `RiskFactor` (id, description, risk) | Orchestrator: (1) failed attempts lockout, (2) impossible travel detection, (3) record event + device novelty, (4) TLS fingerprint check, (5) behavioral analysis, (6) cap at 10.0, (7) action decision |
| `session.rs` | `LoginEvent` (user_id, ip_address, user_agent, lat/lon, timestamp, success), `DeviceFingerprint` (SHA-256 of user_agent + IP /24 prefix), `UserLoginHistory`, `SessionStore` (DashMap-backed, thread-safe) | Per-user login history storage; device fingerprint tracking; failure counting with time window; typical login hour computation |
| `geo.rs` | `GeoPoint` (lat, lon), `haversine_distance()`, `check_impossible_travel()` | Haversine formula (Earth radius 6371 km); returns (is_impossible, required_speed_kmh, distance_km). Zero elapsed time with different locations → immediately impossible |
| `behavior.rs` | `analyze_behavior()`, `BehaviorScore`, `BehaviorFinding` | Time-of-day anomaly (circular hour distance), low history flag, burst login detection |
| `tls_fingerprint.rs` | `TlsFingerprint`, `TlsFingerprintTracker`, `extract_fingerprint()` | **NEW:** JA4-style TLS fingerprinting for bot detection. Extracts cipher suites, TLS version, extensions, ALPN protocols into unique fingerprint hash. Tracks fingerprint history per IP for anomaly detection. Correlates with known bot signatures |

### Evaluation Pipeline

```
LoginEvent arrives
    │
    ├─── 1. Failed Attempt Lockout
    │        Count failures in window (300s)
    │        ≥5 failures → risk += 10.0 × weight_failures → BLOCK
    │
    ├─── 2. Impossible Travel Detection (BEFORE recording event)
    │        Haversine distance from last successful login
    │        Required speed > 900 km/h → risk += 8.0 × weight_geo
    │
    ├─── 3. Record Event + Device Novelty
    │        SHA-256 fingerprint (user_agent + IP/24)
    │        New device → risk += 3.0 × weight_device
    │
    ├─── 4. Behavioral Analysis
    │        Login hour vs typical hour (circular distance)
    │        Low history warning
    │
    └─── 5. Decision
             risk ≥ 9.0 → BLOCK
             risk ≥ 5.0 → REQUIRE_MFA
             else        → ALLOW
```

**Critical design note:** Impossible travel detection runs BEFORE `record_login()` to compare against the previous successful login, not the event being recorded.

### Haversine Formula

```
a = sin²(Δφ/2) + cos(φ₁) × cos(φ₂) × sin²(Δλ/2)
c = 2 × atan2(√a, √(1−a))
d = R × c    (R = 6371 km)
```

If elapsed_secs ≤ 0 and distance > 0 → impossible (infinite speed required)

---

## 8. System 7: Data Loss Prevention

**Crate:** `dlp-engine` v0.1.0 — `crates/dlp-engine/`
**License:** MIT
**Tests:** 27

### Purpose

Outbound email content scanning for PII (credit cards, SSNs, phone numbers, email addresses), high-entropy secrets (API keys, tokens), and confidentiality policy violations.

### Module Map (6 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `DlpError` (PatternError/ScanError/PolicyViolation) | Error types |
| `config.rs` | `DlpConfig` (12 fields) | Enable flags: `detect_credit_cards`, `detect_ssn`, `detect_phone_numbers`, `detect_email_addresses`, `detect_secrets`. `entropy_threshold` (4.5), `min_entropy_token_length` (20). 10 `confidential_keywords` ("confidential", "internal only", "proprietary", "trade secret", "do not distribute", "restricted", "top secret", "classified", "attorney-client", "privileged"). `quarantine_threshold` (5.0), `block_threshold` (10.0), `max_scan_size` (1MB), `allowlisted_domains` |
| `engine.rs` | `DlpEngine`, `DlpVerdict` (risk_score, action, pii_findings, entropy_findings, policy_matches, summary), `DlpAction` (Allow/Audit/Quarantine/Block) | Orchestrator: (1) domain allowlist check, (2) PII scan, (3) entropy scan, (4) content policy scan, (5) determine action. Also: `scan_body()` convenience method |
| `pii.rs` | `scan_pii()`, `PiiMatch` (pii_type, redacted, risk, offset), `PiiType` (CreditCard/Ssn/PhoneNumber/EmailAddress), `luhn_check()` | Credit card: regex `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` + Luhn validation (risk 5.0). SSN: `\b\d{3}-\d{2}-\d{4}\b` excluding invalid area numbers 000/666/9xx (risk 7.0). Phone: regex with international formats (risk 2.0). Email: standard pattern (risk 1.0). All matched data is redacted in output |
| `entropy.rs` | `scan_entropy()`, `shannon_entropy()`, `EntropyFinding`, `looks_like_secret()` | Shannon entropy: $H = -\sum p_i \log_2 p_i$. Tokens ≥20 chars with entropy ≥4.5 → potential secret. `looks_like_secret()` checks for known prefixes: `sk_`, `pk_`, `AKIA`, `ghp_`, `gho_`, `xox`, `sk-`, `rk_`, `whsec_`, plus base64/hex pattern heuristics. Risk: 6.0 for known-prefix secrets, 4.0 for high-entropy tokens |
| `content_policy.rs` | `scan_content_policy()`, `PolicyMatch` | Aho-Corasick case-insensitive keyword matching against configured confidential keywords. Risk: 3.0 per match (deduplicated) |

### PII Detection — Luhn Algorithm

The Luhn checksum validates credit card numbers to eliminate false positives:

```
1. Double every second digit from the right
2. If result > 9, subtract 9
3. Sum all digits
4. Valid if sum mod 10 == 0
```

Example: `4111 1111 1111 1111` → sum = 0 mod 10 → **valid CC** (risk 5.0)
Example: `1234 5678 9012 3456` → sum ≠ 0 mod 10 → **not a CC** (no match)

### Action Thresholds

| Risk Score | Action | Description |
|------------|--------|-------------|
| < 5.0 | **Allow** or **Audit** | Low risk; log if any findings |
| 5.0 – 9.9 | **Quarantine** | Hold for review |
| ≥ 10.0 | **Block** | Reject the email |

---

## 9. System 8: Threat Intelligence

**Crate:** `threat-intel` v0.1.0 — `crates/threat-intel/`
**License:** MIT
**Tests:** 32

### Purpose

Threat intelligence feed ingestion, IP and domain blocklist management with CIDR support, TTL-based expiration, background purge tasks, and composite reputation scoring.

### Module Map (7 source files)

| Module | Key Types | Responsibility |
|--------|-----------|----------------|
| `lib.rs` | `ThreatIntelError` (ParseError/FetchError/InvalidIp/InvalidCidr) | Error types |
| `config.rs` | `ThreatIntelConfig` (9 fields), `FeedSource`, `FeedFormat` | `default_ttl_secs` (86400), `max_ip_entries` (1M), `max_domain_entries` (500K). Thresholds: `block_threshold` (7.0), `flag_threshold` (4.0). Weights: `weight_ip` (1.0), `weight_domain` (1.0). Default feeds: Spamhaus DROP + EDROP. `FeedFormat`: SpamhausDrop, PlainText, CsvIp, JsonIp, DomainList |
| `engine.rs` | `ThreatIntelEngine`, `ThreatVerdict` (ip_reputation, domain_reputation, action, summary), `ThreatAction` (Allow/Flag/Block), `ThreatIntelStats` | `check_ip()`, `check_domain()`, `check()` (worst-of combined). Also: `purge_expired()`, `stats()` |
| `ip_blocklist.rs` | `IpBlocklist`, `IpBlockEntry`, `ThreatCategory` (Spam/Malware/Botnet/Scanner/Phishing/Hijacked/Bogon/BadReputation) | DashMap exact IP lookup + Vec CIDR range matching. `add_ip()`, `add_cidr()` parse and store. CIDR: precomputed prefix mask for O(n) range scan. `purge_expired()` removes entries past `expires_at` |
| `domain_blocklist.rs` | `DomainBlocklist`, `DomainBlockEntry` | DashMap string lookup. `lookup()` does exact match first, then walks parent domains for subdomain matching (e.g., `mail.evil.tk` matches `evil.tk`). Case-insensitive. Trailing dot handling. `parse_domain_list()` for bulk import |
| `reputation.rs` | `ReputationScore` (subject, score 0–10, sources, classification), `SourceScore`, `ReputationClass` (Clean/Suspicious/Malicious) | Composite: 70% worst source + 30% average of all sources. Classification: ≥7.0 Malicious, ≥4.0 Suspicious, <4.0 Clean |
| `background_task.rs` | `PurgeTaskConfig`, `PurgeStats`, `run_purge_loop()` | **NEW:** Async background task for automatic TTL-based cleanup. Configurable purge intervals. Returns statistics (entries_purged, duration_ms). Graceful shutdown via cancellation token |

### Threat Categories

```rust
pub enum ThreatCategory {
    Spam,           // Known spam sources
    Malware,        // Malware distribution
    Botnet,         // C&C or botnet member
    Scanner,        // Port/vulnerability scanner
    Phishing,       // Phishing infrastructure
    Hijacked,       // Hijacked IP space
    Bogon,          // Unallocated/reserved IP
    BadReputation,  // General bad reputation
}
```

### Reputation Scoring

```
composite_score = 0.7 × max(source_scores) + 0.3 × avg(source_scores)

if composite ≥ 7.0  → Malicious → BLOCK
if composite ≥ 4.0  → Suspicious → FLAG
if composite < 4.0  → Clean → ALLOW
```

### Feed Ingestion

Default feeds (configurable):

| Feed | Format | URL |
|------|--------|-----|
| Spamhaus DROP | `SpamhausDrop` | `https://www.spamhaus.org/drop/drop.txt` |
| Spamhaus EDROP | `SpamhausDrop` | `https://www.spamhaus.org/drop/edrop.txt` |

Supported formats: plain text (one IP/CIDR per line, `#` comments), Spamhaus DROP (SBL numbers), CSV IP, JSON IP, domain lists.

---

## 10. Cross-System Integration

### Request Processing Order

For an inbound email, the security systems are invoked in sequence:

```
1. threat-intel.check(sender_ip, sender_domain)
   └─ If Block → reject connection (451/550)

2. ddos-protection.evaluate(request_context)
   └─ If Block → reject with tarpit
   └─ If Challenge → issue PoW/JS/Cookie

3. ids-engine.inspect(ip, port, protocol, payload)
   └─ If Drop (IPS mode) → drop packet silently
   └─ If Reject → send RST/ICMP unreachable

4. waf-engine.inspect(http_request)  [HTTP/API traffic only]
   └─ If Block → 403 Forbidden
   └─ If Monitor → log + allow

5. ato-protection.evaluate(login_event)  [auth endpoints only]
   └─ If Block → 403 Account locked
   └─ If RequireMfa → redirect to MFA

6. spam-filter.analyze(body, headers, auth_results)
   └─ If Reject → 550 spam rejection
   └─ If Spam → quarantine / X-Spam-Flag header

7. sandbox.analyze(attachment_data, filename)
   └─ If Reject → strip attachment, notify sender
   └─ If Flag → quarantine for review

8. dlp-engine.scan(body, sender_domain)  [outbound only]
   └─ If Block → reject send, notify admin
   └─ If Quarantine → hold for review
   └─ If Audit → log findings, allow
```

### Shared Dependencies

All 8 crates share these workspace dependencies:

| Dependency | Version | Used For |
|------------|---------|----------|
| `tokio` | 1.44 | Async runtime |
| `serde` / `serde_json` | 1.0 | Configuration serialization |
| `sha2` | 0.10 | Hashing (fingerprints, PoW, file hashes) |
| `dashmap` | 6.1 | Lock-free concurrent hash maps |
| `parking_lot` | 0.12 | High-performance RwLock/Mutex |
| `thiserror` | 2.0 | Error type derivation |
| `chrono` | 0.4 | Timestamps and duration calculations |
| `aho-corasick` | 1.1 | Multi-pattern string matching |
| `tracing` | 0.1 | Structured logging |
| `prometheus` | 0.13 | Metrics exposition |

---

## 11. Testing & Quality Assurance

### Test Coverage by Crate

| Crate | Tests | Key Test Scenarios |
|-------|-------|--------------------|
| `ddos-protection` | 520 | Adaptive rate limiting, bot detection, middleware, SMTP protection, coordinator CRDTs, ML anomaly detection + caching, challenges (PoW difficulty 24), cost limiter, sessions, reputation, integration, **adversarial bypass tests**, **edge case overflow/underflow**, **performance stress tests** |
| `waf-engine` | 122 | SQL injection: tautology, UNION, stacked, blind, comment evasion. XSS: script, event, JS URI, SVG, CSS expression. **Fast-path pre-filter bypass tests**. **JSON/GraphQL depth limiting (MAX_DEPTH=128)**. **GraphQL introspection/fragment detection**. Command injection: shell metacharacters + `& whoami`, `sudo su`, newline+command patterns. Decoder: URL, HTML, Base64, multi-layer |
| `ids-engine` | 13 | Engine: clean traffic, basic detection, inline mode. Signatures: matching, no-match, multiple matches. Protocol: SMTP bare LF/null, DNS oversize, TLS SSLv3. Connections: port scan, SYN flood, established state |
| `spam-filter` | 23 | Bayesian: empty model, basic train+classify, tokenizer. Headers: clean, SPF/DKIM fail, from/reply mismatch, missing ID. Content: clean, spam phrases, phishing, ALL-CAPS, invisible chars. URLs: extraction, shortener, IP URL, suspicious TLD, data URI, mixed scripts. Engine: obvious spam, clean, phishing, class display |
| `sandbox` | 25 | File inspector: PE, ELF, PDF, ZIP, OLE2, HTML, text, SHA-256, double extension, macro detection, VBA, malicious PDF, **encrypted archive detection (ZIP/RAR password-protected)**. Policy: clean PDF, executable reject, oversized reject, blocked extension, suspicious quarantine. Engine: clean text, executable, double extension, too large, batch, verdict serializable |
| `ato-protection` | 49 | Geo: Haversine same/NYC-London/antipodal, impossible travel, plausible travel, zero elapsed. Session: fingerprint, new/different device, failure counting, capacity. Behavior: normal/unusual hour, hour distance, low history. **TLS fingerprinting: JA4-style extraction, fingerprint history, bot detection correlation**. Engine: first login, known device, failed lockout, impossible travel, action display |
| `dlp-engine` | 27 | PII: Luhn valid/invalid, CC detection, SSN detection/invalid, phone, redaction, no false positives. Entropy: Shannon uniform/max, API key, AWS key, normal text, looks-like-secret. Policy: confidential, no matches, empty keywords, risk, deduplication. Engine: clean, CC, SSN block, confidential, allowlist, API key, action display |
| `threat-intel` | 32 | IP blocklist: parse plain/Spamhaus, exact/CIDR/string lookup, expired, purge, invalid CIDR. Domain: exact, subdomain, case, trailing dot, expired, purge, parse list. Reputation: clean, suspicious, malicious, worst-source emphasis. **Background purge task: TTL expiration, configurable intervals, purge statistics**. Engine: clean IP, blocked IP/CIDR/domain, subdomain, combined, stats |

### Running All Security Tests

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd services/mail-server
# Run with all features for full coverage (811+ tests)
cargo test -p ddos-protection --features full \
           -p waf-engine -p ids-engine -p spam-filter \
           -p sandbox -p ato-protection -p dlp-engine -p threat-intel
```

---

## 12. Monitoring & Metrics

### DDoS Protection Metrics (Prometheus)

| Metric | Type | Description |
|--------|------|-------------|
| `ddos_requests_total` | Counter | Total requests evaluated |
| `ddos_blocked_ips` | Gauge | Currently blocked IPs |
| `ddos_anomaly_score` | Histogram | Anomaly score distribution |
| `ddos_challenge_latency` | Histogram | Challenge verification latency |
| `ddos_challenges_issued` | Counter | Challenges issued (by type) |
| `ddos_challenges_passed` | Counter | Challenges passed |
| `ddos_challenges_failed` | Counter | Challenges failed |
| `ddos_reputation_score` | Histogram | IP reputation score distribution |
| `ddos_threat_events` | Counter | Threat events shared across regions |
| `ddos_cost_budget_usage` | Gauge | System-wide cost budget utilization |
| `ddos_active_sessions` | Gauge | Active tracked sessions |

### Recommended Additional Metrics

Each security crate should expose:

| System | Recommended Metrics |
|--------|-------------------|
| WAF | `waf_requests_inspected`, `waf_attacks_blocked` (by category), `waf_anomaly_score` |
| IDS | `ids_packets_inspected`, `ids_alerts_total` (by severity), `ids_connections_tracked` |
| Spam Filter | `spam_emails_analyzed`, `spam_classified` (by class: ham/spam/reject), `spam_bayesian_score` |
| Sandbox | `sandbox_files_analyzed`, `sandbox_verdicts` (by decision), `sandbox_file_types` |
| ATO | `ato_logins_evaluated`, `ato_actions` (by action: allow/mfa/block), `ato_impossible_travel_count` |
| DLP | `dlp_emails_scanned`, `dlp_pii_detected` (by type), `dlp_actions` (by action) |
| Threat Intel | `threatintel_lookups`, `threatintel_hits` (ip/domain), `threatintel_entries` (ip/domain counts) |

---

## Appendix A: Crate Dependency Graph

```
ddos-protection ──► apexmail-rate-limiter
                ──► fingerprint

waf-engine      (standalone — no internal deps)
ids-engine      (standalone — no internal deps)
spam-filter     (standalone — no internal deps)
sandbox         (standalone — no internal deps)
ato-protection  (standalone — no internal deps)
dlp-engine      (standalone — no internal deps)
threat-intel    (standalone — no internal deps)
```

## Appendix B: File Inventory

| Crate | Source Files | Lines (approx) |
|-------|-------------|-----------------|
| `ddos-protection` | 15 | ~5,000 |
| `waf-engine` | 10 | ~2,200 |
| `ids-engine` | 6 | ~1,300 |
| `spam-filter` | 7 | ~1,200 |
| `sandbox` | 5 | ~950 |
| `ato-protection` | 7 | ~1,100 |
| `dlp-engine` | 6 | ~1,000 |
| `threat-intel` | 7 | ~1,200 |
| **Total** | **63** | **~13,950** |
