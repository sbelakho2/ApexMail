# Deliverability Operations Guide

This guide covers the operational procedures, configurations, and monitoring practices for maintaining high email deliverability in ApexMail.

---

## Table of Contents

- [IP Warmup Schedules](#ip-warmup-schedules)
- [Domain Warmup](#domain-warmup)
- [Authentication Standards](#authentication-standards)
- [Bounce Handling](#bounce-handling)
- [Complaint Monitoring](#complaint-monitoring)
- [Reputation Tracking](#reputation-tracking)
- [Suppression List Management](#suppression-list-management)
- [Circuit Breakers](#circuit-breakers)
- [ISP-Aware MX Detection](#isp-aware-mx-detection)
- [Inbox Placement Testing](#inbox-placement-testing)
- [Engagement Trust Scoring](#engagement-trust-scoring)
- [Bot Click Detection](#bot-click-detection)

---

## IP Warmup Schedules

New sending IPs have no established reputation with mailbox providers. The IP warmup process gradually increases send volume to build trust over a 14-day minimum period. ApexMail applies ISP-specific warmup schedules derived from each provider's documented best practices and observed throttling behavior.

### ISP-Specific Volume Caps (Messages/Day)

> Source of truth: `apps/worker/src/services/ip-rate-limiter.ts` — `DEFAULT_ISP_WARMUP_SCHEDULES`

| Day | Gmail | Microsoft | Yahoo | Apple | Default (all others) |
|-----|------:|----------:|------:|------:|--------------------:|
| 1   | 50 | 100 | 50 | 75 | 100 |
| 2   | 100 | 200 | 100 | 150 | 200 |
| 3   | 200 | 400 | 200 | 300 | 400 |
| 4   | 400 | 800 | 400 | 600 | 800 |
| 5   | 800 | 1,500 | 800 | 1,200 | 1,500 |
| 6   | 1,500 | 3,000 | 1,500 | 2,400 | 3,000 |
| 7   | 2,500 | 5,000 | 2,500 | 4,000 | 5,000 |
| 8   | 4,000 | 8,000 | 4,000 | 6,000 | 8,000 |
| 9   | 6,000 | 12,000 | 6,000 | 9,000 | 12,000 |
| 10  | 8,000 | 18,000 | 8,000 | 12,000 | 18,000 |
| 11  | 10,000 | 25,000 | 10,000 | 16,000 | 25,000 |
| 12  | 15,000 | 35,000 | 15,000 | 22,000 | 35,000 |
| 13  | 20,000 | 50,000 ✅ | 20,000 ✅ | 30,000 ✅ | 50,000 |
| 14  | 30,000 ✅ | Fully warmed | Fully warmed | Fully warmed | 75,000 |
| 15  | Fully warmed | — | — | — | 100,000 ✅ |

### Warmup Rules

1. **Volume allocation:** Messages are distributed across warmed and fully warmed IPs. Overflow beyond the current warmup cap is routed to the next available IP.
2. **Pause on high bounce:** If the bounce rate exceeds 5% on any day, the warmup is paused and the previous day's volume cap is applied until the rate drops below 3%.
3. **Pause on complaints:** If the complaint rate exceeds 0.1%, the warmup is paused immediately and a review is required before resuming.
4. **Graduation:** After Day 14 with clean metrics, the IP is marked as "warm" and volume caps are removed.
5. **ISP detection:** The warmup scheduler uses MX record lookups to classify destination domains into ISP groups and apply the correct per-ISP cap.

---

## Domain Warmup

In addition to IP warmup, ApexMail tracks per-domain sending volume to ensure new domains ramp gradually.

### Domain Volume Tracking

Domain warmup tracks per-domain sending volume using daily counters:

- Counters are incremented atomically on each send.
- Each counter expires after 48 hours to prevent unbounded growth.
- The warmup engine compares the current counter value against the domain's daily volume target before releasing messages to the MTA.

### Domain Warmup Behavior

- **New domains** start with a conservative daily cap (100 messages) and increase by approximately 50% each day.
- **Domain age** is tracked from the first successful send. Domains with no sends for 30+ days are re-entered into warmup.
- **Shared domains** (e.g., ApexMail-hosted subdomains) are pre-warmed and exempt from per-domain warmup.

---

## Authentication Standards

ApexMail enforces strict email authentication to maximize deliverability and protect sender reputation.

### SPF (Sender Policy Framework)

Required DNS TXT record on the sending domain:

```
v=spf1 include:spf.apexmail.dev ~all
```

- ApexMail verifies SPF alignment on outbound messages.
- Domains without a valid SPF record are placed in `pending` status and cannot send.

### DKIM (DomainKeys Identified Mail)

ApexMail signs all outbound messages with a 2048-bit RSA key. The required CNAME record:

```
apexmail._domainkey.yourdomain.com → dkim.apexmail.dev
```

- Key rotation occurs automatically every 90 days.
- Both the old and new keys remain active during the 7-day rotation window.

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

A DMARC record is required at minimum `p=none` for new domains:

```
_dmarc.yourdomain.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-rua@yourdomain.com; pct=100"
```

ApexMail recommends progressing to `p=reject` once deliverability is established.

### ARC (Authenticated Received Chain) — RFC 8617

ApexMail applies ARC headers to forwarded messages to preserve authentication results across intermediary hops. This is critical for mailing lists and auto-forwarding rules that break SPF and DKIM alignment.

ARC seal fields applied:

- `ARC-Seal` — Cryptographic seal over the chain.
- `ARC-Message-Signature` — DKIM-like signature of the message.
- `ARC-Authentication-Results` — Authentication results at each hop.

### MTA-STS (RFC 8461)

MTA-STS prevents TLS downgrade attacks by advertising a strict transport policy. ApexMail publishes:

```
_mta-sts.yourdomain.com TXT "v=STSv1; id=20260209"
```

With a policy file hosted at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mx1.apexmail.dev
mx: mx2.apexmail.dev
max_age: 86400
```

### TLSRPT (RFC 8460)

TLS Reporting enables receiving MTA-STS and DANE failure reports:

```
_smtp._tls.yourdomain.com TXT "v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com"
```

### BIMI (Brand Indicators for Message Identification)

BIMI displays a brand logo next to messages in supported clients (Gmail, Yahoo, Apple Mail).

**Requirements:**

| Requirement | Specification |
|-------------|--------------|
| Logo format | SVG Tiny Portable/Secure (SVG Tiny PS) |
| Max file size | 32 KB |
| DMARC policy | Must be `p=quarantine` or `p=reject` |
| VMC certificate | Verified Mark Certificate from DigiCert or Entrust |

**DNS record:**

```
default._bimi.yourdomain.com TXT "v=BIMI1; l=https://yourdomain.com/logo.svg; a=https://yourdomain.com/vmc.pem"
```

---

## Bounce Handling

ApexMail classifies bounces according to RFC 3463 enhanced status codes and applies automated disposition rules.

### Bounce Classification

| Category | Type | RFC 3463 Codes | Action |
|----------|------|----------------|--------|
| Invalid mailbox | Hard | `5.1.1`, `5.1.6` | Add to suppression list immediately |
| Domain not found | Hard | `5.1.2` | Add to suppression list; flag domain |
| Mailbox full | Soft | `4.2.2` | Retry for 72 hours, then suppress |
| Message too large | Soft | `5.3.4` | Return to sender; no suppression |
| Server unavailable | Soft | `4.0.0`, `4.4.1` | Retry with exponential backoff |
| Policy rejection | Hard | `5.7.1`, `5.7.13` | Add to suppression list |
| Rate limited | Soft | `4.7.1` | Defer and apply ISP-specific throttling |
| Auth required | Hard | `5.7.8` | Flag configuration issue |
| Spam blocked | Hard | `5.7.1` (with spam indicators) | Suppress; alert sender |

### Retry Schedule for Soft Bounces

| Attempt | Delay |
|---------|-------|
| 1 | 5 minutes |
| 2 | 15 minutes |
| 3 | 1 hour |
| 4 | 4 hours |
| 5 | 12 hours |
| 6 | 24 hours |
| 7 (final) | 48 hours |

After 7 failed attempts, the message is marked as a permanent failure and the recipient is flagged for review.

---

## Complaint Monitoring

Complaint rates are the single most critical factor in maintaining sender reputation with major ISPs.

### Thresholds and Alerts

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Complaint rate (per campaign) | > 0.05% | > 0.1% | Pause campaign; notify account owner |
| Complaint rate (per domain) | > 0.03% | > 0.08% | Throttle domain sends; escalate |
| Complaint rate (per IP) | > 0.05% | > 0.1% | Reroute traffic to alternate IP |

### Feedback Loop (FBL) Processing

ApexMail processes FBL reports from all major ISPs:

- **Gmail:** Integrated via Gmail Postmaster Tools and the `Feedback-ID` header.
- **Microsoft (SNDS/JMRP):** Automatic parsing of ARF-formatted reports.
- **Yahoo/AOL:** Standard ARF processing via registered FBL address.
- **Apple:** Processing via Apple's complaint reporting program.

On receipt of a complaint:

1. The recipient is immediately added to the account-level suppression list.
2. A `complained` event is emitted.
3. The complaint is attributed to the originating campaign.
4. If the complaint threshold is breached, automated throttling is applied.

---

## Reputation Tracking

ApexMail maintains a `reputation_stats` table that aggregates sending metrics per domain, per IP, and per ISP combination.

### Tracked Metrics

| Metric | Update Frequency | Retention |
|--------|-----------------|-----------|
| Send volume | Real-time | 365 days |
| Delivery rate | Hourly rollup | 365 days |
| Bounce rate (hard/soft) | Hourly rollup | 365 days |
| Complaint rate | Real-time | 365 days |
| Open rate | Hourly rollup | 90 days |
| Click rate | Hourly rollup | 90 days |
| Spam trap hits | Real-time | 365 days |
| Blocklist status | Every 6 hours | 365 days |

### Blocklist Monitoring

ApexMail periodically checks sending IPs against major DNS blocklists:

- Spamhaus (SBL, XBL, PBL)
- Barracuda RBL
- SORBS
- SpamCop
- URIBL

Blocklist detections trigger an immediate alert and automatic traffic rerouting.

---

## Suppression List Management

Suppression lists prevent sending to addresses that should not receive mail.

### Suppression Sources

| Source | Type | Behavior |
|--------|------|----------|
| Hard bounce | Automatic | Permanent suppression after first hard bounce |
| Complaint | Automatic | Permanent suppression on FBL report |
| Unsubscribe | Automatic | Per-list suppression; respects List-Unsubscribe |
| Manual | User-initiated | Account owner adds via API or dashboard |
| Regulatory | System | Addresses flagged by compliance engine |

### Suppression Checks

Suppression is checked at two points:

1. **Pre-queue:** Before the message enters the send queue. Suppressed messages are immediately dropped with a `dropped` event.
2. **Pre-send:** Before SMTP handshake. Catches addresses added to the suppression list after queuing.

### Suppression Expiry

- Hard bounces: No expiry (permanent).
- Soft bounces: Suppressed for 30 days, then eligible for retry.
- Unsubscribes: No expiry unless the recipient re-subscribes via confirmed opt-in.

---

## Circuit Breakers

ApexMail implements circuit breakers at the MTA connection layer to prevent cascade failures and protect sender reputation.

### Connection Circuit Breaker

Monitors per-destination SMTP connection success/failure.

| Parameter | Value |
|-----------|-------|
| Failure threshold | 10 consecutive failures |
| Reset timeout | 60 seconds |
| Monitoring window | 2 minutes |
| States | `closed` → `open` → `half-open` |

**Behavior:**

- **Closed (normal):** Connections proceed normally. Failures are counted.
- **Open (tripped):** All connection attempts to the destination are immediately rejected. A `deferred` event is emitted. The breaker remains open for 60 seconds.
- **Half-open (probing):** After the reset timeout, a single test connection is allowed. If it succeeds, the breaker closes. If it fails, the breaker re-opens.

### Error Rate Circuit Breaker

Monitors the rolling outcome rate across recent delivery attempts.

| Parameter | Value |
|-----------|-------|
| Window size | 20 outcomes |
| Failure threshold | 10+ failures within the window |
| Pause duration | 60 seconds |

When triggered, all sends to the affected destination are paused for 60 seconds, then a gradual ramp-up resumes.

### Per-ISP Throttling

Circuit breaker state is tracked per ISP group. If Gmail's circuit breaker trips, traffic to Microsoft and other providers continues unaffected.

---

## ISP-Aware MX Detection

ApexMail resolves MX records for every recipient domain and classifies them into ISP groups for targeted policy application.

### Detection Logic

1. Resolve MX records for the recipient domain.
2. Match the MX hostnames against known ISP patterns:
   - **Gmail:** `*.google.com`, `*.googlemail.com`
   - **Microsoft:** `*.outlook.com`, `*.protection.outlook.com`, `*.mail.protection.outlook.com`
   - **Yahoo:** `*.yahoodns.net`, `*.yahoo.com`
   - **Apple:** `*.icloud.com`, `*.apple.com`, `*.me.com`
3. Custom domains using ISP-hosted mail (e.g., Google Workspace) are correctly attributed to the underlying ISP.
4. Unknown MX patterns fall back to the `default` policy.

### ISP-Specific Policies

Each ISP group has tailored settings for:

- Warmup schedule (see [IP Warmup Schedules](#ip-warmup-schedules))
- Concurrent SMTP connections (Gmail: 10, Microsoft: 20, Yahoo: 5)
- Messages per connection (Gmail: 10, Microsoft: 50, Yahoo: 10)
- Retry intervals
- TLS requirements

---

## Inbox Placement Testing

Seed list testing provides empirical verification that messages reach the inbox rather than the spam folder.

### How It Works

1. **Seed lists** contain test addresses at major ISPs (Gmail, Microsoft, Yahoo, Apple, and regional providers).
2. Before or during a campaign, a subset of the send volume is directed to seed addresses.
3. ApexMail monitors inbox vs. spam folder placement via IMAP polling.
4. Results are aggregated and surfaced in the deliverability dashboard.

### Seed Test Results

| Metric | Description |
|--------|-------------|
| Inbox rate | Percentage of seeds that received the message in the primary inbox |
| Spam rate | Percentage of seeds that received the message in the spam folder |
| Missing rate | Percentage of seeds that did not receive the message at all |
| ISP breakdown | Per-ISP inbox vs. spam placement |

### Recommendations

- Run seed tests on every new template or sending domain.
- Investigate immediately if inbox placement drops below 90%.
- Use seed tests to validate DNS configuration changes.

---

## Engagement Trust Scoring

ApexMail calculates a per-recipient engagement trust score to optimize send decisions and improve deliverability.

### Scoring Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Opens (last 30 days) | 30% | Frequency of opens relative to messages received |
| Clicks (last 30 days) | 25% | Click-through activity |
| Recency | 20% | Days since last engagement (exponential decay) |
| Complaint history | -15% | Any complaints heavily penalize the score |
| Bounce history | -10% | Soft bounces reduce the score; hard bounces suppress |

### Score Ranges

| Range | Label | Recommendation |
|-------|-------|---------------|
| 80–100 | Highly engaged | Send freely; prioritize in IP warmup |
| 50–79 | Engaged | Normal sending cadence |
| 20–49 | At risk | Reduce frequency; consider re-engagement campaign |
| 0–19 | Disengaged | Exclude from regular campaigns; sunset after re-engagement attempt |

---

## Bot Click Detection

ApexMail identifies non-human click activity to ensure engagement metrics reflect genuine recipient behavior.

### Detection Signals

| Signal | Description |
|--------|-------------|
| Click timing | Clicks within < 1 second of delivery are flagged as automated |
| Multi-link clicks | All tracked links clicked in rapid succession (< 5 seconds between clicks) |
| Known bot user agents | Matches against a curated list of security scanner and link-prefetch user agents |
| IP reputation | Clicks from known proxy/scanner IP ranges |
| TLS fingerprinting | JA3/JA4 fingerprint matches known automated clients |
| Headless browser markers | Missing or inconsistent JavaScript environment indicators |

### Handling

- Bot clicks are recorded but excluded from engagement metrics by default.
- Events are tagged with `"bot_detected": true` in their metadata.
- The engagement trust score ignores bot-attributed interactions.
- Webhook payloads include the `bot_detected` flag so downstream systems can filter accordingly.
- Dashboard analytics provide a toggle to show or hide bot-attributed engagement.
