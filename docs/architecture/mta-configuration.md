# MTA (Mail Transfer Agent) Configuration and Security Guide

> **ApexMail Internal Documentation**
> Last updated: 2026-02-09
>
> **Implementation Note (2026-02):** The MTA is implemented as a Rust crate at `services/mail-server/crates/mta/`. Postfix is not used; SMTP handling is native Rust using the `lettre` and `mail-parser` crates.

This document covers the architecture, security controls, and authentication engine of the ApexMail Mail Transfer Agent (MTA). All **inbound** email processing, sender authentication, and feedback loop handling are managed by this subsystem.

> **Scope:** This document covers the **inbound MTA** only. Outbound email delivery uses a hybrid architecture: AWS SES for shared sending, Hetzner Cloud (self-hosted SMTP) for dedicated IPs. See [Delivery Transport](delivery-transport.md) and [Hybrid Email Infrastructure](hybrid-email-infrastructure.md) for outbound architecture.

---

## Table of Contents

- [MTA Architecture](#mta-architecture)
- [Email Authentication Engine](#email-authentication-engine)
- [DNS Cache](#dns-cache)
- [Inbound Server Security](#inbound-server-security)
- [Bounce Server Security](#bounce-server-security)
- [Feedback Loop Security](#feedback-loop-security)
- [Gmail Annotations](#gmail-annotations)

---

## MTA Architecture

The MTA runs three distinct inbound servers, each responsible for a specific class of incoming SMTP traffic. This separation enforces strict protocol-level isolation between customer mail, bounce notifications, and ISP complaint reports.

### Server Overview

| Server              | Port(s)            | Purpose                                  |
|---------------------|--------------------|-----------------------------------------|
| InboundServer       | 25 (STARTTLS), 465 (implicit TLS) | Receives customer email                |
| BounceServer        | 2525               | Processes DSN bounce notifications      |
| FeedbackLoopServer  | 2526               | Processes ISP complaint (ARF) reports   |

### InboundServer (Ports 25 / 465)

The primary inbound server handles all customer-facing email reception.

- **Port 25**: Accepts connections with optional STARTTLS upgrade (RFC 3207). Advertises `STARTTLS` in the EHLO response and upgrades to TLS upon client request.
- **Port 465**: Implicit TLS (SMTPS). The TLS handshake occurs immediately upon connection — no plaintext phase. This is the preferred submission port for authenticated senders.

Both ports enforce the same authentication and authorization pipeline once a TLS session is established.

### BounceServer (Port 2525)

Dedicated bounce processor that exclusively handles Delivery Status Notification (DSN) messages.

- Accepts only null-sender (`<>`) messages per RFC 5321 §4.5.5.
- Parses VERP (Variable Envelope Return Path) addresses to correlate bounces with original messages.
- Classifies bounce types using RFC 3463 enhanced status codes.

### FeedbackLoopServer (Port 2526)

Processes complaint reports from ISP feedback loops.

- Validates source IPs against a curated list of trusted ISP complaint originators.
- Parses ARF (Abuse Reporting Format, RFC 5965) reports.
- Automatically suppresses recipients who file complaints.

---

## Email Authentication Engine

ApexMail implements a comprehensive email authentication stack that validates inbound messages against all major authentication standards. Each check produces a structured result that feeds into the final disposition decision.

### SPF — Sender Policy Framework (RFC 7208)

Full implementation of SPF record evaluation with support for all defined mechanisms:

| Mechanism   | Description                                              |
|-------------|----------------------------------------------------------|
| `a`         | Match if sender IP is in the domain's A/AAAA records     |
| `mx`        | Match if sender IP is in the domain's MX host A records  |
| `ip4`       | Match against an IPv4 address or CIDR prefix             |
| `ip6`       | Match against an IPv6 address or CIDR prefix             |
| `ptr`       | Reverse DNS match (deprecated but supported)             |
| `include`   | Recursively evaluate another domain's SPF record         |
| `redirect`  | Replace the current SPF record with another domain's     |
| `exists`    | Match if an A record exists for the macro-expanded domain |

**Enforcement rules:**

- **10-DNS-lookup limit**: The engine tracks the cumulative number of DNS lookups across `include`, `a`, `mx`, `ptr`, `exists`, and `redirect` mechanisms. If the count exceeds 10, evaluation terminates with a `permerror` result per RFC 7208 §4.6.4.
- **CIDR matching**: `ip4` and `ip6` mechanisms support CIDR prefix notation (e.g., `ip4:192.168.0.0/16`, `ip6:2001:db8::/32`). The engine performs bitwise prefix comparison against the connecting IP.
- **Void lookup limit**: No more than 2 void (NXDOMAIN/empty) lookups are permitted before returning `permerror`.

**SPF result codes**: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`.

### DKIM — DomainKeys Identified Mail (RFC 6376)

The DKIM engine validates cryptographic signatures embedded in the `DKIM-Signature` header and generates signatures for outbound messages.

**Supported key types:**

| Algorithm | Minimum Key Size | Notes                              |
|-----------|------------------|------------------------------------|
| RSA       | 2048-bit         | Keys below 2048-bit are rejected   |
| Ed25519   | 256-bit          | Elliptic curve — compact, fast     |

**Canonicalization modes:**

| Mode      | Header Treatment                        | Body Treatment                          |
|-----------|-----------------------------------------|-----------------------------------------|
| `simple`  | No modification                         | Trailing whitespace ignored at end only |
| `relaxed` | Lowercase, unfold, compress whitespace  | Ignore trailing whitespace per line     |

The `DKIM-Signature` header specifies the canonicalization as `c=header/body` (e.g., `c=relaxed/simple`). Both orderings are supported.

**Hash algorithms**: `sha256` (preferred), `sha1` (accepted for verification only — not used for signing).

**Verification process:**

1. Extract `DKIM-Signature` header fields (`d=`, `s=`, `b=`, `bh=`, `h=`, `c=`, `a=`).
2. Fetch the public key from DNS: `{selector}._domainkey.{domain}` TXT record.
3. Canonicalize headers and body per the specified mode.
4. Compute the body hash and compare against `bh=`.
5. Verify the RSA/Ed25519 signature in `b=` against the canonicalized header fields.
6. Validate key size (reject RSA keys < 2048 bits).

### DMARC — Domain-based Message Authentication, Reporting & Conformance (RFC 7489)

DMARC ties together SPF and DKIM results with domain alignment checks to produce a policy-based disposition.

**Alignment modes:**

| Mode      | Behavior                                                              |
|-----------|-----------------------------------------------------------------------|
| `strict`  | The identifier domain must exactly match the `From:` header domain    |
| `relaxed` | The identifier domain must share the same organizational domain       |

**Organizational domain resolution:**

When in relaxed mode, the engine determines the organizational domain by consulting the Public Suffix List (PSL). For example, `mail.example.co.uk` resolves to the organizational domain `example.co.uk` because `co.uk` is a registered public suffix.

**Policy values:**

| Policy       | Action                                                        |
|--------------|---------------------------------------------------------------|
| `none`       | Monitor only — no action taken on failures                    |
| `quarantine` | Mark as suspicious (e.g., deliver to spam folder)             |
| `reject`     | Reject the message outright at the SMTP level                 |

The `pct=` tag controls the percentage of failing messages to which the policy applies. Sub-domain policy (`sp=`) is supported as a fallback when no explicit sub-domain DMARC record exists.

### ARC — Authenticated Received Chain (RFC 8617)

ARC preserves authentication results across message forwarding hops where SPF/DKIM may break.

**Validation:**

1. Parse all `ARC-Seal`, `ARC-Message-Signature`, and `ARC-Authentication-Results` header sets.
2. Validate the chain: each instance number (`i=`) must be sequential starting from 1.
3. Verify the `ARC-Seal` signature for each hop.
4. Verify the `ARC-Message-Signature` for the most recent hop.
5. Determine the chain validation status: `pass`, `fail`, or `none`.

**Header generation:**

When ApexMail forwards a message, it appends a new ARC header set with:
- `ARC-Authentication-Results`: The authentication results from this hop.
- `ARC-Message-Signature`: A DKIM-like signature over the message.
- `ARC-Seal`: A signature over all prior ARC-Seal headers plus the current ARC header set.

### BIMI — Brand Indicators for Message Identification

BIMI allows senders to display brand logos alongside authenticated messages in supporting mail clients.

**Validation steps:**

1. **DMARC enforcement check**: The sender's domain must have a DMARC policy of `quarantine` or `reject` (not `none`). DMARC must pass.
2. **BIMI record lookup**: Fetch `default._bimi.{domain}` TXT record containing `v=BIMI1; l={logo_url}; a={vmc_url}`.
3. **SVG Tiny PS validation**:
   - Logo must conform to SVG Tiny Portable/Secure profile.
   - Maximum file size: **32 KB**.
   - **No scripts** (`<script>` tags are forbidden).
   - No external references or embedded raster images.
4. **VMC certificate validation**:
   - Verified Mark Certificate (VMC) must be a valid X.509 certificate.
   - Issued by a BIMI-qualified Certificate Authority.
   - The certified logo must match the SVG in the BIMI record.

### MTA-STS — Mail Transfer Agent Strict Transport Security (RFC 8461)

MTA-STS enables receiving domains to declare that they support TLS and that senders should refuse to deliver mail over unencrypted connections.

**Validation process:**

1. **DNS TXT check**: Look up `_mta-sts.{domain}` for a TXT record containing `v=STSv1; id={policy_id}`.
2. **HTTPS policy fetch**: Retrieve the policy document from `https://mta-sts.{domain}/.well-known/mta-sts.txt`.
3. **Policy evaluation**:

| Mode       | Behavior                                                        |
|------------|-----------------------------------------------------------------|
| `enforce`  | Require valid TLS; refuse delivery on certificate failure       |
| `testing`  | Attempt TLS but deliver anyway on failure; report violations    |
| `none`     | No TLS requirement; policy is deactivated                       |

4. **MX matching**: The policy's `mx:` entries are matched against the resolved MX hosts. Wildcards (e.g., `*.example.com`) are supported.

### TLSRPT — TLS Reporting (RFC 8460)

TLSRPT allows domains to receive reports about TLS connection successes and failures.

- **DNS record**: `_smtp._tls.{domain}` TXT record specifying reporting endpoints.
- **Report format**: JSON reports per RFC 8460, including policy type (MTA-STS, DANE), result types (success, failure reasons), and counts.
- ApexMail generates and sends aggregate TLS reports on a daily cadence to declared `rua=` endpoints.

---

## DNS Cache

All DNS lookups performed by the authentication engine are cached using an in-memory LRU (Least Recently Used) cache.

| Parameter        | Value            |
|------------------|------------------|
| Eviction policy  | LRU              |
| Maximum entries  | 10,000           |
| Default TTL      | 5 minutes        |

- Cache entries respect the DNS response TTL, capped at the configured maximum of 5 minutes.
- Negative responses (NXDOMAIN) are cached with a shorter TTL to allow rapid recovery from transient DNS issues.
- The cache is shared across all authentication checks within a single MTA process.
- Cache statistics (hit rate, eviction count, size) are exposed via the monitoring system.

---

## Inbound Server Security

### SMTP Credential Authentication

SMTP credentials are hashed using **scrypt** (RFC 7914) with the following parameters:

| Parameter   | Value       |
|-------------|-------------|
| Algorithm   | scrypt      |
| N (cost)    | 2^14        |
| r (block)   | 8           |
| p (parallel)| 1           |
| Key length  | 64 bytes    |

Credentials are verified during the SMTP `AUTH` phase. Plaintext passwords are never stored or logged.

### Brute-Force Protection

| Control                     | Configuration                          |
|-----------------------------|----------------------------------------|
| Max attempts                | 5 per minute per IP                    |
| Tracking backend            | Persistent across restarts             |
| Block escalation            | Persistent IP block after threshold    |
| Block storage               | TTL-based expiration                   |

Failed authentication attempts are tracked using a sliding window counter keyed by the connecting IP address. Once the threshold is exceeded, the IP is added to a persistent block list. Blocked IPs receive an immediate `421` rejection at the connection level, before the `AUTH` command is processed.

### Rate Limiting

Rate limits are enforced at multiple levels to prevent abuse:

| Limit                      | Scope              | Description                                 |
|----------------------------|--------------------|--------------------------------------------|
| Connections per IP         | Per source IP      | Maximum concurrent SMTP connections         |
| Messages per connection    | Per SMTP session   | Maximum `MAIL FROM` commands per session    |
| Recipients per message     | Per message        | Maximum `RCPT TO` commands per transaction  |

Limits are configurable per tenant and per plan tier. Exceeding a limit results in a `452` temporary rejection, allowing the sender to retry.

### Sender Validation

Before accepting a message for delivery, the inbound server validates the sender:

1. **Domain ownership**: The `MAIL FROM` domain must belong to a verified domain owned by the authenticated tenant. Unverified or unrecognized domains are rejected with `550 5.7.1`.
2. **Domain verification status**: The domain must have completed DNS verification (SPF, DKIM, and optionally DMARC records confirmed).

### Recipient Validation

Recipient addresses are validated during the `RCPT TO` phase:

1. **Domain existence**: The recipient's domain must exist in the ApexMail system.
2. **Domain verified**: The domain must have passed verification.
3. **Inbound enabled**: The domain must have `accepts_inbound = true` configured. Domains that are outbound-only reject inbound mail with `550 5.1.1`.

Invalid recipients are rejected immediately at the SMTP level — no bounce generation is required for unknown recipients.

### VERP Reply Detection

ApexMail uses Variable Envelope Return Path (VERP) encoding to correlate bounce messages with the original outbound message.

**VERP address format:**

```
bounce+{tenantId}+{messageId}+{recipientHash}@bounce.domain
```

| Component        | Description                                                    |
|------------------|----------------------------------------------------------------|
| `tenantId`       | The tenant that sent the original message                      |
| `messageId`      | The unique identifier of the original outbound message         |
| `recipientHash`  | A truncated hash of the original recipient address             |

When a bounce or reply is received at this address, the MTA parses the VERP components to:
- Identify the originating tenant.
- Look up the original message in the database.
- Associate the bounce with the specific recipient.

---

## Bounce Server Security

The bounce server (port 2525) is purpose-built for DSN processing with strict protocol-level restrictions.

### Null Sender Enforcement

Per RFC 5321 §4.5.5, legitimate bounce messages **must** have a null sender (`MAIL FROM:<>`). The bounce server enforces this absolutely:

- Any `MAIL FROM` with a non-empty address is rejected with `550 5.7.1 Bounce server accepts null sender only`.
- This prevents the bounce server from being used as an open relay or for backscatter amplification attacks.

### VERP Parsing

The `RCPT TO` address is parsed to extract VERP components:

1. Validate the address matches the VERP pattern: `bounce+{tenantId}+{messageId}+{recipientHash}@bounce.domain`.
2. Extract `tenantId`, `messageId`, and `recipientHash`.
3. Look up the original message and recipient in the database.
4. If the VERP address does not parse or the referenced message is not found, the bounce is accepted but logged as unresolvable.

### DSN Parsing and Enhanced Status Codes

Bounce messages are parsed to extract the RFC 3464 Delivery Status Notification content. The enhanced status code from the `Diagnostic-Code` or `Status` field is used for bounce classification per RFC 3463.

### Bounce Classification

Bounces are classified into hard and soft categories based on the enhanced status code:

**Hard bounces** (permanent failures — address will never accept mail):

| Code Range | Category                    | Examples                            |
|------------|-----------------------------|-------------------------------------|
| `5.1.x`    | Address-related             | Mailbox does not exist, bad domain  |
| `5.2.x`    | Mailbox-related             | Mailbox full (permanent), disabled  |
| `5.3.x`    | Mail system-related         | System not capable of delivery      |
| `5.5.x`    | Protocol-related            | Bad command sequence, syntax error  |
| `5.6.x`    | Content-related             | Media not supported                 |
| `5.7.x`    | Security/policy-related     | Sender blocked, authentication required |

**Soft bounces** (temporary failures — retry may succeed):

| Code Range | Category                    | Examples                                |
|------------|-----------------------------|-----------------------------------------|
| `4.x.x`   | All 4xx enhanced codes      | Mailbox full (temp), greylisting, rate-limited |

### Auto-Suppression on Hard Bounce

When a hard bounce is detected:

1. The recipient address is added to the tenant's **suppression list** with the reason `hard_bounce`.
2. Subsequent send attempts to this address are blocked before SMTP submission.
3. A `bounce` webhook event is dispatched to the tenant's configured webhook endpoint.
4. The bounce is recorded in analytics for deliverability reporting.

---

## Feedback Loop Security

The feedback loop server (port 2526) processes ISP complaint reports that indicate a recipient has marked a message as spam.

### Source IP Validation

Inbound connections are validated using a two-step DNS verification process:

1. **Reverse DNS (rDNS)**: Perform a PTR lookup on the connecting IP to obtain the hostname.
2. **Forward DNS confirmation**: Perform an A/AAAA lookup on the PTR hostname and confirm the connecting IP is in the result set.

The resolved hostname is then compared against a curated **trusted ISP list**:

| ISP       | Domain patterns                                |
|-----------|-------------------------------------------------|
| Microsoft | `*.outlook.com`, `*.hotmail.com`                |
| Yahoo     | `*.yahoo.com`, `*.yahoodns.net`                 |
| Google    | `*.google.com`, `*.googlemail.com`              |
| AOL       | `*.aol.com`                                     |
| Comcast   | `*.comcast.net`                                 |

Connections from untrusted IPs are rejected with `554 5.7.1 Unauthorized feedback source`.

### ARF Report Parsing

Complaint reports are parsed per the Abuse Reporting Format (ARF, RFC 5965):

1. Identify the MIME structure: `multipart/report` with `report-type=feedback-report`.
2. Extract the machine-readable `message/feedback-report` part.
3. Parse key fields: `Feedback-Type`, `Original-Mail-From`, `Arrival-Date`, `Source-IP`, `Authentication-Results`.
4. Extract the original message from the `message/rfc822` part (if included).
5. Use the original message headers to correlate with the outbound message (via `Message-ID` or VERP).

### Complaint Types

| Feedback-Type | Description                                      | Action                |
|---------------|--------------------------------------------------|-----------------------|
| `abuse`       | Recipient marked message as spam                 | Suppress + alert      |
| `opt-out`     | Recipient requests removal from mailing list     | Suppress + unsubscribe|
| `fraud`       | Message reported as phishing/fraud               | Suppress + flag       |
| `virus`       | Message reported as containing malware           | Suppress + quarantine |

### Auto-Suppression on Complaint

Every complaint results in immediate suppression:

1. The complainant's address is added to the tenant's **suppression list** with reason `complaint`.
2. The complaint type is recorded for analytics.
3. A `complaint` webhook event is dispatched to the tenant.

### Reputation Tracking

Complaint rates are tracked per tenant and per sending domain:

- **Complaint rate** = complaints / emails delivered (rolling 7-day window).
- **Alert threshold**: An alert is triggered when the complaint rate exceeds **0.1%**.
- Alerts are sent to the tenant via webhook and to the ApexMail operations team via the configured alerting channel.
- Sustained complaint rates above threshold may result in sending throttling or suspension, depending on the tenant's plan and history.

---

## Gmail Annotations

ApexMail supports Gmail Annotations — schema.org JSON-LD markup embedded in email HTML that enables rich rendering in the Gmail Promotions tab.

### Supported Annotation Types

#### DiscountOffer

Displays a promotional offer badge in the Promotions tab.

```json
{
  "@context": "http://schema.org",
  "@type": "DiscountOffer",
  "description": "20% off your next order",
  "discountCode": "SAVE20",
  "availabilityStarts": "2026-02-01T00:00:00-05:00",
  "availabilityEnds": "2026-02-28T23:59:59-05:00"
}
```

#### Product Carousel

Renders a horizontal product carousel in the Promotions tab. Supports up to **10 products** per carousel.

```json
{
  "@context": "http://schema.org",
  "@type": "ItemList",
  "itemListElement": [
    {
      "@type": "ListItem",
      "position": 1,
      "item": {
        "@type": "Product",
        "name": "Product Name",
        "image": "https://example.com/product.jpg",
        "url": "https://example.com/product"
      }
    }
  ]
}
```

Each `ListItem` requires a `position` (1-indexed) and a `Product` with at minimum `name`, `image`, and `url`.

#### ViewAction CTA

Adds a call-to-action button alongside the email in the inbox list.

```json
{
  "@context": "http://schema.org",
  "@type": "ViewAction",
  "url": "https://example.com/landing",
  "name": "Shop Now"
}
```

### Implementation Notes

- JSON-LD is embedded in the email HTML within a `<script type="application/ld+json">` tag in the `<head>`.
- ApexMail validates the JSON-LD against the schema.org vocabulary before injection.
- Annotations are only injected when the recipient domain is `gmail.com` or `googlemail.com`.
- The sending domain must be registered with Gmail's Promotions tab annotations program for annotations to render.
