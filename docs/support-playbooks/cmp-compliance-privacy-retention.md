# CMP — Compliance, Privacy, Retention & Regulatory Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** GDPR/CCPA erasure & export, CAN-SPAM requirements, data retention & zero-retention, DPA requests, sub-processor disclosure, data residency, SOC 2/HIPAA/BAA evidence, accessibility/WCAG, legal holds, encryption evidence.
> **Intent Class:** `CMP.*` — 24 leaf intents
> **Last Updated:** 2026-02-17

---

## ⚠️ Prerequisites — Do NOT duplicate

The following topics are covered **elsewhere** — link rather than repeat:

| Topic | Covered In |
|-------|-----------|
| Unsub link rendering / one-click unsub | `f-bounces-complaints-suppressions.md` (SUP.UNSUB.*) |
| Suppression list management | `f-bounces-complaints-suppressions.md` (SUP.SUPPRESSION.*) |
| Audit log tamper-proof hash chain | `ip-allowlist-security-controls.md` (ACC.AUDIT.*) |
| API key rotation after leak | `ip-allowlist-security-controls.md` (SEC.KEY.*) |
| Message content retention period | `message-diagnostics-retention.md` (D96-D125) |

---

## Reference: Compliance Architecture

```
┌──────────────────────────────────────────────────────┐
│  apps/compliance/src/                                │
│  ├── gdpr/automation.ts     GDPR request lifecycle   │
│  ├── risk/scoring.ts        10-factor risk engine     │
│  ├── content/scanner.ts     Spam/phishing/malware     │
│  ├── audit/hash-chain.ts    Tamper-evident audit log   │
│  └── secrets/manager.ts     AES-256 secret storage    │
│                                                      │
│  Cron jobs: GDPR queue · secret rotation · risk      │
│  reassessment · content scan queue                   │
└──────────────────────────────────────────────────────┘
```

---

## CMP.GDPR.ERASURE_REQUEST — "Customer submitted a GDPR deletion / right-to-be-forgotten request"

**Symptoms:** Customer or their end-user demands all personal data be erased under GDPR Art. 17.

**Resolution:**

1. **Automated path** — ApexMail provides a self-service GDPR automation module (`apps/compliance/src/gdpr/automation.ts`):
   - **Request types:** `access`, `rectification`, `erasure`, `portability`, `consent`.
   - **Workflow:** Create request → email verification (token-based) → queue for processing → execute → complete.
   - A 30-day grace period is enforced before final erasure (configurable via `GDPR_DELETION_GRACE_DAYS`).

2. **Manual trigger via API:**
   ```bash
   curl -X POST https://api.apexmail.ee/v1/compliance/gdpr \
     -H "Authorization: Bearer <ADMIN_KEY>" \
     -H "Content-Type: application/json" \
     -d '{
       "type": "erasure",
       "email": "user@example.com",
       "reason": "GDPR Art. 17 request"
     }'
   ```

3. **What gets deleted:**
   - Subscriber records (name, email, custom fields)
   - Message metadata tied to that recipient
   - Event history (opens, clicks, bounces)
   - Consent records
   - Preferences / suppression entries (moved to anonymized suppression)

4. **What is NOT deleted:**
   - Aggregate analytics (counts, rates) — no PII
   - Audit log entries — required for regulatory compliance; PII is hashed, not stored in plain text
   - Billing records — financial record retention obligation (typically 7 years)

5. **Failure handling:** Failed requests are moved to `gdpr:requests:failed` in Redis. Check:
   ```sql
   SELECT * FROM gdpr_requests
   WHERE status = 'failed' AND tenant_id = '<TENANT_ID>'
   ORDER BY created_at DESC;
   ```

6. **SLA:** Requests must be fulfilled within 30 days per GDPR. The system defaults to processing within 72 hours after the grace period.

---

## CMP.GDPR.EXPORT_REQUEST — "Customer wants a data export / data portability request"

**Symptoms:** End-user requests a copy of all their personal data (GDPR Art. 15 / Art. 20).

**Resolution:**

1. Submit via API:
   ```bash
   curl -X POST https://api.apexmail.ee/v1/compliance/gdpr \
     -H "Authorization: Bearer <ADMIN_KEY>" \
     -d '{ "type": "access", "email": "user@example.com" }'
   ```

2. The system exports:
   - Subscriber profile data
   - All messages sent to that address
   - Event history (delivered, opened, clicked, bounced, complained)
   - Consent records with timestamps
   - Preferences (suppression opt-outs, frequency caps)

3. **Format:** JSON (machine-readable for portability) or CSV. Download link emailed to the requester, valid for **7 days** (configurable via `GDPR_EXPORT_EXPIRATION_DAYS`).

4. **For bulk "portability" (Art. 20):** Use the same endpoint with `"type": "portability"`. The export includes only customer-provided data (not derived/inferred data).

5. **Rate limit:** Max 10 GDPR requests per tenant per cron tick to prevent abuse.

---

## CMP.GDPR.CONSENT_PROOF_MISSING — "Customer cannot prove consent for a recipient"

**Symptoms:** Customer is challenged on whether they have valid consent for a recipient (e.g., after a complaint or regulatory inquiry).

**Resolution:**

1. **Check consent records:**
   ```sql
   SELECT email, consent_type, consent_source, consent_ip,
          consent_timestamp, consent_text, opt_in_method
   FROM consents
   WHERE tenant_id = '<TENANT_ID>' AND email = '<EMAIL>'
   ORDER BY consent_timestamp DESC;
   ```

2. **Expected consent types:** `explicit` (double opt-in), `implicit` (existing relationship), `legitimate_interest`, `contractual`.

3. **If no consent record exists:**
   - The customer must be able to demonstrate legal basis themselves (we store what they send us).
   - Recommend retroactive consent campaigns: send a re-permission email asking existing contacts to re-confirm.
   - If the recipient complained, suppress immediately regardless.

4. **Best practice guidance for customers:**
   - Always pass `consent_source` and `consent_timestamp` when adding subscribers.
   - Use double opt-in (DOI) — ApexMail tracks the confirmation click event.
   - Store the original sign-up form URL and IP address.

---

## CMP.CANSPAM.FOOTER_MISSING — "Email is missing required CAN-SPAM footer / unsubscribe link"

**Symptoms:** Customer's emails are flagged for missing unsubscribe link or physical address. ISPs may filter these to spam.

**Resolution:**

1. **CAN-SPAM Act requirements (16 CFR Part 316):**
   - ✅ Must include a **physical mailing address** (PO Box is acceptable).
   - ✅ Must include a **clear unsubscribe mechanism** (one-click preferred, must work for 30 days after send).
   - ✅ Must honor unsubscribe within **10 business days**.
   - ✅ Subject line must not be deceptive.
   - ✅ Must identify the message as an ad (if commercial).

2. **Content scanner enforcement:** `apps/compliance/src/content/scanner.ts` checks for unsubscribe link presence as part of CAN-SPAM policy compliance. Messages without one receive a policy warning.

3. **Auto-injection:** If the customer's template has `{{unsubscribe_url}}` or `{{{unsubscribe_link}}}`, ApexMail auto-inserts a working one-click unsubscribe link.

4. **If the customer intentionally omits the footer:**
   - Transactional emails (order confirmations, password resets) are exempt from CAN-SPAM's commercial message rules, but still must include the sender's physical address.
   - For commercial/marketing emails, the footer is **mandatory**. Warn the customer.

5. **Fix:** Add to the template:
   ```html
   <p style="font-size:12px; color:#999;">
     {{company_name}} · {{company_address}}<br>
     <a href="{{unsubscribe_url}}">Unsubscribe</a>
   </p>
   ```

---

## CMP.UNSUB.TIMELINE_REQUIREMENT — "How fast must unsubscribes be honored?"

**Symptoms:** Customer asks about regulatory requirements for honoring unsubscribe requests.

**Resolution:**

| Regulation | Requirement |
|-----------|-------------|
| CAN-SPAM (US) | Must honor within **10 business days** |
| GDPR (EU) | Must honor "without undue delay" — practically within **30 days**, but best practice is **immediately** |
| CASL (Canada) | Must honor within **10 business days** |
| PECR (UK) | Immediately upon request |
| Google/Yahoo (2024+ rules) | Must support **RFC 8058 one-click** unsub; must honor within **2 days** |

ApexMail's behavior:
- **One-click List-Unsubscribe:** Adds `List-Unsubscribe` and `List-Unsubscribe-Post` headers automatically. When a mailbox provider fires the one-click POST, the recipient is suppressed **immediately** (within seconds).
- **Link-based unsub:** When the recipient clicks the unsubscribe link in the email body, suppression happens immediately.
- **Manual unsub (API):** `POST /v1/suppressions` takes effect immediately for the next send cycle.

---

## CMP.DATA.RETENTION_POLICY_QUESTION — "What is the data retention policy?"

**Symptoms:** Customer asks how long data is kept, or what happens after retention expires.

**Resolution:**

| Data Type | Hot Retention | Cold Retention | Notes |
|-----------|--------------|---------------|-------|
| Email events (opens, clicks, etc.) | 90 days | 2 years (Parquet) | `apps/analytics/src/` CompactionWorker |
| Message metadata | Plan-dependent (7–730 days) | None | Free: 7 d, Starter: 30 d, Pro: 60 d, Growth: 90 d, Scale: 365 d, Enterprise: 730 d |
| Message body content | Temporary (delivery + retries) | None | Purged after successful delivery or final failure |
| Audit logs | 365 days (default) | Configurable | `apps/compliance/src/audit/hash-chain.ts` |
| GDPR request records | 3 years | None | Required to prove compliance |
| Subscriber/contact data | Until deletion | None | Customer controls via API/dashboard |
| Billing records | 7 years | None | Financial regulation requirement |
| Analytics aggregates | Indefinite | Parquet cold storage | Anonymized, no PII |

**Configuration:** Retention periods are configurable for Enterprise plans. Contact `support@apexmail.ee`.

---

## CMP.DATA.ZERO_RETENTION_REQUEST — "Customer wants zero-retention / no data stored after send"

**Symptoms:** Customer demands that no message content or metadata be stored after delivery.

**Resolution:**

1. **Message body content:** Already NOT stored long-term. Body is processed for delivery/retries and then purged. No change needed.

2. **Message metadata (to, from, subject, timestamps):** Required for:
   - Bounce/complaint processing
   - Suppression management
   - Event webhooks
   - Analytics

3. **Minimum viable zero-retention:**
   - Set retention to shortest plan-available window.
   - Disable open/click tracking (removes pixel & link rewriting).
   - Use webhook delivery for all events → customer stores their own copy → we purge after webhook confirmation.

4. **Enterprise zero-retention mode:** Contact `enterprise@apexmail.ee`. This configures:
   - 24-hour metadata retention (minimum for retry/bounce processing)
   - No analytics storage
   - Immediate purge after final delivery status
   - Webhook-only event delivery (no API event history)

5. **Attachments:** Never stored after delivery. Processed in-memory and discarded.

---

## CMP.DPA.REQUEST_SIGNATURE — "Customer needs a Data Processing Agreement signed"

**Symptoms:** Enterprise/EU customer requires a DPA under GDPR Art. 28.

**Resolution:**

1. **Standard DPA:** Available at `https://apexmail.ee/legal/dpa`. Self-service download and countersign.

2. **DPA covers:**
   - Data processing purpose and scope
   - Sub-processor list (see CMP.SUBPROCESSOR.DISCLOSURE below)
   - Technical and organizational measures (TOMs)
   - Data breach notification procedure (72-hour window)
   - Data deletion/return upon contract termination
   - Audit rights

3. **Custom DPA terms:** Enterprise customers may request modifications. Route to `legal@apexmail.ee`. Typical turnaround: 5–10 business days.

4. **Standard Contractual Clauses (SCCs):** Included in the DPA for international transfers (EU→non-EU). Based on EU Commission Decision 2021/914.

---

## CMP.SUBPROCESSOR.DISCLOSURE — "Customer needs the list of sub-processors"

**Symptoms:** Customer (or their DPA) requires disclosure of all third-party sub-processors who handle personal data.

**Resolution:**

The current sub-processor list is published at `https://apexmail.ee/legal/subprocessors` and includes:

| Sub-processor | Purpose | Location |
|--------------|---------|----------|
| Hetzner Cloud | Infrastructure hosting | Germany (EU) / Finland (EU) |
| PostgreSQL (purpose-built infrastructure) | Primary database | Same region as tenant |
| Redis (purpose-built infrastructure) | Caching, queues | Same region as tenant |
| Cloudflare | CDN, DDoS protection, DNS | Global (US HQ, EU data processing) |
| Stripe | Payment processing | US (SCCs in place) |
| Let's Encrypt | TLS certificate issuance | US (no PII processed) |

**Notification:** Customers subscribed to DPA updates receive 30-day advance notice before any sub-processor change. Object within 30 days or terminate.

---

## CMP.DATA_RESIDENCY.EU_ONLY — "Customer requires EU-only data residency"

**Symptoms:** Customer (usually EU enterprise or public sector) requires that all data processing and storage occurs within the EU.

**Resolution:**

1. **Current infrastructure:** Primary hosting is Hetzner Cloud in Germany and Finland (EU). PostgreSQL, Redis, and application servers all run within EU data centers.

2. **EU-only data path:**
   - ✅ Database: EU (Hetzner DE/FI)
   - ✅ Application servers: EU
   - ✅ Email delivery: Originates from EU IPs
   - ⚠️ CDN/DNS: Cloudflare processes requests globally but can be configured for EU-only resolution
   - ⚠️ Stripe: US-based but processes only billing data (not email content)

3. **For strict EU-only:**
   - Enterprise plan required
   - Cloudflare configured in EU-only mode (no US PoPs)
   - Billing PII minimized (Stripe tokenization, no email content in billing)
   - Confirm with `compliance@apexmail.ee`

4. **Data residency certification:** Available on request for Enterprise customers. References specific Hetzner data center locations and network topology.

---

## CMP.SOC2.EVIDENCE_REQUEST — "Customer needs SOC 2 Type II evidence / audit report"

**Symptoms:** Customer's security team requires SOC 2 evidence for vendor assessment.

**Resolution:**

1. **SOC 2 Type II report:** Available under NDA. Request via `security@apexmail.ee`.

2. **Evidence commonly requested (and where it lives in ApexMail):**

   | Control | Evidence |
   |---------|----------|
   | Access control | RBAC with 5 roles, API key scopes (15 scopes), IP allowlisting |
   | Encryption at rest | AES-256 for secrets (`apps/compliance/src/secrets/manager.ts`) |
   | Encryption in transit | TLS 1.2+ enforced, STARTTLS for SMTP |
   | Audit logging | Tamper-evident hash chain (`apps/compliance/src/audit/hash-chain.ts`) |
   | Incident response | Alerting service with PagerDuty/OpsGenie escalation |
   | Change management | Git-based, PR reviews, CI/CD pipeline |
   | Monitoring | Prometheus + Grafana dashboards, OpenTelemetry tracing |
   | Backup & recovery | PostgreSQL WAL archiving, point-in-time recovery |
   | Vendor management | Sub-processor list, DPA with all vendors |
   | Data classification | PII masking in logs (40+ field patterns) |

3. **CAIQ (Consensus Assessments Initiative Questionnaire):** Pre-filled version available on request.

4. **Penetration test reports:** Annual third-party pentest. Summary available under NDA.

---

## CMP.HIPAA.BAA_REQUEST — "Customer needs HIPAA compliance / BAA"

**Symptoms:** Healthcare customer asks if ApexMail is HIPAA-compliant and whether a Business Associate Agreement (BAA) is available.

**Resolution:**

1. **Current status:** ApexMail can support HIPAA-covered workflows on Enterprise plan with additional configuration:
   - ✅ Encryption at rest (AES-256) and in transit (TLS 1.2+)
   - ✅ Audit logging with tamper-evident hash chain
   - ✅ Role-based access control
   - ✅ Automatic session timeout
   - ✅ Data retention controls
   - ⚠️ BAA available for Enterprise customers

2. **BAA process:**
   - Request via `compliance@apexmail.ee`
   - Covers ApexMail as a Business Associate processing PHI in transactional emails
   - Does NOT cover use of ApexMail for marketing emails containing PHI (not recommended)

3. **HIPAA configuration requirements:**
   - Enable audit logging for all actions
   - Enable encryption for stored data
   - Configure minimum necessary data in email content
   - Set up IP allowlisting for API access
   - Disable open/click tracking if emails contain PHI
   - Configure short retention periods (minimum viable)

4. **Guidance:** Recommend customers do NOT include PHI in email subject lines or plain-text bodies sent through any ESP. Use secure patient portals with email notifications that link to the portal without exposing PHI.

---

## CMP.ACCESSIBILITY.WCAG_QUERY — "Customer asks about email accessibility / WCAG compliance"

**Symptoms:** Customer wants to ensure their emails are accessible to people with disabilities.

**Resolution:**

1. **ApexMail's role:** ApexMail delivers the email; accessibility is primarily a **template design** concern. We provide guidance and tooling.

2. **WCAG 2.1 AA checklist for HTML emails:**

   | Requirement | How to implement |
   |------------|-----------------|
   | Alt text on images | `<img alt="descriptive text">` — never leave alt empty for informational images |
   | Sufficient color contrast | 4.5:1 ratio for body text, 3:1 for large text (18px+) |
   | Semantic HTML | Use `<h1>`–`<h6>`, `<p>`, `<table role="presentation">` for layout tables |
   | Link text is descriptive | "Read our guide" not "Click here" |
   | `lang` attribute | `<html lang="en">` on the root element |
   | Table headers | Data tables need `<th scope="col/row">` |
   | Font size | Minimum 14px body text, 22px+ headings |
   | Don't rely on color alone | Use icons/text in addition to color for status indicators |
   | Keyboard navigation | Not applicable in most email clients (limited support) |

3. **Template engine support:**
   - MJML produces accessible markup by default (proper table roles, responsive breakpoints).
   - Our content scanner (`apps/compliance/src/content/scanner.ts`) can flag missing alt text as a warning.

4. **Testing tools to recommend:** Litmus Accessibility Checker, Email on Acid, axe-core (for web preview), NVDA/VoiceOver manual testing.

---

## CMP.LEGAL.HOLD_REQUEST — "Legal department requires a litigation hold / data preservation"

**Symptoms:** Customer's legal team requires that data related to a legal matter NOT be deleted, even by automated retention policies.

**Resolution:**

1. **Process:**
   - Customer submits a legal hold request via `legal@apexmail.ee` specifying:
     - Tenant ID
     - Date range of data to preserve
     - Scope (all data, specific recipients, specific domains)
     - Expected duration of hold

2. **Implementation:**
   - **Audit logs:** Already tamper-evident (hash chain). Cannot be deleted without breaking the chain.
   - **Message metadata:** Retention override applied — exempt from automated purge.
   - **Event data:** Marked with `legal_hold = true` flag — excluded from compaction/deletion cron.
   - **GDPR interaction:** If an erasure request arrives for data under legal hold, the hold takes precedence. The erasure request is paused and the customer is notified of the conflict.

3. **Release:** When the hold is lifted, customer notifies us. Data then follows normal retention/deletion policies. Any pending GDPR erasure requests are resumed.

4. **Caution:** Legal holds are the customer's responsibility to initiate. ApexMail does NOT auto-detect litigation obligations.

---

## CMP.DATA.ENCRYPTION_EVIDENCE — "Customer asks what encryption is used / needs encryption evidence"

**Symptoms:** Customer's security team asks for details about encryption mechanisms.

**Resolution:**

| Layer | Mechanism | Details |
|-------|-----------|---------|
| **Data in transit (API)** | TLS 1.2+ | HTTPS enforced; HSTS headers; `secureHeaders` middleware |
| **Data in transit (SMTP)** | STARTTLS / implicit TLS | Opportunistic TLS with MTA-STS enforcement; DANE support |
| **Data at rest (secrets)** | AES-256-GCM | `apps/compliance/src/secrets/manager.ts`; per-secret encryption |
| **Data at rest (database)** | Disk-level encryption | Hetzner volume encryption (LUKS) |
| **Audit log integrity** | HMAC-SHA256 | Hash chain with 32+ byte keys enforced in production |
| **Webhook signatures** | HMAC-SHA256 | `{timestamp}.{rawBody}` signed with per-webhook secret |
| **Password storage** | bcrypt / scrypt | Salted hashing, no reversible storage |
| **API keys** | SHA-256 hash | Keys stored as hashes, original not recoverable |
| **DKIM** | RSA-2048 / Ed25519 | Per-domain signing keys |

**Key management:**
- Secret rotation configurable (default 90 days)
- Max 10 key versions retained for rollback
- Access control per-secret with audit trail
- Expired secrets automatically denied access

---

## CMP.GDPR.PROCESSING_LEGAL_BASIS — "What legal basis does ApexMail use for processing?"

**Symptoms:** Customer or DPO asks under what GDPR legal basis ApexMail processes personal data.

**Resolution:**

| Processing Activity | Legal Basis | Notes |
|---------------------|-------------|-------|
| Sending emails on customer's behalf | Art. 6(1)(b) — Contract | Data processor role; customer is controller |
| Billing and invoicing | Art. 6(1)(b) — Contract | Direct customer relationship |
| Fraud/abuse prevention | Art. 6(1)(f) — Legitimate interest | Risk scoring, content scanning |
| Audit logging | Art. 6(1)(c) — Legal obligation | Security and compliance requirements |
| Analytics (aggregated) | Art. 6(1)(f) — Legitimate interest | Anonymized; no individual PII |
| Support ticket processing | Art. 6(1)(b) — Contract | Service delivery |

**Key point:** ApexMail acts as a **Data Processor** (not Controller) for email sending. The customer is the Data Controller and determines the legal basis for their end-users' data.

---

## CMP.INTERNATIONAL.CROSS_BORDER_TRANSFER — "How are international data transfers handled?"

**Symptoms:** Customer asks about data transfer mechanisms for cross-border processing.

**Resolution:**

1. **EU → EU:** No additional mechanism needed. Primary infrastructure is in Germany/Finland.

2. **EU → US (or other non-adequate country):**
   - Standard Contractual Clauses (SCCs) included in the DPA.
   - Based on EU Commission Decision 2021/914 (Module 2: Controller → Processor).
   - EU-US Data Privacy Framework certification (where applicable).

3. **Transfer Impact Assessment (TIA):** Available on request for Enterprise customers.

4. **Minimal data exposure:** Only billing data (Stripe) and CDN edge data (Cloudflare) may leave the EU. Email content and recipient data remain in EU infrastructure.

---

## Decision Tree

```
Customer compliance question
├── Data deletion → CMP.GDPR.ERASURE_REQUEST
├── Data export → CMP.GDPR.EXPORT_REQUEST
├── Consent proof → CMP.GDPR.CONSENT_PROOF_MISSING
├── Missing footer/unsub → CMP.CANSPAM.FOOTER_MISSING
├── Unsub timing → CMP.UNSUB.TIMELINE_REQUIREMENT
├── Retention policy → CMP.DATA.RETENTION_POLICY_QUESTION
├── Zero retention → CMP.DATA.ZERO_RETENTION_REQUEST
├── DPA request → CMP.DPA.REQUEST_SIGNATURE
├── Sub-processor list → CMP.SUBPROCESSOR.DISCLOSURE
├── EU-only hosting → CMP.DATA_RESIDENCY.EU_ONLY
├── SOC 2 report → CMP.SOC2.EVIDENCE_REQUEST
├── HIPAA / BAA → CMP.HIPAA.BAA_REQUEST
├── Accessibility → CMP.ACCESSIBILITY.WCAG_QUERY
├── Legal hold → CMP.LEGAL.HOLD_REQUEST
├── Encryption details → CMP.DATA.ENCRYPTION_EVIDENCE
├── Legal basis → CMP.GDPR.PROCESSING_LEGAL_BASIS
└── Cross-border transfer → CMP.INTERNATIONAL.CROSS_BORDER_TRANSFER
```
