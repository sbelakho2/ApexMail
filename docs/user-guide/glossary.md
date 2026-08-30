# Glossary

A comprehensive reference of email industry terms, security standards, and ApexMail-specific concepts.

---

## Email Authentication

### SPF (Sender Policy Framework)

A DNS-based email authentication method that specifies which mail servers are authorized to send email on behalf of a domain. Published as a TXT record (for a domain sending through ApexMail's default transport: `v=spf1 include:amazonses.com ~all`; the dashboard generates the exact record for your domain). Receiving servers check the sending IP against the SPF record to detect spoofing.

### DKIM (DomainKeys Identified Mail)

A cryptographic email authentication method that attaches a digital signature to outgoing messages. ApexMail generates a private key per sending domain and publishes its matching public key as a TXT record at `<selector>._domainkey.<domain>`. Receiving servers use that record to verify the signature and detect alteration in transit.

### DMARC (Domain-based Message Authentication, Reporting and Conformance)

A DNS-based policy that builds on SPF and DKIM to tell receiving servers what to do when authentication fails. DMARC policies can be set to `none` (monitor only), `quarantine` (send to spam), or `reject` (block entirely). DMARC also provides aggregate and forensic reporting via the `rua` and `ruf` tags.

### ARC (Authenticated Received Chain)

A protocol that preserves email authentication results across intermediate mail servers (e.g., mailing lists, forwarding services). When an email is forwarded, ARC seals the original SPF/DKIM/DMARC results so the final recipient's server can evaluate the full chain of trust.

### BIMI (Brand Indicators for Message Identification)

A standard that allows senders to display their brand logo next to authenticated emails in supporting inbox providers. Requires a valid DMARC policy (at least `p=quarantine`) and a Verified Mark Certificate (VMC). BIMI records are published as DNS TXT records at `default._bimi.<domain>`.

### MTA-STS (Mail Transfer Agent Strict Transport Security)

A mechanism that allows a domain to declare that it supports TLS for incoming email and that senders should refuse to deliver email over an unencrypted connection. Published via a DNS TXT record and a well-known HTTPS endpoint (`https://mta-sts.<domain>/.well-known/mta-sts.txt`).

### TLSRPT (TLS Reporting)

A standard for receiving aggregate reports about TLS connection successes and failures for email delivery to your domain. Configured via a DNS TXT record at `_smtp._tls.<domain>`. Reports help you identify misconfigured servers or MITM attacks.

---

## Bounces and Delivery

### Hard Bounce

A permanent email delivery failure. The receiving server has definitively rejected the message — typically because the mailbox does not exist (5.1.x), is disabled (5.2.x), or the sender is blocked by policy (5.7.x). Hard-bounced addresses are automatically added to the suppression list in ApexMail.

### Soft Bounce

A temporary email delivery failure. The message could not be delivered right now but may succeed later — typically because the mailbox is full (4.2.x), the server is temporarily unavailable (4.4.x), or greylisting is in effect (4.7.x). ApexMail retries soft bounces with exponential backoff.

### DSN (Delivery Status Notification)

A standardized message (RFC 3464) sent by a receiving or intermediate mail server to report the delivery status of an email. DSNs can indicate successful delivery, temporary failure, or permanent failure. Also known as a "bounce message" or "non-delivery report (NDR)."

### FBL (Feedback Loop)

A mechanism through which mailbox providers (Gmail, Yahoo, Outlook, etc.) report spam complaints back to the sender. When a recipient clicks "Report Spam," the provider sends an ARF-formatted report to the sender's registered FBL address. ApexMail processes FBL reports automatically and suppresses complaining addresses.

### ARF (Abuse Reporting Format)

The standardized message format (RFC 5965) used to report email abuse, including spam complaints. ARF messages contain the original email headers and metadata needed to identify the offending message. Used by FBL systems.

### VERP (Variable Envelope Return Path)

A technique where each outgoing email is given a unique envelope sender address that encodes the recipient's address. When a bounce occurs, the unique return path allows the sender to automatically identify which recipient bounced, without parsing the often-inconsistent bounce message body.

---

## List Management

### Suppression List

A global, account-wide list of email addresses that must never receive email. Addresses are added automatically (hard bounces, spam complaints, unsubscribes) or manually. The suppression list takes precedence over all contact lists and segments. Also known as a "block list" or "exclusion list."

### Warmup (IP and Domain)

The process of gradually increasing email volume on a new IP address or domain to build a positive sending reputation with mailbox providers. Sending too much too fast from a new IP/domain signals spammy behavior. A typical warmup takes 2–4 weeks with incremental volume increases.

---

## Metrics and Analytics

### Deliverability

The ability of an email to reach the recipient's inbox (as opposed to being filtered to spam, bounced, or blocked). Deliverability is influenced by sender reputation, authentication, content quality, and list hygiene.

### Inbox Placement

The percentage of delivered emails that land in the recipient's primary inbox rather than the spam/junk folder. Distinct from delivery rate, which only measures whether the receiving server accepted the message.

### Open Rate

The percentage of delivered emails that were opened by recipients. Calculated as `(unique opens / delivered) × 100`. Note: open tracking relies on a tracking pixel, so it may undercount (image blocking) or overcount (email prefetching by privacy features like Apple Mail Privacy Protection).

### Click Rate

The percentage of delivered emails in which at least one link was clicked. Calculated as `(unique clicks / delivered) × 100`.

### CTR (Click-Through Rate)

Sometimes used interchangeably with click rate. In some contexts, CTR specifically means `(unique clicks / unique opens) × 100` — i.e., of the people who opened the email, how many clicked.

### Bounce Rate

The percentage of sent emails that bounced (hard or soft). Calculated as `(bounces / sent) × 100`. A healthy bounce rate is below 2%. Rates above 5% indicate serious list quality issues.

### Complaint Rate

The percentage of delivered emails that resulted in a spam complaint. Calculated as `(complaints / delivered) × 100`. Mailbox providers expect a complaint rate below **0.1%** (1 per 1,000). Rates above 0.3% can trigger throttling or blocking.

---

## Billing

### PAYG (Pay-As-You-Go)

A billing model where you pay for what you use rather than committing to a fixed monthly plan. In ApexMail, PAYG billing charges per email sent, with no minimum commitment. Usage is tracked and invoiced monthly.

---

## Protocols and Infrastructure

### SMTP (Simple Mail Transfer Protocol)

The standard protocol for sending email between servers. SMTP operates on port 25 (server-to-server), port 587 (submission with STARTTLS), or port 465 (submission with implicit TLS). ApexMail uses SMTP for outbound delivery.

### MTA (Mail Transfer Agent)

The software responsible for routing and delivering email messages between servers using SMTP. ApexMail's MTA handles queue management, retry logic, TLS negotiation, and delivery to recipient servers.

### MX Record (Mail Exchanger Record)

A DNS record that specifies the mail server(s) responsible for receiving email for a domain. MX records include a priority value; lower numbers indicate higher priority. Sending MTAs look up MX records to determine where to deliver email.

### TLS (Transport Layer Security)

A cryptographic protocol that encrypts data in transit between two systems. In the context of email, TLS encrypts the connection between sending and receiving mail servers to prevent eavesdropping. The successor to SSL.

### STARTTLS

An SMTP extension that upgrades a plain-text connection to an encrypted TLS connection on the same port. Unlike implicit TLS (port 465), STARTTLS begins unencrypted and then negotiates encryption. Most modern email servers support STARTTLS on port 25 and 587.

---

## API Concepts

### Idempotency Key

A unique identifier sent with an API request (via the `Idempotency-Key` header) to ensure the operation is only performed once, even if the request is retried. If the same key and request body are sent again, the server returns the original response without re-executing the operation. Keys expire after 24 hours.

### Webhook

An HTTP callback — a POST request that ApexMail sends to your server when a specific event occurs (e.g., email delivered, bounced, opened, clicked, complained). Webhooks enable real-time, event-driven integrations without polling.

### Webhook Signature

An HMAC-SHA256 hash included in the `X-ApexMail-Signature` header of every webhook request. Computed over the raw request body using your webhook's signing secret. You should verify this signature on every incoming webhook to confirm it was sent by ApexMail and was not tampered with.

---

## Service Reliability

### Failed Messages

Messages that could not be delivered after exhausting all retry attempts. In ApexMail, failed messages can be reviewed, retried, or deleted in **Messages → Failed Messages**.

### Rate Limiting

The practice of restricting the number of API requests a client can make within a time window. ApexMail uses rate limiting to protect service stability. Your current limits are communicated via `X-RateLimit-*` response headers on every API response.

---

## AI Features

### STO (Send Time Optimization)

A feature that analyzes each contact's historical engagement patterns (opens, clicks) to determine the optimal time to deliver an email for maximum engagement. Rather than sending to all contacts at the same time, STO staggers delivery per-contact.

### RFM (Recency, Frequency, Monetary)

A customer segmentation model based on three dimensions: how **recently** a contact engaged (Recency), how **often** they engage (Frequency), and how much **value** they represent (Monetary). In ApexMail, RFM analysis feeds into contact scoring and segmentation.

---

## Compliance and Privacy

### CAN-SPAM (Controlling the Assault of Non-Solicited Pornography And Marketing Act)

A U.S. federal law (2003) governing commercial email. Key requirements: include a physical postal address, provide a clear unsubscribe mechanism, honor unsubscribe requests within 10 business days, don't use deceptive subject lines or headers. Violations can result in penalties of up to $51,744 per email.

### GDPR (General Data Protection Regulation)

An EU regulation (2018) governing the processing of personal data of EU residents. Key provisions relevant to email: requires lawful basis for processing (e.g., consent), grants data subjects the right to access, portability, and erasure of their data, and mandates breach notification within 72 hours.

### CCPA (California Consumer Privacy Act)

A California state law (2020) granting residents the right to know what personal data is collected, the right to delete it, and the right to opt out of its sale. Similar in spirit to GDPR but specific to California residents and with different mechanisms.

### HIPAA (Health Insurance Portability and Accountability Act)

A U.S. federal law (1996) governing the protection of health information (PHI). Relevant to ApexMail if you send emails containing health-related data. Requires a Business Associate Agreement (BAA), encryption in transit and at rest, and audit logging.

### DSAR (Data Subject Access Request)

A formal request from an individual exercising their rights under privacy laws (GDPR, CCPA, etc.) to access, export, or delete their personal data. ApexMail provides API endpoints and UI tools to fulfill DSARs for contact data.

---

## Compliance Frameworks and Certifications

### SOC 2 (System and Organization Controls 2)

An auditing framework developed by the AICPA that evaluates a service organization's controls related to security, availability, processing integrity, confidentiality, and privacy (the "Trust Services Criteria"). SOC 2 Type II reports cover a period of time (typically 6–12 months).

### ISO 27001

An international standard for information security management systems (ISMS). ISO 27001 certification demonstrates that an organization has a systematic approach to managing sensitive information, including risk assessment, security controls, and continuous improvement.

### PCI-DSS (Payment Card Industry Data Security Standard)

A set of security standards for organizations that handle credit card data. PCI-DSS compliance requires encryption, access controls, regular vulnerability scanning, and audit logging for cardholder data environments.

---

## Identity and Access Management

### SSO (Single Sign-On)

An authentication mechanism that allows users to log in once and access multiple applications without re-authenticating. ApexMail supports SSO via SAML and OIDC for enterprise accounts.

### SAML (Security Assertion Markup Language)

An XML-based standard for exchanging authentication and authorization data between an identity provider (IdP) and a service provider (SP). Used for enterprise SSO. The IdP authenticates the user and sends a SAML assertion to ApexMail.

### OIDC (OpenID Connect)

An identity layer built on top of OAuth 2.0 that allows clients to verify user identity based on authentication performed by an authorization server. OIDC uses JWT-based ID tokens. ApexMail supports OIDC for SSO and user authentication.

### SCIM (System for Cross-domain Identity Management)

A standard protocol for automating user provisioning and deprovisioning between an identity provider and cloud applications. With SCIM, when a user is added or removed in your IdP (e.g., Okta, Azure AD), the change is automatically reflected in ApexMail.

### RBAC (Role-Based Access Control)

An access control model where permissions are assigned to roles, and roles are assigned to users. ApexMail's RBAC system includes roles such as Owner, Admin, Editor, and Viewer, each with a defined set of permissions for managing domains, templates, contacts, and settings.

---

## Reliability and Operations

### SLA (Service Level Agreement)

A contractual commitment defining the expected level of service, including uptime guarantees, response times, and remedies for breaches. ApexMail's SLA defines uptime targets and credit policies for downtime events.

### SLO (Service Level Objective)

An internal target for a specific aspect of service reliability (e.g., "99.95% API uptime" or "p99 latency < 500ms"). SLOs are typically stricter than external SLAs to provide a safety margin.

### Error Budget

The allowed amount of unreliability over a period, derived from the SLO. For example, a 99.95% uptime SLO allows ~21.6 minutes of downtime per month. Teams use the error budget to balance feature velocity with reliability investment — when the budget is exhausted, focus shifts to stability.

---

## Multi-Tenancy

### Multi-Tenancy

An architecture where a single instance of software serves multiple customers (tenants). Each tenant's data is logically isolated from others. ApexMail is a multi-tenant system where all tenants share the same infrastructure but have complete data isolation.

### Tenant Isolation

The set of mechanisms ensuring that one tenant cannot access another tenant's data or resources. In ApexMail, tenant isolation is enforced at every layer: API authentication, data access, and storage.

### Defense-in-Depth Isolation

A security approach where tenant data isolation is enforced at multiple independent layers. Even if one layer has a bug, other layers prevent cross-tenant data access. ApexMail uses defense-in-depth as a core principle for tenant isolation.
