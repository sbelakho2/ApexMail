+++
title = "Architecture"
description = "ApexMail deployment models, infrastructure architecture, and responsibility matrix."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Deployment Models

Shared EU Cloud is the publicly available deployment model. Dedicated Tenant and BYOC below describe contract-only deployment patterns that may be assessed case by case; they are not public plan entitlements and are not available unless a written agreement confirms the scope, controls, and operations.

### Shared EU Cloud

Multi-tenant infrastructure with an EU/EEA-oriented default deployment configuration. You share compute, network, and IP pools with other ApexMail customers, with logical tenant isolation at the application layer. Active service and telemetry locations are deployment-specific and confirmed under the applicable agreement.

**Ideal for:** Startups, SMBs, and teams who want zero infrastructure responsibility and fast time-to-value.

**Key characteristics:**
- No infrastructure management required.
- Shared IP pools with automatic reputation management.
- 99.9% uptime SLA (Scale and Enterprise, subject to the applicable service terms).
- Pay-as-you-go or committed monthly plans.
- EU/EEA-oriented storage configuration; confirm active regions and transfer safeguards for the deployment.
- Provisioned in minutes.

### Dedicated Tenant

Isolated infrastructure provisioned exclusively for your organization within ApexMail-managed EU data centers. You get dedicated compute, storage, and IP addresses with enhanced controls.

**Ideal for:** Organizations with high volume, regulatory requirements, or the need for custom configurations without managing cloud infrastructure.

**Key characteristics:**
- Dedicated compute, storage, and networking.
- Dedicated IP pool (2+ IPs, managed).
- 99.95% uptime SLA.
- Private networking available.
- Custom maintenance windows.
- Custom backup and retention policies.
- Named technical owner.
- Monthly service reviews.
- Enhanced SLA and support.
- 12-month minimum term.
- Pricing, setup, and service terms are contractual and confirmed during an Enterprise review.

### BYOC (Bring Your Own Cloud)

ApexMail software deployed and operated within your own cloud accounts (AWS, GCP, Azure, or on-premises OpenStack). You control the infrastructure; ApexMail provides the software, deployment automation, and ongoing operations.

**Ideal for:** Organizations with strict data sovereignty requirements, existing cloud commitments, or internal infrastructure mandates.

**Key characteristics:**
- Software deployed in your cloud.
- You control infrastructure, networking, and access.
- ApexMail manages the application layer.
- Customer manages cloud infrastructure, databases, and networking.
- Customer pays cloud costs directly (compute, storage, egress).
- 12–24 month minimum term.
- Pricing, setup, and service terms are contractual and confirmed during an Enterprise review.
- Includes: software license, deployment automation, upgrades, release management, monitoring integration, operational support, deliverability services, architecture reviews, security documentation, incident coordination.

## Responsibility Matrix

The division of responsibilities depends on your deployment model. This matrix maps the eleven key operational areas to ApexMail or Customer responsibility.

| Area | Shared EU Cloud | Dedicated Tenant | BYOC |
|---|---|---|---|
| Application uptime and SLA | ApexMail | ApexMail | ApexMail |
| Infrastructure provisioning | ApexMail | ApexMail | **Customer** |
| Data residency compliance | ApexMail | ApexMail | Shared |
| Security patching (OS, dependencies) | ApexMail | Shared | **Customer** |
| Database administration | ApexMail | ApexMail | **Customer** |
| Network configuration and firewalls | ApexMail | Shared | **Customer** |
| Backup and disaster recovery | ApexMail | ApexMail | Shared |
| Monitoring and alerting | ApexMail | ApexMail | Shared |
| Incident response coordination | ApexMail | Shared | Shared |
| Audit and assessment facilitation | ApexMail | ApexMail | **Customer** |
| Upgrade and release management | ApexMail | ApexMail | ApexMail |

### ApexMail Responsibility

Areas where ApexMail assumes full operational responsibility. No Customer action required.

### Shared Responsibility

Areas where both parties have defined responsibilities. For example, in Dedicated Tenant, security patching is shared: ApexMail patches the application and managed services; the Customer approves and coordinates maintenance windows.

### Customer Responsibility

Areas where the Customer is fully responsible. In BYOC, for example, the Customer manages cloud infrastructure, databases, and networking directly.

## IP Pools

### Shared IP Pools

Shared EU Cloud customers send from ApexMail's shared IP pools:

- Multiple IP addresses across different subnets.
- Automatic load balancing and rotation.
- Reputation monitoring with automatic removal of degraded IPs.
- No configuration or warm-up required.

### Dedicated IPs

Available through the applicable runtime entitlement: an approved Pro add-on, Growth (one included), Scale (three included), and Enterprise (ten included). Private-deployment availability is contractual:

- Exclusive IP addresses not shared with other customers.
- Full control over sending reputation.
- Required warm-up period: 2–4 weeks.
- Minimum 2 IPs recommended for redundancy.
- Manual rotation available via API (Enterprise).

### IP Pool Comparison

| Feature | Shared | Dedicated |
|---|---|---|
| IP exclusivity | No | Yes |
| Warm-up required | No | Yes (2–4 weeks) |
| Reputation control | ApexMail managed | Customer influenced |
| Volume predictability | Varies with pool health | Consistent per-IP capacity |
| Blacklist recovery | Automatic | Manual + support-assisted |
| Recommended for | < 100K emails/month | > 100K emails/month or regulated industries |

## Email Authentication Implementation

ApexMail's MTA (Mail Transfer Agent) implements the full suite of modern email authentication standards.

### SPF (Sender Policy Framework) — RFC 7208

- ApexMail publishes its own SPF record authorizing its sending infrastructure.
- When sending through the AWS SES transport, customer domains include Amazon SES in SPF (`include:amazonses.com`) — see [SPF setup](/domains/spf/) for the exact record the dashboard generates for your domain.
- SPF validation is performed on the return-path (MAIL FROM) domain.
- Custom return-path domains ensure SPF alignment for DMARC.

### DKIM (DomainKeys Identified Mail) — RFC 6376

- The signer rejects RSA keys shorter than 2048 bits.
- DKIM selectors are assigned per sending domain. Copy the exact selector and DNS record from the Domains settings; do not reuse an example selector from another account.
- Signing covers `From`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, and `Content-Type` headers.
- Key changes follow an operational overlap and DNS-propagation procedure; rotation is not represented as an automatic public entitlement.
- `relaxed/relaxed` canonicalization for header and body.
- Customer-managed keys require a separately approved Enterprise arrangement.

### DMARC (Domain-based Message Authentication, Reporting, and Conformance) — RFC 7489

- DMARC builds on SPF and DKIM for domain-level authentication.
- Alignment modes: `relaxed` (default) ensures subdomain matching.
- RUA aggregate reports processed and made available to customers.
- RUF forensic reports supported.

### DANE (DNS-based Authentication of Named Entities) — RFC 6698 / RFC 7672

- TLSA records published for ApexMail's SMTP endpoints.
- DANE verification of recipient MX servers on outbound delivery.
- Provides stronger assurance than opportunistic TLS by binding TLS certificates to DNS.

### MTA-STS (SMTP MTA Strict Transport Security) — RFC 8461

- MTA-STS policy published for `apexmail.ee`.
- Policy enforces TLS for all inbound SMTP connections.
- `mode: enforce` with `max_age` for caching.
- TLSRPT (TLS Reporting, RFC 8460) for TLS failure visibility.

### ARC (Authenticated Received Chain) — RFC 8617

- ARC is applied to forwarded or modified email to preserve original authentication results.
- Useful for email that passes through intermediate MTAs (mailing lists, forwarding services).

### BIMI (Brand Indicators for Message Identification)

- BIMI support enables verified brand logos in supporting email clients (Gmail, Yahoo, Apple Mail).
- Requires DMARC policy at `p=quarantine` or `p=reject`.
- Verified Mark Certificate (VMC) supported for BIMI logo verification.

## Data Flow

```
Sender Application
       │
       ├─ REST API (api.apexmail.ee:443)
       │     └─ Authentication, validation, queuing
       │
       └─ SMTP (smtp.apexmail.ee:587, STARTTLS)
             └─ Authentication, validation, queuing
                    │
              Message Queue
                    │
              MTA Processing
             ├─ DKIM signing
             ├─ Return-path configuration
             ├─ Content modification (tracking pixel, link rewriting)
             ├─ Spam/phishing analysis (outbound)
                    │
              Delivery Attempt
             ├─ Configured delivery provider (self-hosted SMTP or SES integration)
             └─ Provider and region selected by the applicable deployment configuration
                    │
              Recipient Mailbox
                    │
              Delivery Events
             ├─ Webhook POST to customer endpoint
             ├─ Stored in analytics (ClickHouse)
             └─ Available via REST API
```

## Network Architecture

```
Internet
    │
    ├─ DDoS Protection (5-layer defense)
    │   ├─ Layer 3/4: Rate limiting, SYN flood protection
    │   ├─ Layer 7: Request signature analysis, challenge-response
    │   ├─ ML-based anomaly detection
    │   ├─ SMTP state machine protection
    │   └─ Adaptive throttling
    │
    ├─ WAF (Web Application Firewall)
    │   ├─ SQLi detection (AST-based)
    │   ├─ XSS detection (AST-based)
    │   └─ OWASP CRS-compatible rules
    │
    ├─ IDS/IPS (Intrusion Detection/Prevention)
    │   ├─ Signature-based detection
    │   ├─ Protocol anomaly detection
    │   └─ Connection tracking
    │
    ├─ API Gateway / Load Balancer
    │   └─ TLS termination, rate limiting, routing
    │
    ├─ Application Services
    │   ├─ REST API
    │   ├─ SMTP Relay
    │   ├─ Dashboard
    │   └─ Webhook delivery
    │
    └─ Data Layer
        ├─ Relational Database (primary storage)
        ├─ ClickHouse (analytics)
        ├─ Redis (caching, rate limiting, sessions)
        └─ Object Storage (attachments, backups)
```

## Infrastructure Stack

| Layer | Technology |
|---|---|
| Primary compute | EU data centres (dedicated tenancy available on Enterprise) |
| Service deployment | Containerised services, immutable images, automated rolling deploys |
| Operating System | Hardened minimal images with mandatory access control |
| Database | PostgreSQL (primary store), ClickHouse (analytics) |
| Caching | Redis |
| Message Queue | Postgres-backed durable queues with Redis coordination |
| Object Storage | S3-compatible storage (EU region) |
| Monitoring | Prometheus, Grafana, Alertmanager, Loki |
| CI/CD | Automated pipeline with image vulnerability scanning |
| Secrets | Encrypted secret files with rotation; never baked into images |
| Networking | Segmented internal networks; no service-to-service traffic crosses the public internet |

## Geographic Distribution

| Component | Location |
|---|---|
| Primary data center | Deployment-specific; default EEA configuration is confirmed during provisioning |
| Secondary data center | Deployment-specific; backup location is confirmed during provisioning |
| External monitoring probes | Western Europe, Northern Europe, North America |
| Status page hosting | Independent of primary infrastructure |

## Related

- [Security Overview](/security)
- [Compliance Center](/compliance)
- [Privacy Policy](/privacy)
- [Data Processing Agreement](/dpa)
- [Subprocessors](/subprocessors)

## Private Cloud Architecture

### Customer-Owned Cloud Deployment (BYOC)

```
┌─────────────────────────────────────────────────────┐
│                 Customer Cloud Account                │
│  (AWS / GCP / Azure / OpenStack)                     │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │          Customer VPC / Virtual Network      │     │
│  │                                              │     │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────┐ │     │
│  │  │ Compute   │  │ Database │  │ Object    │ │     │
│  │  │ Instances │  │ Cluster  │  │ Storage   │ │     │
│  │  │ (Customer)│  │(Customer)│  │ (Customer)│ │     │
│  │  └────┬─────┘  └────┬─────┘  └─────┬─────┘ │     │
│  │       │              │               │       │     │
│  │       └──────────────┼───────────────┘       │     │
│  │                      │                       │     │
│  │  ┌───────────────────┴───────────────────┐   │     │
│  │  │      ApexMail Application Layer       │   │     │
│  │  │  ┌──────┐ ┌──────┐ ┌──────┐          │   │     │
│  │  │  │ REST │ │ SMTP │ │Queue │          │   │     │
│  │  │  │ API  │ │Relay │ │Proc. │          │   │     │
│  │  │  └──────┘ └──────┘ └──────┘          │   │     │
│  │  │  ┌──────┐ ┌──────┐ ┌──────────┐      │   │     │
│  │  │  │Webhk │ │MTA   │ │Monitoring│      │   │     │
│  │  │  │Deliv.│ │      │ │  Agent   │      │   │     │
│  │  │  └──────┘ └──────┘ └──────────┘      │   │     │
│  │  └───────────────────┬───────────────────┘   │     │
│  │                      │                       │     │
│  │              Customer-Managed                │     │
│  └──────────────────────────────────────────────┘     │
│                                                       │
│  Customer DNS ─── Ingress ─── WAF ─── LB              │
│                                                       │
└───────────────────────┬─────────────────────────────┘
                        │
                        │ Encrypted control channel
                        │ (mutual TLS)
                        │
┌───────────────────────┴─────────────────────────────┐
│              ApexMail Control Plane                   │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Release  │  │ License  │  │ Incident          │   │
│  │ Registry │  │ Manager  │  │ Coordination      │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Upgrade  │  │Telemetry │  │ Support           │   │
│  │ Pipeline │  │Collector │  │ Ticketing         │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
│                                                       │
│  Configured EU/EEA Data Center                         │
└───────────────────────────────────────────────────────┘

Trust boundaries:
─── Trust boundary (Customer | ApexMail)
Internet-facing: Ingress, WAF, LB
Private: Compute, Database, Queue, MTA
Customer-controlled: Cloud account, networking, IAM, encryption keys
ApexMail-controlled: Application layer, upgrades, monitoring, incident coordination
```

### ApexMail-Managed Dedicated Deployment (Dedicated Tenant)

```
┌─────────────────────────────────────────────────────┐
│            ApexMail EU Data Center                    │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │        Customer-A Dedicated Tenant           │     │
│  │                                              │     │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────┐ │     │
│  │  │ Compute  │  │ Database │  │ Object    │ │     │
│  │  │ (Dedic.) │  │(Dedicated│  │ Storage   │ │     │
│  │  │          │  │ Instance)│  │ (Dedic.)  │ │     │
│  │  └────┬─────┘  └────┬─────┘  └─────┬─────┘ │     │
│  │       │              │               │       │     │
│  │  ┌────┴──────────────┴───────────────┴────┐  │     │
│  │  │    Dedicated Application Instance      │  │     │
│  │  │    API │ SMTP │ Queue │ MTA │ Webhk   │  │     │
│  │  └────────────────────┬───────────────────┘  │     │
│  │                       │                      │     │
│  │  ┌────────────────────┴───────────────────┐  │     │
│  │  │   Dedicated IP Pool (2+ IPs)           │  │     │
│  │  │   Dedicated Monitoring Dashboard       │  │     │
│  │  │   Customer-Managed Encryption Keys     │  │     │
│  │  └────────────────────────────────────────┘  │     │
│  │                                              │     │
│  │  ApexMail-Managed Infrastructure            │     │
│  └──────────────────────────────────────────────┘     │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │        Customer-B Dedicated Tenant           │     │
│  │        (separate compute, storage, IPs)      │     │
│  └─────────────────────────────────────────────┘     │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │          Shared Infrastructure               │     │
│  │  Monitoring │ Backup │ DNS │ DDoS Protection │     │
│  └─────────────────────────────────────────────┘     │
│                                                       │
│  Customer DNS ─── Ingress ─── DDoS ─── WAF ─── LB    │
│                                                       │
└───────────────────────────────────────────────────────┘

Trust boundaries:
Customer-dedicated: Compute, Database, Storage, Application, IP Pool
ApexMail-managed: Infrastructure patching, monitoring, backups
Shared (ApexMail): DDoS protection, DNS infrastructure, WAF
Encryption boundary: Data at rest (customer-managed keys available)
```

## Private Cloud Components by Responsibility

| Component | Shared EU Cloud | Dedicated Tenant | BYOC |
|---|---|---|---|
| Cloud account | ApexMail | ApexMail | Customer |
| Compute instances | Shared | Dedicated | Customer |
| Database | Shared (logically isolated) | Dedicated instance | Customer-managed |
| Message queue | Shared (logically isolated) | Dedicated | Customer-managed |
| Application code | Shared (logically isolated) | Dedicated instance | Customer-deployed (ApexMail-managed) |
| Control plane | Shared | Shared | Shared (ApexMail) |
| IP pools | Shared | Dedicated | Customer-provisioned |
| Encryption keys | ApexMail-managed | Customer-managed (optional) | Customer-managed |
| Monitoring | Shared dashboard | Dedicated dashboard | Shared visibility |
| Backups | ApexMail-managed | ApexMail-managed | Customer-managed |
| Upgrade path | Automatic | Customer-approved | Customer-approved |
| Root access | ApexMail only | ApexMail only (with customer approval) | Customer has root |
| Outbound internet | Required | Required | Customer network policy |

## Private Cloud Disaster Recovery and Failover

### Backup Architecture
- **Frequency:** Daily full backups; transaction log backups every 15 minutes.
- **Retention:** 30 days standard; configurable up to 730 days (Enterprise).
- **Geographic separation:** Backup location is selected by the active deployment configuration and confirmed during provisioning.
- **Encryption:** AES-256 at rest; TLS 1.2+ in transit.
- **Verification:** Quarterly automated restore tests.

### Disaster Recovery Targets
- **RPO (Recovery Point Objective):** 15 minutes (transaction log shipping).
- **RTO (Recovery Time Objective):** 60 minutes (automated failover and restore).
- **DR testing:** Quarterly full restore tests with results shared with Enterprise customers.
- **Multi-region:** Regional routing and failover scope are deployment- and agreement-specific. Cross-region failover is a planned capability for Dedicated Tenant — not yet live. Multi-region active-active is not currently offered.

### High Availability

The standard shared deployment runs on a single EU host with:

- Health-checked services with automatic restart and automated rollback deploys.
- Queue and message persistence to disk (PostgreSQL WAL) — no in-flight mail is lost to a service restart.
- Daily encrypted backups with verified restore (see Backup Policy above).
- Management-plane redundancy (replication, multi-node failover) is available on Dedicated Tenant deployments under a separate agreement.

We do not claim multi-region active-active availability on the shared plans. If your workload requires it, ask about Dedicated Tenant.
