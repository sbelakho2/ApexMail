# IP Pools, Warmup, Dedicated IPs & Infrastructure Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Dedicated IPs, IP warmup, rDNS (PTR), IP pools, blocklist monitoring, MTA-STS, DANE, TLS-RPT, inbound receiving, relay configuration.
> **Last Updated:** 2026-02-16

---

## ⚠️ Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| IP Warmup (rate limiting) | ✅ Implemented | `apps/worker/src/ip-rate-limiter.ts` — gradual volume increase per IP |
| Dedicated IP assignment | ✅ Supported | Provisioned per tenant, configured via control plane |
| IP Pools (multi-IP grouping) | ⚠️ Roadmap | No dedicated IP pool abstraction layer; current architecture is 1 IP per tenant |
| rDNS / PTR records | ✅ Manual setup | Configured at infrastructure level (Hetzner Cloud) |
| Blocklist monitoring | ✅ Partial | MTA checks common blocklists during delivery decisions |
| MTA-STS | ✅ Implemented | `apps/mta/src/mta-sts.ts` — policy fetch and cache |
| DANE / TLSA | ✅ Implemented | `apps/mta/src/auth/dane.ts` — RFC 6698/7671/7672, DNSSEC-secured TLSA validation |
| TLS-RPT | ✅ Implemented | Inbound receiving and parsing of TLS reports |
| Inbound receiving | ✅ Implemented | `apps/mta/src/inbound-server.ts` — ports 25/465 |
| Custom SMTP relay | ⚠️ Partial | Worker sends via Nodemailer to configured SMTP host; not a custom MTA relay |

---

## Reference: IP Architecture

```
Tenant Account
└── Sending IP (dedicated or shared pool)
    ├── IP Rate Limiter (warmup schedule)
    │   └── apps/worker/src/ip-rate-limiter.ts
    ├── rDNS/PTR → Configured at hosting provider
    └── Outbound → Nodemailer → SMTP host
```

### Warmup Schedule (Default)

| Day | Daily Send Limit | Cumulative |
|-----|-----------------|-----------|
| 1 | 50 | 50 |
| 2 | 100 | 150 |
| 3 | 250 | 400 |
| 4 | 500 | 900 |
| 5 | 1,000 | 1,900 |
| 6 | 2,500 | 4,400 |
| 7 | 5,000 | 9,400 |
| 8-14 | 10,000 | ~79,400 |
| 15-21 | 25,000 | ~254,400 |
| 22-28 | 50,000 | ~604,400 |
| 29+ | 100,000+ | Full volume |

---

## Issue E126 — "How to request a dedicated IP"

**Symptoms:** Customer wants to move from shared IP pool to a dedicated IP for reputation isolation.

**Resolution:**
1. **Dedicated IPs are available on Scale and Enterprise plans.**
2. **Request process:**
   - Dashboard → Settings → Dedicated IP → Request.
   - Or contact `contact@apexmail.ee` with the request.
3. **Provisioning timeline:** 1-3 business days. IP is allocated from our clean IP inventory.
4. **Requirements before assignment:**
   - Customer must send > 50,000 emails/month to justify a dedicated IP.
   - A warmup period is mandatory (see E128).
   - rDNS/PTR record will be configured for the customer's sending domain.
5. **Cost:** Included in Scale/Enterprise plans. Additional IPs may incur extra charges.

---

## Issue E127 — "Already have a dedicated IP, want to add more"

**Symptoms:** Customer's volume exceeds what one IP can handle cleanly, or they want separate IPs for transactional vs marketing.

**Resolution:**
1. ⚠️ **IP pool management (grouping multiple IPs with routing rules) is on the roadmap but not yet implemented as a self-service feature.**
2. **Current support:** Additional dedicated IPs can be provisioned manually by the operations team.
3. **Splitting traffic by IP:**
   - Currently requires manual routing configuration by support.
   - Customer can request: "Transactional on IP-A, Marketing on IP-B."
4. **Future:** Self-service IP pools with automatic traffic routing.
5. **Escalate to ops team** for additional IP requests.

---

## Issue E128 — "How does IP warmup work?"

**Symptoms:** Customer is on a new dedicated IP and wants to understand warmup.

**Resolution:**
1. **IP warmup gradually increases sending volume** to build reputation with ISPs.
2. **How it works:** `apps/worker/src/ip-rate-limiter.ts` enforces per-IP daily limits based on the warmup schedule (see table above).
3. **During warmup:**
   - Emails exceeding the daily limit are queued and sent the next day (NOT dropped).
   - Warmup progress is tracked per IP.
   - Customer can monitor progress via Dashboard → Settings → IP → Warmup Status.
4. **Warmup tips:**
   - Start with your most engaged recipients (recent openers/clickers).
   - Maintain consistent daily volume (don't skip days).
   - Monitor bounce rate and spam complaints closely during warmup.
   - If bounce rate > 5% or complaint rate > 0.3%, pause and investigate list quality.
5. **Accelerated warmup:** Enterprise customers can request an accelerated schedule if they have strong engagement data.

---

## Issue E129 — "IP warmup stalled—volume not increasing"

**Symptoms:** Customer is in warmup but the daily limit isn't increasing as expected.

**Root cause:** Warmup progression depends on maintaining good metrics. If bounce or complaint rates are high, warmup can be paused.

**Resolution:**
1. **Check warmup status:**

```sql
SELECT ip_address, warmup_day, daily_limit, current_count, paused, pause_reason
FROM ip_warmup_status
WHERE tenant_id = '<TENANT_ID>';
```

2. **If `paused = true`:**
   - Check `pause_reason`: high bounce rate, high complaints, or manual pause.
   - **Fix:** Address the underlying issue (clean list, improve content), then request warmup resume.
3. **If not paused but volume isn't increasing:**
   - Customer may not be sending enough volume to hit the daily limit.
   - Warmup day advances only when the customer sends at least 80% of the day's limit.
4. **Manual progression:** Support can manually advance the warmup day for customers who demonstrate good sending practices.

---

## Issue E130 — "Warmup schedule too slow for our launch timeline"

**Symptoms:** Customer needs to send 100K+ emails for a product launch in 2 weeks, but warmup takes 4 weeks.

**Resolution:**
1. **Options:**
   a. **Accelerated warmup:** Enterprise customers can request a faster schedule. Requires strong list quality evidence.
   b. **Hybrid approach:** Use shared IPs for the launch volume and warm the dedicated IP in parallel.
   c. **Pre-warmed IP:** In rare cases, ApexMail may have pre-warmed IPs available for immediate assignment (from inventory).
2. **Risks of skipping warmup:**
   - ISPs will block or rate-limit emails from a cold IP.
   - Emails will go to spam.
   - IP reputation damage can take weeks to recover.
3. **Recommendation:** Plan IP provisioning 4-6 weeks before high-volume campaigns.

---

## Issue E131 — "How to set up rDNS/PTR for our dedicated IP"

**Symptoms:** Customer has a dedicated IP but rDNS shows the hosting provider's generic hostname instead of their domain.

**Resolution:**
1. **rDNS (PTR record)** maps an IP address to a hostname. ISPs check rDNS as part of delivery evaluation.
2. **Setup:** PTR records are configured at the hosting provider level (Hetzner Cloud for ApexMail infrastructure).
3. **ApexMail configures rDNS** for each dedicated IP:
   - Default pattern: `mail.yourdomain.com` → IP address.
   - Customer provides their desired hostname.
4. **Requirements:**
   - The hostname must have a matching A record pointing to the IP.
   - Forward DNS (A record) and reverse DNS (PTR) must match.
5. **Verify:**

```bash
# Forward lookup
dig A mail.yourdomain.com +short
# Should return: 1.2.3.4

# Reverse lookup
dig -x 1.2.3.4 +short
# Should return: mail.yourdomain.com.
```

6. **If rDNS doesn't match:** Contact support to update the PTR record.

---

## Issue E132 — "rDNS mismatch causing delivery issues"

**Symptoms:** Emails from dedicated IP are rejected or go to spam. Error messages reference rDNS.

**Root cause:** Forward and reverse DNS don't match, or rDNS shows a generic hostname.

**Resolution:**
1. **ISP requirements:**
   - Gmail: Requires valid rDNS. Generic hostnames (e.g., `server-1234.hetzner.com`) are penalized.
   - Microsoft: Checks rDNS for spam scoring.
   - Yahoo: Requires rDNS.
2. **Check current rDNS:**

```bash
dig -x <YOUR_IP> +short
```

3. **Fix:** Request support to update PTR record to match the customer's sending domain.
4. **Propagation:** PTR record changes can take up to 48 hours to propagate fully.

---

## Issue E133 — "IP on a blocklist (Spamhaus, Barracuda, etc.)"

**Symptoms:** Delivery failures with rejection messages referencing blocklists (e.g., "listed on zen.spamhaus.org").

**Resolution:**
1. **Check blocklist status:**

```bash
# Check Spamhaus
dig +short <REVERSED_IP>.zen.spamhaus.org
# Non-empty result = listed

# Check Barracuda
dig +short <REVERSED_IP>.b.barracudacentral.org

# Or use a multi-blocklist checker
# MXToolbox: https://mxtoolbox.com/blacklists.aspx
```

2. **Common blocklists and delisting:**

| Blocklist | Delisting Process | Timeline |
|-----------|------------------|----------|
| Spamhaus SBL | Manual request at spamhaus.org/sbl/lookup | 24-72 hours |
| Spamhaus XBL | Automated — fix the issue, listing expires | 24 hours |
| Barracuda BRBL | Request at barracudacentral.org/rbl/removal | 12-24 hours |
| SORBS | Request at sorbs.net | 48 hours |
| SpamCop | Automated — expires after complaints stop | 24-48 hours |

3. **Root cause analysis:**
   - Why was the IP listed? Check bounce logs for patterns.
   - High complaint rate from a specific campaign?
   - Compromised account sending spam?
   - Dirty email list (purchased or scraped)?
4. **Immediate actions:**
   - Stop sending from the listed IP (switch to backup / shared).
   - Submit delisting requests.
   - Investigate and fix the root cause BEFORE resuming.
5. **Prevention:** Monitor blocklist status proactively. Set up monitoring via Dashboard → Settings → IP → Blocklist Monitoring.

---

## Issue E134 — "Different blocklist for different ISPs—partial blocking"

**Symptoms:** Emails deliver to Gmail but not to Microsoft (or vice versa). Only some ISPs are rejecting.

**Resolution:**
1. **ISPs use different blocklists:**
   - Gmail: primarily uses internal reputation data, less reliance on third-party blocklists.
   - Microsoft: uses Spamhaus, internal data, and Sender Reputation Data (SRD).
   - Yahoo: uses Spamhaus, internal reputation.
2. **Check all major blocklists** (see E133).
3. **ISP-specific reputation tools:**
   - Gmail: [Google Postmaster Tools](https://postmaster.google.com/) — domain and IP reputation.
   - Microsoft: [SNDS](https://sendersupport.olc.protection.outlook.com/snds/) — Sender Network Data Services.
4. **Fix:** Different ISPs may require different delisting procedures. Address each ISP's requirements individually.

---

## Issue E135 — "How to monitor IP reputation proactively"

**Symptoms:** Customer wants ongoing monitoring, not reactive blocklist responses.

**Resolution:**
1. **Set up monitoring:**
   - Google Postmaster Tools — register your sending domain.
   - Microsoft SNDS — register your sending IP.
   - Dashboard → Settings → IP → Blocklist Monitoring (checks major lists daily).
2. **Metrics to watch:**
   - Bounce rate: keep < 2%.
   - Complaint rate: keep < 0.1% (Gmail threshold: 0.3%).
   - Blocklist status: daily check.
   - Inbox placement: use seed list testing if available.
3. **Alerts:** Configure webhook events for `bounce_rate_alert` and `complaint_rate_alert`.

---

## Issue E136 — "Sending from shared IP—reputation affected by other senders"

**Symptoms:** Customer on shared IP pool experiencing delivery issues due to another sender's bad behavior.

**Resolution:**
1. **Shared IP risk:** All senders on a shared IP share its reputation. One bad sender can affect everyone.
2. **ApexMail mitigations:**
   - Content scanning prevents abusive senders from sending spam.
   - Risk scoring flags problematic accounts.
   - Accounts violating policies are suspended.
3. **If customer is affected:**
   - Check if the issue is IP-related: are bounce messages referencing IP reputation?
   - Escalate to ops team to investigate the shared IP pool.
4. **Long-term fix:** Upgrade to a dedicated IP on Scale/Enterprise plan.

---

## Issue E137 — "Want to send from multiple IPs with load balancing"

**Symptoms:** Customer wants to distribute outbound traffic across multiple IPs.

**Resolution:**
1. ⚠️ **IP pool load balancing is on the roadmap.** Not currently available as self-service.
2. **Current approach:** Manual IP routing configured by ops team:
   - Round-robin across assigned IPs.
   - Traffic split by type (transactional vs marketing).
   - Domain-based routing (different IPs for different sender domains).
3. **Escalate** to ops team for multi-IP configuration.

---

## Issue E138 — "IP pool routing by email type (transactional vs promotional)"

**Symptoms:** Customer wants transactional emails on one IP and promotional on another.

**Resolution:**
1. ⚠️ **Not available as self-service IP pool feature yet.**
2. **Workaround:** Use two separate API keys, each configured with a different sending IP by the ops team.
3. **API request differentiation:** Customer tags sends with `"stream": "transactional"` or `"stream": "promotional"` in the API request. Ops team configures routing based on this.
4. **Why separate IPs?**
   - Transactional emails (password resets, receipts) need high deliverability.
   - If promotional emails damage IP reputation, it shouldn't affect transactional delivery.
5. **Best practice:** Always separate transactional and promotional streams on different IPs once volume justifies it.

---

## Issue E139 — "Failover IP—what happens when primary IP fails?"

**Symptoms:** Customer wants to know the failover behavior if their dedicated IP becomes unavailable.

**Resolution:**
1. **Dedicated IP failover:** If the primary dedicated IP is unreachable (server down), sending is paused — NOT automatically routed to a different IP.
2. **Why not auto-failover?** Switching IPs changes the sender reputation profile. Auto-switching can damage the backup IP's reputation with a sudden volume spike.
3. **Manual failover:** Contact support to switch to a backup IP with proper warmup considerations.
4. **HA architecture:** For enterprise customers requiring high availability, a warm standby IP can be maintained with low-volume traffic to keep reputation warm.

---

## Issue E140 — "MTA-STS policy blocking our delivery"

**Symptoms:** Emails to certain domains fail with TLS-related errors. The receiving domain has an MTA-STS policy.

**Resolution:**
1. **MTA-STS (RFC 8461):** Receiving domain publishes a policy requiring TLS for inbound mail.
2. **ApexMail honors MTA-STS** (`apps/mta/src/mta-sts.ts`):
   - Fetches policy from `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
   - If policy mode is `enforce`: delivery fails if TLS cannot be established.
   - If policy mode is `testing`: delivery proceeds but failures are reported via TLS-RPT.
3. **If delivery fails due to MTA-STS:**
   - Check if our TLS is working: `openssl s_client -connect <our_IP>:25 -starttls smtp`.
   - Check if the MX servers listed in the MTA-STS policy match our delivery target.
   - The issue is usually temporary: remote server's TLS cert expired or misconfigured.
4. **Resolution:** Wait for the remote server to fix their TLS. ApexMail will retry delivery.

---

## Issue E141 — "How to set up MTA-STS for our domain"

**Symptoms:** Customer wants to protect their domain's inbound mail with MTA-STS.

**Resolution:**
1. **MTA-STS requires three things:**
   a. DNS record: `_mta-sts.yourdomain.com TXT "v=STSv1; id=20260216"`
   b. HTTPS policy file: `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`
   c. TLS-RPT DNS record (optional): `_smtp._tls.yourdomain.com TXT "v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com"`

2. **Policy file content:**
   ```
   version: STSv1
   mode: testing
   mx: mx1.yourdomain.com
   mx: mx2.yourdomain.com
   max_age: 604800
   ```
3. **Start with `mode: testing`** to receive reports without blocking delivery.
4. **Only switch to `mode: enforce`** after confirming no legitimate delivery failures in TLS-RPT reports.

---

## Issue E142 — "DANE/TLSA—do you support it?"

**Symptoms:** Customer asks about DANE (DNS-Based Authentication of Named Entities) for TLS verification.

**Resolution:**
1. **DANE/TLSA is fully supported.** ApexMail implements RFC 6698, RFC 7671, and RFC 7672.
2. **What DANE does:** Uses DNSSEC-secured TLSA records to associate TLS certificates with domain names, providing an alternative to CA-based PKI.
3. **DANE modes supported:**
   - **DANE-EE (Usage 3):** End-entity certificate — highest security, recommended
   - **DANE-TA (Usage 2):** Trust anchor assertion
   - **PKIX-EE/PKIX-TA (Usage 0,1):** CA-constrained with DANE validation
4. **Verification with MTA module:**
   ```typescript
   import { verifyDANE, generateTLSARecord } from '@apexmail/mta/auth';
   
   // Verify DANE for a domain
   const result = await verifyDANE('mail.example.com', 25, 'tcp');
   console.log(result.supported);     // true if valid TLSA records + DNSSEC
   console.log(result.mode);          // 'dane-ee' | 'dane-ta' | 'pkix' | 'none'
   console.log(result.tlsaRecords);   // Array of parsed TLSA records
   
   // Generate TLSA record for a certificate
   const tlsa = generateTLSARecord(pemCertificate, 'mail.example.com', {
     port: 25,
     usage: 3,        // DANE-EE
     selector: 1,     // SPKI
     matchingType: 1, // SHA-256
   });
   console.log(tlsa.dnsRecord); // _25._tcp.mail.example.com. IN TLSA 3 1 1 <hash>
   ```
5. **Requirements:** DNSSEC must be enabled for the domain. Use `checkDNSSEC()` to verify.
6. **Outbound delivery:** ApexMail validates TLSA records when DANE is detected and enforces certificate matching.

---

## Issue E143 — "TLS-RPT reports — how to read them and what to do"

**Symptoms:** Customer is receiving TLS-RPT reports and doesn't understand them.

**Resolution:**
1. **TLS-RPT (RFC 8460):** Reports about TLS negotiation failures when others send email to your domain.
2. **Report format (JSON):**
   ```json
   {
     "organization-name": "Google",
     "date-range": { "start-datetime": "...", "end-datetime": "..." },
     "policies": [{
       "policy": { "policy-type": "sts", "policy-string": ["..."] },
       "summary": { "total-successful-session-count": 1234, "total-failure-session-count": 2 },
       "failure-details": [{
         "result-type": "certificate-expired",
         "sending-mta-ip": "1.2.3.4",
         "receiving-mx-hostname": "mx.yourdomain.com"
       }]
     }]
   }
   ```
3. **Common failure types:**
   - `starttls-not-supported`: Sender doesn't support TLS (their problem).
   - `certificate-expired`: Your MX server's cert is expired (your problem).
   - `certificate-host-mismatch`: Cert doesn't match MX hostname (your problem).
4. **Action:** Fix certificate issues on your MX servers. If failures are from senders not supporting TLS, that's their issue.

---

## Issue E144 — "Inbound email receiving setup"

**Symptoms:** Customer wants to receive emails through ApexMail's inbound MTA.

**Resolution:**
1. **Inbound MTA** (`apps/mta/src/inbound-server.ts`) listens on ports 25 and 465.
2. **Setup:**
   a. Point MX records to ApexMail's inbound servers.
   b. Configure inbound processing rules (forwarding, webhook, storage).
3. **MX record:**
   ```
   yourdomain.com MX 10 mx.apexmail.io.
   ```
4. **Inbound processing:**
   - Authentication: SPF, DKIM, DMARC verification on incoming messages.
   - ARC sealing for forwarded messages.
   - Webhook delivery of inbound messages to customer's endpoint.
5. **Available on Scale and Enterprise plans.**

---

## Issue E145 — "Inbound SMTP authentication failing"

**Symptoms:** External senders can't deliver to the customer's domain via ApexMail's inbound MTA.

**Resolution:**
1. **Check MX records:**

```bash
dig MX yourdomain.com +short
# Must point to: mx.apexmail.io.
```

2. **Check inbound domain is configured:** The domain must be registered and verified in ApexMail.
3. **SMTP errors:**
   - `550 5.1.1 User unknown`: The specific mailbox isn't configured for receiving.
   - `550 5.7.1 Not authorized`: Domain not configured for inbound.
   - `421 4.7.0 Rate limited`: Too many connections from the sending IP.
4. **Check inbound configuration:** Dashboard → Domains → Inbound Settings.

---

## Issue E146 — "Outbound relay — how does ApexMail send emails?"

**Symptoms:** Customer wants to understand the delivery architecture.

**Resolution:**
1. **Architecture:**
   ```
   API → Queue (Redis/BullMQ) → Worker → Nodemailer → SMTP relay host
   ```
2. **Worker sends via Nodemailer** (`apps/worker/src/email-sender.ts`):
   - Connects to configured SMTP host.
   - Supports TLS (STARTTLS and direct TLS).
   - Handles connection pooling and retry.
3. **IP assignment:** The SMTP relay host determines which IP is used for outbound delivery.
4. **ApexMail does NOT run a custom SMTP relay server.** It uses Nodemailer as the SMTP client, connecting to configured relay infrastructure.

---

## Issue E147 — "AWS SES fallback — when does it activate?"

**Symptoms:** Customer asks about the SES fallback mentioned in system architecture.

**Resolution:**
1. **AWS SES fallback** is configured as a secondary delivery path:
   - Activates when the primary SMTP relay is unavailable or returns persistent errors.
   - Provides redundancy for critical transactional emails.
2. **Note:** AWS SES fallback uses Amazon's shared IP infrastructure. Emails sent via fallback may have different deliverability characteristics.
3. **Customer impact:** Mostly transparent. The `delivered` event will include delivery metadata indicating which path was used.
4. **For dedicated IP customers:** SES fallback will NOT use their dedicated IP (it uses SES IPs). This is a trade-off: availability vs IP consistency.

---

## Issue E148 — "Want to use our own SMTP relay instead of ApexMail's"

**Symptoms:** Customer wants to route outbound email through their own SMTP infrastructure.

**Resolution:**
1. ⚠️ **Not supported as a self-service feature.** ApexMail manages the delivery infrastructure.
2. **Why:** Using customer's own relay would bypass ApexMail's deliverability optimizations, warmup management, and reputation monitoring.
3. **Alternative:** If customer needs specific relay features, discuss Enterprise custom arrangements with `contact@apexmail.ee`.

---

## Issue E149 — "What ports does ApexMail use for SMTP?"

**Symptoms:** Customer's firewall team needs to know which ports to open.

**Resolution:**

| Direction | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Outbound | 25 | SMTP | Primary delivery (MTA → recipient MX) |
| Outbound | 465 | SMTPS | Implicit TLS delivery |
| Outbound | 587 | Submission | Relay submission (if using relay) |
| Inbound | 25 | SMTP | Receiving inbound email |
| Inbound | 465 | SMTPS | Receiving inbound (implicit TLS) |
| API | 443 | HTTPS | API, dashboard, tracking |

---

## Issue E150 — "Connection timeout when sending—firewall or DNS issue?"

**Symptoms:** Worker reports connection timeouts when trying to deliver email.

**Resolution:**
1. **Check if the recipient's MX is reachable:**

```bash
dig MX recipient-domain.com +short
# Get MX hostname

telnet mx.recipient-domain.com 25
# Should connect within 5 seconds
```

2. **Common causes:**
   - Recipient's MX is down.
   - Our IP is firewalled by the recipient's server.
   - DNS resolution failure (our DNS resolver issue).
   - Network routing issue.
3. **If widespread:** Check our DNS resolver health and network connectivity.
4. **If for one domain:** That domain's mail server is likely down or rate-limiting us.

---

## Issue E151 — "Need to warm up a replacement IP after blocklisting"

**Symptoms:** Customer's dedicated IP was blocklisted and they need a new IP.

**Resolution:**
1. **Recommended approach:**
   a. Request delisting on the original IP (see E133).
   b. During delisting: provision a replacement IP with warmup.
   c. Once replacement is warmed up and original is delisted: choose which to keep.
2. **Replacement IP warmup follows the standard schedule** (see table above).
3. **Parallel warmup:** While the replacement warms up, continue sending limited volume on the original IP (if not fully blocked) to maintain some reputation.
4. **Root cause analysis:** Before switching, understand why the original was blocklisted to prevent recurrence.

---

## Issues E152-E165 — Additional IP/Infrastructure Scenarios

### E152 — "How to check our sending IP's reputation"

```bash
# Google Postmaster Tools: register at postmaster.google.com
# Microsoft SNDS: register at sendersupport.olc.protection.outlook.com
# Spamhaus: check.spamhaus.org
# Sender Score: senderscore.org

# Quick check: reverse DNS
dig -x <IP> +short

# Check if IP is in any blocklist
for bl in zen.spamhaus.org b.barracudacentral.org bl.spamcop.net; do
  result=$(dig +short $(echo <IP> | awk -F. '{print $4"."$3"."$2"."$1}').$bl)
  echo "$bl: ${result:-clean}"
done
```

### E153 — "Can we send from IPv6?"

IPv6 sending is NOT currently supported for outbound delivery. Most ISPs accept IPv6, but reputation systems are less mature for IPv6. Stick with IPv4.

### E154 — "Our IP is rate-limited by Gmail/Microsoft—not blocklisted"

Rate limiting ≠ blocklisting. ISPs rate-limit new or low-reputation IPs. This is normal during warmup. Continue warming up gradually. Don't increase volume until rate limiting stops.

### E155 — "Sending IP changed unexpectedly"

Check if the dedicated IP assignment changed: `GET /v1/account/settings | jq '.sending_ip'`. If using shared IPs: the sending IP can change (that's normal for shared pools). If dedicated IP changed: escalate to ops — possible infrastructure migration.

### E156 — "Need separate IP for different subdomain"

Same as E138 — multiple IPs by type. Subdomain-based routing requires ops team configuration.

### E157 — "Blackhole routing during maintenance"

During scheduled maintenance: outbound delivery is paused (messages queue). No messages are lost. Queue depth may increase temporarily. Normal delivery resumes after maintenance. Check `https://status.apexmail.ee` for maintenance windows.

### E158 — "Connection pooling settings for high volume"

Nodemailer manages connection pooling automatically. Default: 5 concurrent connections per target MX. Enterprise customers can request higher concurrency. Check worker config: `SMTP_POOL_SIZE` and `SMTP_MAX_CONNECTIONS`.

### E159 — "Outbound DKIM signing from which IP?"

DKIM signing is per-domain, not per-IP. The same DKIM key is used regardless of which IP sends the message. The DKIM signature proves the message came from the domain, not from a specific IP.

### E160 — "SPF record for our dedicated IP"

Customer's SPF record must include the dedicated IP: `v=spf1 ip4:<DEDICATED_IP> include:_spf.apexmail.io ~all`. If they only have `include:_spf.apexmail.io`: this covers shared IPs. Dedicated IPs should be explicitly listed OR covered by the include if we update our SPF record.

### E161 — "Can I bring my own IP (BYOIP)?"

⚠️ Not currently supported. ApexMail provisions IPs from our own allocations. BYOIP requires BGP integration and is not on the current roadmap.

### E162 — "Sending volume spike triggers automatic throttling"

Sudden volume spikes (>5x normal volume) trigger automatic throttling to protect IP reputation. Throttling reduces send rate, it doesn't block sends. To avoid: ramp up volume gradually. For planned spikes: notify support in advance for temporary limit increase.

### E163 — "Network egress costs for high-volume sending"

Bandwidth is included in all plans. No per-message network cost. Large attachments (>10MB) may contribute to bandwidth usage at the infrastructure level but are not billed separately.

### E164 — "IPv4 address space — any shortage risks?"

We maintain a sufficient inventory of clean IPv4 addresses. IP provisioning is not affected by general IPv4 exhaustion. Enterprise customers with multi-IP needs should plan ahead (2-4 weeks lead time).

### E165 — "Custom PTR format for compliance requirements"

Custom PTR records can be configured per customer's requirements. Format: `mail.yourdomain.com`, `outbound.yourdomain.com`, etc. The PTR hostname must have a matching forward A record. Contact support for custom PTR configuration.

---

## Troubleshooting Decision Tree

```
IP / Infrastructure Issue
├── Dedicated IP
│   ├── How to request → E126
│   ├── Add more IPs → E127
│   ├── Sending IP changed → E155
│   └── BYOIP → E161
├── Warmup
│   ├── How it works → E128
│   ├── Stalled → E129
│   ├── Too slow → E130
│   └── Replacement IP → E151
├── rDNS / PTR
│   ├── Setup → E131
│   ├── Mismatch → E132
│   └── Custom format → E165
├── Blocklists
│   ├── Listed → E133
│   ├── Partial blocking → E134
│   ├── Proactive monitoring → E135
│   └── Reputation check → E152
├── Shared vs Dedicated
│   ├── Shared IP issues → E136
│   ├── Load balancing → E137
│   ├── Traffic splitting → E138
│   └── Failover → E139
├── TLS / MTA-STS / DANE
│   ├── MTA-STS blocking → E140
│   ├── Setup MTA-STS → E141
│   ├── DANE support → E142
│   └── TLS-RPT reports → E143
├── Inbound
│   ├── Setup → E144
│   └── Auth failing → E145
├── Relay / Architecture
│   ├── Delivery architecture → E146
│   ├── AWS SES fallback → E147
│   ├── Custom relay → E148
│   └── Ports → E149
└── Operations
    ├── Connection timeout → E150
    ├── IPv6 → E153
    ├── ISP rate limiting → E154
    ├── Volume throttling → E162
    └── Maintenance → E157
```

---

## Related

- [Deliverability Triage](deliverability-triage.md) — platform-wide deliverability diagnosis
- [Bounce Investigation](bounce-investigation.md) — bounce analysis
- [B) DKIM/SPF/DMARC](b-dkim-spf-dmarc-correctness.md) — authentication setup
- [Performance Degradation](performance-degradation.md) — system performance
- Internal: `apps/worker/src/ip-rate-limiter.ts` — warmup rate limiting
- Internal: `apps/worker/src/email-sender.ts` — Nodemailer delivery
- Internal: `apps/mta/src/mta-sts.ts` — MTA-STS implementation
- Internal: `apps/mta/src/inbound-server.ts` — inbound receiving
