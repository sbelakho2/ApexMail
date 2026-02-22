# G) Deliverability & Inbox Placement Playbook (Issues 94–108)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Inbox placement, sender reputation, content optimization, and deliverability best practices.

---

## Reference: Deliverability Benchmarks

| Metric | Good | Needs Work | Critical |
|--------|------|------------|----------|
| Open rate | > 20% | 10–20% | < 10% |
| Click-through rate | > 2% | 1–2% | < 1% |
| Bounce rate | < 2% | 2–5% | > 5% |
| Complaint rate | < 0.1% | 0.1–0.3% | > 0.3% |
| Unsubscribe rate | < 0.5% | 0.5–1% | > 1% |

**Industry average:** Open rate ~21.5%, CTR ~2.3%, Email ROI $36 per $1 spent.

**IP Warmup Schedule (dedicated IPs):**
Warmup is **ISP-specific** and enforced daily by `apps/worker/src/services/ip-rate-limiter.ts`. Approximate rough guidance (Gmail/Yahoo are strictest, starting at 50/day; Microsoft allows 100/day from day 1). Full schedules are in the [IP Pools & Warmup Playbook](ip-pools-warmup-infrastructure.md). Typical trajectory to full volume: ~14 days for Microsoft, ~15+ days for Gmail.

---

## Issue 94 — New domain/IP has poor inbox placement

**Symptoms:** Customer just set up their account, sent their first campaign, and emails are going to spam or being blocked.

**Root cause:** New domains and IPs have no reputation. ISPs treat unknown senders with suspicion.

**Resolution:**
1. This is expected behavior for new senders. ISPs use a "guilty until proven innocent" model.
2. Action plan:
   - Complete warmup schedule (see reference table above).
   - Start by sending to your most engaged recipients.
   - Send content that drives engagement (opens, clicks, replies).
   - Set up all authentication records: SPF, DKIM, DMARC, Return-Path.
   - Register with postmaster tools (Google Postmaster Tools, Microsoft SNDS).
3. Building reputation takes 2–4 weeks of consistent, well-received email.
4. During warmup: avoid large blasts, purchased lists, or promotional-heavy content.

---

## Issue 95 — Emails landing in Gmail Promotions tab instead of Primary

**Symptoms:** Customer's emails are delivered but recipients say they're in the Promotions tab.

**Root cause:** Gmail categorizes emails into tabs (Primary, Social, Promotions, Updates) based on content, formatting, and sender behavior.

**Resolution:**
1. Explain: "The Promotions tab is NOT spam. Emails in Promotions are delivered successfully. Many users regularly check this tab."
2. Factors that push to Promotions:
   - HTML-heavy formatting with lots of images
   - Marketing language ("sale," "limited time," "buy now")
   - Multiple links and CTAs
   - Tracking pixels and click tracking
   - Use of email marketing platform (detected via headers)
3. To improve Primary placement:
   - Use simpler, text-like formatting
   - Reduce image-to-text ratio
   - Include conversational language
   - Ask recipients to "star" or reply (engagement signals)
4. ApexMail cannot force Gmail categorization — it's Gmail's algorithm.

---

## Issue 96 — Tracking domain mismatch causing deliverability issues

**Symptoms:** Click-tracked links show a different domain (e.g., `t.apexmail.ee`), causing ISP suspicion or recipient distrust.

**Root cause:** ApexMail rewrites URLs for click tracking. If the customer hasn't set up a custom tracking domain, the default ApexMail domain is used, which can look suspicious.

**Resolution:**
1. Set up a custom tracking domain:
   - Customer adds CNAME: `track.yourdomain.com → t.apexmail.ee`
   - Configure in Dashboard → Settings → Tracking Domain
2. Benefits of custom tracking domain:
   - Links match the sender's domain (builds trust)
   - Improves deliverability (ISPs see consistent domains)
   - Looks professional to recipients
3. Without custom tracking domain: links show `t.apexmail.ee` which recipients may not recognize.
4. Ensure the tracking domain has valid SSL (auto-provisioned by ApexMail via CNAME).

---

## Issue 97 — URL shorteners (bit.ly, tinyurl) in email content

**Symptoms:** Emails with shortened URLs are going to spam or being blocked.

**Root cause:** Spammers heavily abuse URL shorteners to hide malicious destinations. ISPs penalize their use.

**Resolution:**
1. Explain: "URL shorteners are a major spam signal. Most ISPs (Gmail, Microsoft, Yahoo) penalize or block emails containing bit.ly, tinyurl, and similar services."
2. Solution: use full URLs in email content. ApexMail's click tracking provides analytics without needing URL shorteners.
3. Shortened URLs that are acceptable:
   - Custom-branded short domains owned by the customer (e.g., `yourbrand.link/xyz`)
4. Even branded short domains can trigger some filters — full URLs are always safest.
5. If customer needs to track specific URLs: ApexMail's built-in click tracking handles this automatically.

---

## Issue 98 — HTML-to-text ratio issues

**Symptoms:** Emails with heavy HTML, many images, and little text land in spam.

**Root cause:** ISPs analyze the ratio of HTML/images to text. Image-heavy emails with minimal text are a spam signal (image-only emails are used to bypass text-based filters).

**Resolution:**
1. Best practices:
   - Maintain at least 60% text to 40% images (by visual weight).
   - Always include a plain-text alternative (MIME multipart).
   - Don't use a single large image as the entire email body.
   - Include meaningful text content, not just image placeholders.
2. A multipart MIME email should have both `text/plain` and `text/html` parts.
3. ApexMail auto-generates plain text from HTML if not provided, but customer-provided plain text is better.
4. Image hosting: host images on a reputable domain, not free hosting services.

---

## Issue 99 — Missing List-Unsubscribe header

**Symptoms:** Gmail or Yahoo rejecting emails or marking them as spam due to missing List-Unsubscribe header.

**Root cause:** Gmail and Yahoo require one-click unsubscribe for bulk senders (Gmail: > 5,000 emails/day). Without `List-Unsubscribe`, emails may be filtered or rejected.

**Resolution:**
1. ApexMail automatically adds `List-Unsubscribe` and `List-Unsubscribe-Post` headers to marketing/promotional emails.
2. If customer is sending via raw API and not seeing these headers:
   - Ensure the send is tagged as "marketing" (not transactional).
   - Check that the sending domain has a configured unsubscribe endpoint.
3. Requirements (Gmail Feb 2024 bulk sender guidelines):
   - `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header
   - `List-Unsubscribe: <https://...>` header
   - One-click functionality (no confirmation page)
4. For transactional emails: `List-Unsubscribe` is NOT required and should not be added.

---

## Issue 100 — Spam trigger words in subject or body

**Symptoms:** Emails with certain words/phrases land in spam consistently.

**Root cause:** ISP content filters scan for patterns associated with spam.

**Resolution:**
1. Common content triggers to avoid:
   - ALL CAPS in subject lines ("FREE OFFER!!!")
   - Excessive punctuation (!!!, ???, $$$)
   - Spam phrases: "Act now", "Limited time", "Buy now", "Click here", "Congratulations"
   - Urgency manipulation: "Your account will be suspended"
   - Money/prize language: "Win $1000", "Earn money fast"
2. Modern ISPs weigh sender reputation MORE than content, but content still matters:
   - Bad subject + good reputation = probably fine
   - Bad subject + new/poor reputation = likely spam
3. Recommendations: write naturally, use sentence case, avoid hype language, focus on value.
4. A/B test subject lines (available on Pro+ plans) to optimize engagement.

---

## Issue 101 — Blocklist investigation (Spamhaus, Barracuda, SpamCop, SORBS)

**Symptoms:** Sudden email rejections across multiple ISPs. Bounce messages reference a blocklist.

**Root cause:** IP or domain has been listed on a DNS-based blocklist (DNSBL).

**Resolution:**
1. Check these blocklists:
   - **Spamhaus SBL/XBL**: https://check.spamhaus.org — most impactful
   - **Barracuda BRBL**: https://barracudacentral.org/lookups
   - **SpamCop**: https://www.spamcop.net/bl.shtml
   - **SORBS**: http://www.sorbs.net/lookup.shtml
2. If listed:
   - Identify the cause (high bounces, complaints, spam trap hits).
   - Fix the root cause FIRST.
   - Submit delisting request to each blocklist.
   - Spamhaus: typically auto-delists after 1 week if issue resolved.
   - Barracuda: submit removal request via web form.
3. On shared IPs: another sender may have caused the listing — contact `contact@apexmail.ee`.
4. On dedicated IPs: the customer's own practices caused it — address root cause.

---

## Issue 102 — Customer's replies/engagement are low

**Symptoms:** Open rates below 10%, click rates near 0%. Customer asks "why isn't my email working?"

**Root cause:** Low engagement is a complex problem: list quality, content relevance, timing, frequency, or reputation.

**Resolution:**
1. Diagnose systematically:
   - **List health**: when were these addresses collected? Double opt-in? How old?
   - **Content**: is it relevant to recipients? Does the subject line compel opens?
   - **Timing**: test different send times and days.
   - **Frequency**: too many emails → fatigue → complaints. Too few → forgotten → spam reports.
   - **Authentication**: all SPF/DKIM/DMARC passing? (See Section B)
   - **Placement**: are emails in spam? (See Issue 85)
2. Quick wins:
   - Segment list by engagement (active vs inactive).
   - Re-engage inactive with a targeted campaign.
   - Clean list of addresses that haven't opened in 90+ days.
   - A/B test subject lines (Pro+ plans).
3. Industry benchmarks: open rate ~21.5%, CTR ~2.3%.

---

## Issue 103 — MIME structure issues (missing multipart)

**Symptoms:** Email displays incorrectly in some clients, or deliverability is reduced.

**Root cause:** Email is sent as HTML-only without a plain-text alternative, or the MIME structure is malformed.

**Resolution:**
1. Best practice: always send multipart/alternative with both text/plain and text/html parts.
2. ApexMail API supports:
   - `html` field: HTML content
   - `text` field: plain text content
   - If only `html` is provided: ApexMail auto-generates a plain text version.
3. Providing both parts:
   - Improves deliverability (ISPs prefer multipart).
   - Ensures readability in text-only email clients.
   - Plain text version is used for accessibility.
4. MIME structure should be:
   ```
   multipart/mixed
   ├── multipart/alternative
   │   ├── text/plain
   │   └── text/html
   └── attachments (if any)
   ```

---

## Issue 104 — Customer's email content triggers phishing detection

**Symptoms:** Emails blocked or flagged as phishing. Bounce includes "suspected phishing" or similar.

**Root cause:** Email content resembles phishing patterns — login links, password reset language, mismatched URLs, or impersonation signals.

**Resolution:**
1. Common triggers:
   - Link text says "yourbank.com" but href goes to different domain.
   - Language like "Verify your account," "Confirm your identity," "Update your payment."
   - Urgency: "Your account will be closed in 24 hours."
   - Mismatched From domain and link domains.
2. Solutions:
   - Ensure link text matches actual destination (or use generic text like "Click here").
   - Align all domains: From, links, tracking, Reply-To.
   - Avoid password/account/login language in marketing emails.
   - If legitimate (password resets, etc.): ensure strong authentication (pass DKIM, SPF, DMARC with p=reject).
3. For transactional emails (password resets): strong auth + consistent sending patterns reduce false positives.

---

## Issue 105 — Spam trap hits

**Symptoms:** Sudden reputation drop. No obvious cause from bounce/complaint rates.

**Root cause:** Customer is sending to spam trap addresses — either recycled (abandoned addresses repurposed) or pristine (addresses that never belonged to real people).

**Resolution:**
1. Explain: "Spam traps are email addresses operated by ISPs and blocklist operators to catch senders with poor list hygiene."
2. Types:
   - **Pristine traps**: Never belonged to a real person. Presence on your list means you scraped or purchased addresses.
   - **Recycled traps**: Former real addresses, abandoned, then repurposed as traps. Means your list hasn't been cleaned.
3. You can't identify specific spam traps (they're not disclosed).
4. Solutions:
   - Implement double opt-in for all new subscribers.
   - Regularly clean list (remove addresses with no engagement in 90+ days).
   - Never purchase or scrape email lists.
   - Use email validation services before importing lists.
5. Recovery: clean the list aggressively, send only to highly engaged recipients, rebuild reputation over 2–4 weeks.

---

## Issue 106 — Customer wants a deliverability audit

**Symptoms:** Customer requests a comprehensive review of their email deliverability.

**Root cause:** Customer is experiencing poor inbox placement, low engagement, or preemptively wants optimization.

**Resolution:**
1. Self-service audit checklist:
   - **Authentication**: SPF, DKIM, DMARC all passing? Check Dashboard → Domain Health.
   - **Reputation**: Check Google Postmaster Tools, Microsoft SNDS, blocklist status.
   - **Content**: review for spam triggers, HTML/text ratio, link quality.
   - **List hygiene**: bounce rate < 2%? Complaint rate < 0.1%? Recent list cleaning?
   - **Engagement**: open rate > 20%? CTR > 2%?
   - **Infrastructure**: custom tracking domain? Dedicated IP warmed up?
   - **Compliance**: List-Unsubscribe header? Unsubscribe link visible? CAN-SPAM/GDPR compliant?
2. Available resources:
   - Dashboard → Analytics for metrics.
   - Dashboard → Domain Health for authentication status.
   - Google Postmaster Tools for Gmail-specific reputation.
3. For Enterprise customers: dedicated deliverability consulting is available — contact `contact@apexmail.ee`.

---

## Issue 107 — IP reputation vs domain reputation confusion

**Symptoms:** Customer asks "is it my IP or my domain causing problems?"

**Root cause:** Both IP and domain reputation affect deliverability. ISPs weigh them differently.

**Resolution:**
1. Explain the difference:
   - **IP reputation**: reputation of the sending IP address. Affected by volume, bounces, complaints from that IP.
   - **Domain reputation**: reputation of the From domain. More persistent; follows the domain regardless of IP changes.
2. Modern ISPs (Gmail especially) weight domain reputation MORE than IP reputation.
3. Shared IP: ApexMail manages IP reputation collectively. Poor senders are isolated/suspended.
4. Dedicated IP (Growth+ plan): customer fully controls IP reputation. Requires warmup.
5. Diagnosis:
   - Google Postmaster Tools: shows both IP and domain reputation separately.
   - If domain reputation is bad: content, list, or authentication issues.
   - If IP reputation is bad but domain is fine: probably a shared IP neighbor (or warmup needed).

---

## Issue 108 — Customer wants to send from multiple IPs

**Symptoms:** Customer asks for multiple dedicated IPs, or asks about IP pools.

**Root cause:** Large senders sometimes separate transactional and marketing email on different IPs to isolate reputation.

**Resolution:**
1. Dedicated IPs are available on Growth ($150/mo — 1 IP), Scale ($350/mo — 3 IPs), and Enterprise ($800/mo — 10 IPs) plans.
2. Use cases:
   - Separate transactional (password resets, receipts) from marketing (newsletters, promotions).
   - Isolate high-risk sends (re-engagement campaigns) from core sends.
3. Setup: contact `contact@apexmail.ee` to request additional IPs and configure pools.
4. Each IP needs independent warmup.
5. Free ($0) and Starter ($25/mo) plans use shared IP pools managed by ApexMail. Pro ($65/mo) uses shared IPs by default but can add a dedicated IP ($30/mo add-on).

---

## DLV.ISP — ISP-Specific Deliverability Issues

### DLV.ISP.YAHOO_BLOCK — "Emails to Yahoo/AOL/Verizon Media going to spam or blocked"

**Symptoms:** Deliverability to `@yahoo.com`, `@aol.com`, `@verizon.net` suddenly drops. May see `421 4.7.0 [TS03]` or `553 5.7.1` errors.

**Root cause:** Yahoo enforces strict DMARC, engagement-based filtering, and aggressive complaint handling.

**Resolution:**

1. **Yahoo's 2024+ requirements:**
   - ✅ Valid SPF **and** DKIM (both required)
   - ✅ DMARC with `p=none` minimum (Yahoo enforces sender's DMARC policy)
   - ✅ `List-Unsubscribe` + `List-Unsubscribe-Post` headers (RFC 8058 one-click)
   - ✅ Spam complaint rate < **0.3%** (measured via Yahoo CFL — Complaint Feedback Loop)
   - ✅ rDNS (PTR) must match sending hostname

2. **Yahoo CFL (Complaint Feedback Loop):**
   - Sign up at `https://senders.yahooinc.com/` → Feedback Loop
   - ApexMail processes FBL reports via `apps/mta/src/servers/feedback-loop.ts` (ARF parsing)
   - Check complaint rate:
     ```sql
     SELECT COUNT(*) FILTER (WHERE type = 'complaint') * 100.0 / COUNT(*) as complaint_pct
     FROM events
     WHERE tenant_id = '<TENANT_ID>'
       AND recipient LIKE '%@yahoo.com'
       AND created_at > NOW() - INTERVAL '7 days';
     ```

3. **Yahoo-specific SMTP error codes:**
   - `421 4.7.0 [TS01]` — Connection deferred, try later
   - `421 4.7.0 [TS03]` — Too many connections from this IP
   - `553 5.7.1 [BL21]` — IP or domain blocklisted
   - `554 5.7.9` — DMARC policy violation

4. **Recovery:** Reduce volume, improve list hygiene, ensure complaint rate < 0.3%, register for Yahoo Postmaster Tools.

### DLV.ISP.APPLE_RELAY — "Emails to iCloud / Apple Mail Privacy Protection issues"

**Symptoms:** Open tracking metrics for Apple Mail users are inflated or unreliable. Emails to `@icloud.com`, `@me.com`, `@mac.com` show 100% open rate.

**Root cause:** Apple Mail Privacy Protection (MPP), introduced in iOS 15 / macOS Monterey, pre-fetches all tracking pixels through Apple's proxy servers regardless of whether the user actually opens the email.

**Resolution:**

1. **Impact on open tracking:**
   - All Apple Mail users appear as "opened" immediately after delivery
   - Open rate becomes artificially inflated (Apple Mail users ≈ 50–60% of consumer email)
   - ApexMail's bot detection service (`apps/analytics/src/services/bot-detection.ts`, 405 lines) helps identify bot/proxy opens

2. **How ApexMail mitigates:**
   - Bot detection scores each open event with heuristics (IP reputation, user-agent, timing pattern)
   - Events flagged as bot-opens are marked in analytics but not excluded by default
   - Use the `?exclude_bots=true` query parameter on analytics endpoints for cleaner metrics

3. **Best practice:**
   - **Do NOT rely solely on open rates** for engagement metrics
   - Use **click rate** as the primary engagement signal
   - Use **reply tracking** (`apps/analytics/src/services/reply-tracking.ts`) for relationship-based campaigns
   - Combine multiple signals (clicks + replies + web activity) for engagement scoring

4. **iCloud-specific delivery:**
   - iCloud supports SPF, DKIM, and DMARC validation
   - No public postmaster tools available for iCloud
   - `@icloud.com` MX: `mx01.mail.icloud.com` through `mx05.mail.icloud.com`

### DLV.GEO.PATTERN_SHIFT — "Sudden geo-pattern shift causing delivery issues"

**Symptoms:** Sending patterns suddenly shift to a new geographic region (e.g., US sender starts sending to EU recipients), causing increased spam filtering.

**Root cause:** ISPs build reputation profiles based on historic sending patterns. A sudden change in recipient geography, language, or timezone can trigger anti-spam heuristics.

**Resolution:**

1. **Gradual expansion:** When entering a new market/region, ramp up volume gradually (similar to IP warmup):
   - Week 1: 10% of new-region recipients
   - Week 2: 25%
   - Week 3: 50%
   - Week 4: 100%

2. **Dedicated IP / IP pool:** Use a separate IP pool for the new region to isolate reputation impact (see Issue 108).

3. **Content localization:** ISPs analyze content language. Ensure headers (`Content-Language`, `lang` attribute) match the recipient's expected language.

4. **Send-time alignment:** Use STO (`apps/analytics/src/services/send-time-optimization.ts`) to send during the recipient's local business hours, not the sender's.

5. **Monitoring:** Watch inbox placement per region:
   ```
   GET /v1/analytics/deliverability?group_by=recipient_domain&timeframe=7d
   ```

### DLV.BLOCKLIST.CLOUDMARK — "Listed on Cloudmark CSI / Sender Intelligence"

**Symptoms:** Emails rejected by ISPs that use Cloudmark filtering (Comcast, Cox, Charter Spectrum, and many others). May see generic rejection without explicit Cloudmark reference.

**Root cause:** Cloudmark CSI (Content Security Intelligence) uses fingerprint-based detection. Even if content changes slightly, the template "fingerprint" may trigger listing.

**Resolution:**

1. **Identification:** Cloudmark doesn't provide a public blocklist lookup. Signs you're listed:
   - Rejections from multiple ISPs simultaneously (Comcast, Cox, Charter)
   - Rejection messages reference "content filtering" without naming a specific blocklist
   - Sudden deliverability drop across US cable ISPs

2. **Delisting:**
   - Contact Cloudmark via `https://csi.cloudmark.com/` sender support
   - Clean list aggressively — remove all addresses with no engagement in 90+ days
   - Change email template significantly (Cloudmark fingerprints template structure)

3. **Prevention:**
   - Vary template content regularly (avoid identical bulk sends)
   - Maintain complaint rate < 0.1% (Cloudmark weights complaints heavily)
   - Use engagement-based segmentation

### DLV.BLOCKLIST.CISCO_TALOS — "Listed on Cisco Talos / SenderBase"

**Symptoms:** Emails rejected by ISPs using Cisco's IronPort or ESA products. SMTP error may reference `senderbase.org` or `talosintelligence.com`.

**Root cause:** Cisco Talos monitors sender reputation based on volume patterns, complaint ratios, and spam trap data.

**Resolution:**

1. **Check reputation:**
   - `https://talosintelligence.com/reputation_center/lookup?search=<YOUR_IP>`
   - Reputation scores: Good, Neutral, Poor

2. **Delisting process:**
   - Submit ticket via `https://talosintelligence.com/reputation_center/support`
   - Provide evidence of list cleanup and compliance measures
   - Typical turnaround: 1–5 business days

3. **Prevention:**
   - Monitor sending volume spikes — Talos flags sudden volume increases
   - Run content through ApexMail's content scanner (`apps/compliance/src/content/scanner.ts`) before sending
   - Keep complaint rate < 0.1% and bounce rate < 2%

---

## Troubleshooting Decision Tree (Section G)

```
Deliverability issue
├── New sender, poor placement → Issue 94 (warmup, build reputation)
├── Gmail Promotions tab → Issue 95 (content optimization, not spam)
├── Link tracking domain mismatch → Issue 96 (custom tracking domain)
├── URL shorteners → Issue 97 (remove them, use full URLs)
├── Image-heavy content → Issue 98 (improve text ratio)
├── Missing List-Unsubscribe → Issue 99 (check headers, bulk sender rules)
├── Spam-trigger content → Issue 100 (clean up language)
├── Blocklisted → Issue 101 (check & delist)
│   ├── Cloudmark → DLV.BLOCKLIST.CLOUDMARK
│   └── Cisco Talos → DLV.BLOCKLIST.CISCO_TALOS
├── Low engagement → Issue 102 (list hygiene, segmentation, A/B test)
├── MIME structure → Issue 103 (multipart/alternative)
├── Phishing detection → Issue 104 (align domains, fix language)
├── Spam traps → Issue 105 (clean list, double opt-in)
├── Deliverability audit → Issue 106 (systematic review)
├── IP vs domain reputation → Issue 107 (understand both)
├── Multiple IPs → Issue 108 (Scale/Enterprise, IP pools)
├── Yahoo/AOL block → DLV.ISP.YAHOO_BLOCK
├── Apple MPP open inflation → DLV.ISP.APPLE_RELAY
└── Geo-pattern shift → DLV.GEO.PATTERN_SHIFT
```
