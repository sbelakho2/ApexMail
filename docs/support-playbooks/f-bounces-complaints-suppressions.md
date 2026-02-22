# F) Bounces, Complaints, Suppressions Playbook (Issues 76–92)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Bounce handling, complaint management, suppression lists, and list hygiene.

---

## Reference: Bounce Categories

| Category | SMTP Code | Meaning | Action |
|----------|-----------|---------|--------|
| Hard bounce | 550 5.1.1 | Mailbox does not exist | Remove permanently; auto-suppressed |
| Soft bounce | 450 4.2.2 | Mailbox full / temporary issue | Retry with exponential backoff (default 3 attempts, 30 s base delay, 30 min cap); permanently fail after exhaustion |
| Block | 550 5.7.1 | IP or domain blocked | Investigate reputation; check blocklists |
| Undetermined | Various | Cannot classify | Review raw SMTP response |

**Retry schedule:** Exponential backoff — 30 s × 2^(attempt−1), capped at 30 min. Default max: 3 attempts (`EMAIL_QUEUE_MAX_RETRIES`). Example: 30 s → 60 s → 2 min.
**Auto-suppression:** Hard bounces are immediately and permanently suppressed. Soft bounces are **not** auto-suppressed; they are retried and then permanently failed if all retries are exhausted.
**Healthy thresholds:** Bounce rate < 2%, complaint rate < 0.1%.

---

## Issue 76 — Hard bounce: mailbox does not exist

**Symptoms:** Email bounced with `550 5.1.1 User unknown` or similar. Webhook fires `message.bounced` with type `hard`.

**Root cause:** The recipient email address does not exist at the destination mail server.

**Resolution:**
1. The address is automatically added to the suppression list — no further sends will attempt delivery.
2. Customer should remove this address from their mailing list.
3. Common causes: typo in email address, user left company, domain expired.
4. If customer believes the address IS valid: ask them to verify with the recipient directly. ApexMail won't override suppression without proof of validity.

---

## Issue 77 — Soft bounce: mailbox full / temporary issue

**Symptoms:** Email bounced with `450 4.2.2 Mailbox full` or `421 Try again later`. Webhook fires `message.bounced` with type `soft`.

**Root cause:** Temporary condition — mailbox full, server overloaded, greylisting, or connection limit reached.

**Resolution:**
1. ApexMail automatically retries soft bounces using exponential backoff: 30 s → 60 s → 2 min (30 s × 2^(attempt−1), capped at 30 min). Default max: 3 attempts.
2. After all retries exhausted: the message is permanently failed and marked as bounced.
3. Soft bounces are **not** auto-suppressed (unlike hard bounces). Each new send to the same address is treated independently.
4. Customer should monitor soft bounce rates. Consistently high soft bounces for an address suggest a problem (abandoned mailbox).

---

## Issue 78 — Bounce classification confusion (hard vs soft vs blocked)

**Symptoms:** Customer doesn't understand why some bounces are "hard" and others "soft". Asks about blocks.

**Root cause:** Email bounce codes are complex and sometimes ambiguous.

**Resolution:**
1. Simple explanation:
   - **Hard bounce** = permanent failure. The address doesn't exist. Remove it.
   - **Soft bounce** = temporary failure. Mailbox full, server busy. We'll retry automatically.
   - **Blocked** = the receiving server blocked us based on reputation, content, or policy. Needs investigation.
   - **Undetermined** = we can't classify the SMTP response. Review headers.
2. SMTP code categories:
   - 5xx = permanent failure (hard bounce or block)
   - 4xx = temporary failure (soft bounce)
   - Sub-codes (5.1.1, 5.7.1, etc.) provide more detail.
3. Customers can view detailed bounce reasons in Dashboard → Messages → click the message → Delivery Details.

---

## Issue 79 — Customer keeps re-sending to hard-bounced addresses

**Symptoms:** Customer says "I keep trying to send to user@example.com but it always fails instantly."

**Root cause:** Address is on the suppression list after a hard bounce. All subsequent sends are blocked before they reach the MTA.

**Resolution:**
1. Explain: "This address was permanently suppressed after a hard bounce. Continuing to send to invalid addresses hurts your sender reputation."
2. Check Dashboard → Suppression List: search for the address.
3. ApexMail blocks sends to suppressed addresses to protect the customer's reputation.
4. If customer insists the address is now valid (e.g., typo was fixed at the other end): see Issue 82 for removal process.
5. Bulk uploading lists with known bad addresses triggers protective measures.

---

## Issue 80 — Complaint rate spikes; customer insists "users love us"

**Symptoms:** Complaint rate exceeds 0.1%. Customer may receive a warning from ApexMail. Customer denies the complaints.

**Root cause:** Recipients marking emails as spam counts as a complaint via ISP Feedback Loops (FBLs). This is different from explicit complaints to the customer.

**Resolution:**
1. Explain: "Complaint rate is measured by ISP Feedback Loops. When a recipient clicks 'Report Spam' in their email client, the ISP sends us an automated report. This is different from someone emailing you directly."
2. Acceptable complaint rate: below **0.1%** (1 complaint per 1,000 emails). Google enforces < 0.3%.
3. Common causes:
   - Recipients forgot they subscribed.
   - Unsubscribe link is hard to find — make it prominent.
   - Email frequency too high.
   - Content not matching expectations.
   - Purchased or rented list (see Issue 92).
4. Actions: reduce frequency, improve content relevance, make unsubscribe easy, segment engaged vs unengaged.
5. If complaint rate stays high: ApexMail may throttle or suspend sending to protect platform reputation.

---

## Issue 81 — Customer wants to remove suppression but has no proof of re-consent

**Symptoms:** Customer wants to send to a previously suppressed address. Can't prove the recipient re-consented.

**Root cause:** Suppressed addresses (from hard bounces or complaints) should only be unsuppressed with evidence that the address is valid and the recipient wants to receive email.

**Resolution:**
1. For hard-bounce suppressions: customer must provide evidence the address is now valid (e.g., the person updated their email, confirmed it works).
2. For complaint suppressions: customer must provide explicit re-consent from the recipient (opt-in confirmation).
3. Without proof: ApexMail will NOT remove the suppression — it protects both the customer's and platform's reputation.
4. Process: contact `contact@apexmail.ee` with evidence. Or use Dashboard → Suppression List → Request Removal (requires justification).

---

## Issue 82 — Customer wants to remove a specific address from suppression

**Symptoms:** Customer has legitimate reason to unsuppress an address.

**Root cause:** Address was previously suppressed but is now valid/wanted.

**Resolution:**
1. Dashboard → Suppression List → search for address → click "Remove."
2. Customer must confirm they have consent from the recipient.
3. If the address hard-bounces again after removal: it will be re-suppressed.
4. Bulk suppression removal is available via API: `DELETE /v1/suppressions/{email}` with appropriate scope.
5. Note: removing a complaint-based suppression without re-consent risks re-complaints and reputation damage.

---

## Issue 83 — Customer's list source is low quality; bot must ask list acquisition questions

**Symptoms:** High bounce rates (>5%), high complaint rates, sudden sending of very large volume.

**Root cause:** Customer may be using purchased, scraped, or very old lists.

**Resolution:**
1. Ask: "How did you acquire your email list? When were these addresses last confirmed?"
2. Red flags:
   - "I bought the list" → **STOP.** Purchased lists violate ApexMail's Acceptable Use Policy. See Issue 92.
   - "I scraped them" → **STOP.** Scraped addresses are non-consensual.
   - "We've had them for years" → Likely many stale/invalid addresses. Recommend re-confirmation campaign.
3. Good list sources: opt-in forms, double opt-in confirmed, customer transactions, event registrations.
4. Recommend: run list through a validation service before uploading. Segment old addresses.
5. If customer persists with bad lists: escalate to `contact@apexmail.ee` for policy review.

---

## Issue 84 — Customer sends to role accounts (admin@, info@) causing high bounces

**Symptoms:** High bounce rate from role-based addresses. Some ISPs reject or filter these.

**Root cause:** Role accounts (`admin@`, `info@`, `support@`, `webmaster@`, `postmaster@`, `sales@`, `abuse@`) often forward to multiple people, are managed by IT, or have strict filtering.

**Resolution:**
1. Role accounts are more likely to generate complaints (one person marks as spam, the complaint fires).
2. Many email verification services flag role accounts as risky.
3. Best practice: only email role accounts for transactional purposes (order confirmations, technical notifications), not marketing.
4. If bounce rate is high: audit the list and remove or separate role accounts from marketing sends.

---

## Issue 85 — Customer sees "delivered" but user says not received

**Symptoms:** Dashboard shows "delivered" status, but the recipient says they never got the email.

**Root cause:** "Delivered" means the recipient's mail server accepted the message (250 OK). It does NOT mean it's in the inbox. It could be in spam, filtered, or a catch-all/null-route.

**Resolution:**
1. Explain: "'Delivered' means the receiving server accepted the message. After that, the receiving server decides placement — inbox, spam folder, promotions tab, or internal filters."
2. Ask recipient to check:
   - Spam/Junk folder
   - Promotions tab (Gmail)
   - Other/Filtered tabs (Outlook)
   - Check if their admin has mail rules routing it elsewhere
3. If consistently going to spam: deliverability investigation needed (see Section G).
4. Some corporate servers have catch-all rules that accept all email but discard unknown addresses.

---

## Issue 86 — Microsoft blocks (550 5.7.1 variants)

**Symptoms:** Emails to Microsoft/Outlook/Hotmail recipients bounce with `550 5.7.1`, `550 5.7.606`, or `550 5.7.708`.

**Root cause:** Microsoft has aggressive spam filtering. Common blocks:
- `550 5.7.1` — IP or domain reputation issue
- `550 5.7.606` — IP banned
- `550 5.7.708` — Content filtered

**Resolution:**
1. Immediate: check if IP is listed on Microsoft's blocklist.
2. Submit a delisting request: https://sender.office.com/ (Microsoft SNDS delist form).
3. Ensure all authentication is correct (SPF, DKIM, DMARC — Microsoft checks strictly).
4. If on dedicated IP: the IP may need warming (see bounce investigation playbook warmup schedule).
5. If on shared IP: ApexMail manages reputation — contact `contact@apexmail.ee` if blocks persist.
6. Microsoft-specific: `5.7.708` usually means content is triggering filters — review email content.

---

## Issue 87 — Gmail/consumer provider temporary deferrals (4xx) at scale

**Symptoms:** Large sends to Gmail recipients get `421-4.7.28` or `421 4.7.0 Try again later`. Emails are delayed.

**Root cause:** Gmail throttles large-volume senders, especially from new or low-reputation IPs/domains.

**Resolution:**
1. Explain: "Gmail throttles incoming email from senders it doesn't yet trust. This is normal for new domains or IPs."
2. These are soft bounces — ApexMail automatically retries.
3. Solutions:
   - Properly warm up new IPs/domains (see warmup schedule).
   - Spread large sends over time (don't blast all at once).
   - Improve engagement metrics (better open/click rates signal legitimacy to Gmail).
4. Monitor Google Postmaster Tools for domain/IP reputation.
5. Gmail throttle limits loosen as reputation improves — this is temporary.

---

## Issue 88 — Customer sees "blocked" and assumes it's ApexMail's fault

**Symptoms:** Customer blames ApexMail for emails being blocked. Demands "fix it now."

**Root cause:** Blocks are usually caused by sender reputation (high bounces, complaints), content issues, or IP blocklisting — most often due to the customer's sending practices.

**Resolution:**
1. Diplomatically explain: "Blocks are imposed by the receiving server based on sender reputation, content analysis, and authentication. Let's investigate together."
2. Check:
   - Bounce/complaint rates (Dashboard → Analytics)
   - Blocklist status (check Spamhaus, Barracuda, SpamCop)
   - Content (spammy language, suspicious URLs, image-heavy)
   - Authentication (SPF, DKIM, DMARC all passing?)
3. On shared IPs: other senders on the same IP could affect reputation — if customer has persistent issues, recommend a dedicated IP (Growth+ plan).
4. On dedicated IP: the customer's own sending practices are solely responsible.

---

## Issue 89 — Customer wants to "warm up" instantly with high volume

**Symptoms:** New customer, new dedicated IP, wants to send 100K emails on day one.

**Root cause:** ISPs track new IPs. A sudden burst of email from a new IP triggers spam filters and blocks.

**Resolution:**
1. Explain: "IP warmup is essential. ISPs need to build trust with a new sending IP. Sending too much too fast will get you blocked."
2. Recommended warmup schedule (ISP-specific; see [IP Pools & Warmup Playbook](ip-pools-warmup-infrastructure.md) for full per-ISP tables):
   - Gmail/Yahoo: start at 50/day (strictest — Day 1)
   - Microsoft: start at 100/day
   - Default (unknown ISPs): start at 100/day
   - Full volume reached in ~14–15 days of consistent sending
3. During warmup: send to your most engaged recipients first.
4. Monitor bounces and complaints at each step — pause if rates exceed thresholds.
5. Do NOT skip warmup. Even Enterprise customers must follow this process.

---

## Issue 90 — User complains about suppression of "valid" recipients (it's actually a typo)

**Symptoms:** Customer says "this address is valid, why is it suppressed?" Address has a typo (e.g., `user@gmial.com`).

**Root cause:** The address was tried, hard bounced (domain doesn't exist or mailbox not found), and suppressed. Customer doesn't notice the typo.

**Resolution:**
1. Show the customer the exact suppressed address.
2. Common typos: `gmial.com`, `gmal.com`, `yahooo.com`, `outlok.com`, double dots, missing TLD.
3. If it IS a typo: customer should correct the address in their list and send to the corrected version.
4. The corrected address is a new address — it won't be suppressed (unless it also bounces).
5. Recommend: use email address validation at point of collection (typo detection, domain verification).

---

## Issue 91 — Complaint feedback loop confusion

**Symptoms:** Customer doesn't understand complaint reports. Asks "who complained?" or "what does this mean?"

**Root cause:** ISP Feedback Loops (FBLs) send automated reports (ARF format) when a recipient clicks "Report Spam." Customers unfamiliar with this mechanism.

**Resolution:**
1. Explain: "When a recipient clicks 'Mark as spam' or 'Report spam' in their email client, the ISP (Gmail, Microsoft, Yahoo) sends us an automated complaint report."
2. ApexMail processes these via the Feedback Loop Server (port 2526).
3. The complained address is automatically suppressed to prevent further spam reports.
4. Customer receives `message.complained` webhook event with the recipient's address.
5. Important: complaint data may be anonymized by some ISPs (Gmail doesn't send full address in some cases).
6. Customer should analyze WHY users complain: content mismatch, frequency, forgotten subscription.

---

## Issue 92 — Customer wants bounce reasons but only has generic SMTP response

**Symptoms:** Bounce reason shows generic text like "Message rejected" without specifics.

**Root cause:** Some receiving servers return minimal SMTP error information. The diagnostic code is vague.

**Resolution:**
1. ApexMail captures the full SMTP response and classifies it. Check Dashboard → Messages → Delivery Details for the diagnostic code.
2. Common generic responses and likely causes:
   - "Message rejected" → content filtered, reputation issue, or policy block
   - "Connection refused" → IP blocked at the firewall level
   - "Too many connections" → rate limiting, needs throttling
3. For more detail: check the receiving domain's postmaster tools (Google Postmaster, Microsoft SNDS).
4. If consistently generic from one provider: it may be their policy not to reveal detailed reasons (anti-abuse measure).

---

## Issue 93 (F-series) — Customer wants to "retry forever"

**Symptoms:** Customer asks ApexMail to keep retrying a soft-bounced message indefinitely.

**Root cause:** Misunderstanding of retry policy. Infinite retries would tie up resources and worsen reputation.

**Resolution:**
1. Explain: "ApexMail retries soft bounces with exponential backoff: 30 seconds, 60 seconds, 2 minutes (30 s × 2^(attempt−1), capped at 30 min). The default is 3 attempts. After all retries are exhausted, the message fails permanently."
2. This is industry standard practice. Retrying indefinitely would:
   - Consume retry queue resources
   - Continue hitting a mailbox that may never accept the message
   - Potential for reputation damage
3. If the message is critical: customer should send it again as a new message after the bounce, possibly to a different address.
4. For time-sensitive transactional email: ensure list hygiene to minimize bounces.

---

## Troubleshooting Decision Tree (Section F)

```
Bounce/complaint/suppression issue
├── Hard bounce → Issue 76 (auto-suppressed, address invalid)
├── Soft bounce → Issue 77 (auto-retry, check after exhaustion)
├── "What's the difference?" → Issue 78
├── "Can't send to this address" → Suppressed (Issue 79)
│   ├── Wants to remove suppression → Issue 82
│   ├── No proof of re-consent → Issue 81
│   └── Actually a typo → Issue 90
├── High complaint rate → Issue 80
│   ├── Purchased list? → Issue 83, STOP
│   ├── Role accounts? → Issue 84
│   └── Complaint confusion → Issue 91
├── "Delivered but not received" → Issue 85
├── Microsoft blocks → Issue 86
├── Gmail throttling → Issue 87
├── "It's your fault" → Issue 88
├── Wants instant high volume → Issue 89
├── Generic bounce reason → Issue 92
└── "Retry forever" → Issue 93
```
