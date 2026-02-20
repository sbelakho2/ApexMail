# A) Domain Verification & DNS Troubleshooting Playbook (Issues 1–18)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Every DNS / domain-verification failure mode customers hit, with exact resolution steps.

---

## DNS Records Required by ApexMail

| Record | Type | Host / Name | Value | Purpose |
|--------|------|-------------|-------|---------|
| SPF | TXT | `@` (root) | `v=spf1 include:_spf.apexmail.ee ~all` | Authorize ApexMail IPs to send on behalf of domain |
| DKIM | TXT | `{selector}._domainkey` | `v=DKIM1; k=rsa; p={public key from dashboard}` | Authenticate outgoing email with per-domain signing key |
| DMARC | TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.ee` | Policy for authentication failures |
| Return-Path | CNAME | `bounce` | `bounce.apexmail.ee` | Bounce processing (VERP) |
| Verification | TXT | `@` (root) | `apexmail-verify=<TOKEN>` | Prove domain ownership |

---

## Issue 1 — Domain "pending verification" because DNS not propagated yet

**Symptoms:** Customer adds domain, clicks Verify, sees "Pending". Dashboard shows ⏳.

**Root cause:** DNS propagation delay. TTL-dependent; can take 5 minutes to 48 hours depending on registrar and previous TTL.

**Resolution:**
1. Ask customer: "When did you add the DNS records?"
2. If < 1 hour: "DNS propagation can take up to 48 hours, but most registrars propagate within 15–30 minutes. Please wait and try again."
3. Suggest checking with a public DNS tool: `dig TXT yourdomain.com` or https://toolbox.googleapps.com/apps/dig/
4. If > 48 hours: records are likely misconfigured — proceed to Issues 2–5.
5. Admin can force re-verify via Dashboard → Domains → Re-verify.

**Key facts:** Typical propagation: 5–30 min (Cloudflare, Route 53), 1–4 hours (GoDaddy, Namecheap), up to 48 hours (some legacy registrars).

---

## Issue 2 — DNS records added to wrong domain (root vs subdomain mixup)

**Symptoms:** Verification fails. Customer swears records are correct.

**Root cause:** Customer verified `mail.example.com` but added DNS records to `example.com` (or vice versa).

**Resolution:**
1. Ask: "Which exact domain did you add in the ApexMail dashboard? And where exactly did you add the DNS records?"
2. If sending from `mail.example.com`, records must be on `mail.example.com`:
   - SPF TXT on `mail.example.com`
   - DKIM TXT `{selector}._domainkey.mail.example.com`
   - DMARC TXT on `_dmarc.mail.example.com`
3. If sending from `example.com`, records go on root domain.
4. Common mistake: adding `apexmail._domainkey.example.com` when the verified domain is `mail.example.com` — the DKIM TXT record name should be `apexmail._domainkey.mail.example.com`.

---

## Issue 3 — DKIM TXT record mistyped or missing

**Symptoms:** SPF and verification pass, but DKIM fails. Domain shows partial verification.

**Root cause:** Typo in the TXT record name or value. Common errors: `apexmal._domainkey` (missing 'i'), `apexmail._domainke` (missing 'y'), wrong public key value.

**Resolution:**
1. Ask customer to run: `dig TXT apexmail._domainkey.yourdomain.com`
2. Expected result: `"v=DKIM1; k=rsa; p=MIGf..."`
3. If no result or wrong value, customer must fix/re-add the TXT record in their DNS provider.
4. Double-check: the **name** is `{selector}._domainkey` (e.g., `apexmail._domainkey`) and the **value** is `v=DKIM1; k=rsa; p={exact public key from dashboard}`.
5. Some registrars auto-append the domain — entering `apexmail._domainkey.example.com` in the host field creates `apexmail._domainkey.example.com.example.com`. Customer should enter just `apexmail._domainkey`.

---

## Issue 4 — DKIM TXT record has incorrect value format

**Symptoms:** DKIM verification fails. `dig TXT apexmail._domainkey.yourdomain.com` returns a record but DKIM still fails.

**Root cause:** The TXT record value is not in the correct DKIM format, OR the customer added a CNAME instead of a TXT record, OR they pasted a truncated/corrupted public key.

**Resolution:**
1. Ask customer to run: `dig TXT apexmail._domainkey.yourdomain.com +short`
2. Expected format: `"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB..."`
3. If a CNAME exists instead of TXT: delete the CNAME and add a TXT record with the exact value from the dashboard.
4. If the TXT value is truncated (some registrars cut off long values): ensure the full key is copied, including the final `=` padding characters.
5. Verify the key matches the one shown in Dashboard → Domains → [Domain] → DNS Records.

---

## Issue 5 — SPF record missing required include

**Symptoms:** SPF fails. DKIM may pass but DMARC fails due to SPF alignment failure.

**Root cause:** Customer's SPF record doesn't include `include:_spf.apexmail.ee`.

**Resolution:**
1. Ask customer to check: `dig TXT yourdomain.com | grep spf`
2. If SPF exists but lacks ApexMail include: merge it. Example:
   - Current: `v=spf1 include:_spf.google.com ~all`
   - Fixed: `v=spf1 include:_spf.google.com include:_spf.apexmail.ee ~all`
3. Do NOT create a second SPF TXT record (see Issue 6).
4. If no SPF exists: add `v=spf1 include:_spf.apexmail.ee ~all`.

---

## Issue 6 — SPF has multiple TXT records ("multiple SPF" causing permerror)

**Symptoms:** SPF returns "permerror". Email authentication fails completely.

**Root cause:** RFC 7208 mandates exactly ONE SPF TXT record per domain. Two or more SPF records (both starting with `v=spf1`) cause a permanent error.

**Resolution:**
1. Ask customer: `dig TXT yourdomain.com | grep spf`
2. If multiple records found, they must merge into ONE.
3. Example merge:
   - Record A: `v=spf1 include:_spf.google.com ~all`
   - Record B: `v=spf1 include:_spf.apexmail.ee ~all`
   - Merged: `v=spf1 include:_spf.google.com include:_spf.apexmail.ee ~all`
4. Delete the old individual records after creating the merged one.

---

## Issue 7 — SPF exceeds 10 DNS lookup limit

**Symptoms:** SPF returns "permerror" or "too many DNS lookups". Some receivers fail SPF.

**Root cause:** RFC 7208 limits SPF to 10 DNS lookups (includes, a, mx, redirect, exists mechanisms). Large organizations with many senders hit this.

**Resolution:**
1. Count lookups: each `include:`, `a:`, `mx:`, `redirect=` counts as 1 lookup (recursively).
2. Strategies to reduce:
   - Replace `include:` with `ip4:` / `ip6:` for static senders (flattening).
   - Remove unused includes (old providers no longer in use).
   - Use an SPF flattening service.
   - Move some senders to a subdomain with its own SPF record.
3. ApexMail's `include:_spf.apexmail.ee` typically costs 2–3 lookups. Ensure total stays ≤ 10.

---

## Issue 8 — SPF record too long / split incorrectly

**Symptoms:** SPF partially works or fails at some receivers.

**Root cause:** Single DNS TXT record can hold up to 255 characters per string. Longer SPF records must be split into multiple strings within the SAME TXT record (RFC 7208 §3.3). Some registrars handle this incorrectly.

**Resolution:**
1. Check total SPF string length. If > 255 chars, ensure registrar stores it as multiple strings in one TXT record (not multiple TXT records — that's Issue 6).
2. Most modern registrars handle this automatically.
3. If registrar doesn't support long TXT records: use SPF flattening to shorten the record, or use a subdomain.

---

## Issue 9 — Customer used ~all vs -all incorrectly

**Symptoms:** SPF passes but DMARC reports show unexpected behavior, or emails are rejected/quarantined.

**Root cause:** Confusion between SPF qualifiers:
- `-all` (hard fail): unauthorized senders are rejected
- `~all` (soft fail): unauthorized senders are marked but typically accepted
- `?all` (neutral): no assertion
- `+all` (pass all — NEVER use, allows anyone)

**Resolution:**
1. ApexMail recommends `~all` during initial setup and testing.
2. Once all legitimate senders are included, upgrade to `-all` for maximum protection.
3. If customer uses `-all` and legitimate mail is being rejected: temporarily switch to `~all` while auditing all senders.
4. NEVER use `+all` — it allows anyone to send as your domain.

---

## Issue 10 — DMARC record missing or invalid syntax

**Symptoms:** DMARC reports not received. DMARC shows "none" or fails validation.

**Root cause:** No `_dmarc` TXT record, or record has syntax errors.

**Resolution:**
1. Check: `dig TXT _dmarc.yourdomain.com`
2. If missing: add `v=DMARC1; p=none; rua=mailto:dmarc@apexmail.ee` as TXT record on `_dmarc.yourdomain.com`.
3. Common syntax errors:
   - Missing `v=DMARC1` at the start
   - Using commas instead of semicolons
   - Spaces in tag values
   - `rua` without `mailto:` prefix
4. Recommended progression: start with `p=none` (monitoring), then `p=quarantine`, then `p=reject`.

---

## Issue 11 — DMARC policy too strict, blocks mail due to alignment failure

**Symptoms:** Customer set `p=reject` but legitimate mail is being rejected by receiving servers.

**Root cause:** DMARC requires either SPF or DKIM to pass AND align with the From domain. If neither aligns, `p=reject` causes rejection.

**Resolution:**
1. Check alignment: the domain in From header must match SPF domain (return-path) or DKIM signing domain.
2. If alignment fails, temporarily change DMARC to `p=none` and review aggregate reports (`rua`).
3. Ensure SPF includes ApexMail (`include:_spf.apexmail.ee`) and DKIM TXT record is correct.
4. If using a subdomain (e.g., `mail.example.com`), ensure DMARC on `_dmarc.mail.example.com` or that the parent `_dmarc.example.com` uses `aspf=r; adkim=r` (relaxed alignment).

---

## Issue 12 — DMARC alignment fails: From domain differs from DKIM/SPF domain

**Symptoms:** DMARC fails despite SPF and DKIM individually passing.

**Root cause:** DMARC alignment checks that the domain in the visible From header matches the domains used by SPF (envelope-from / return-path) and DKIM (d= signing domain). With strict alignment (`aspf=s` or `adkim=s`), subdomains don't match parent domains.

**Resolution:**
1. Check DMARC alignment mode: `aspf=s` (strict) or `aspf=r` (relaxed, default).
2. If strict: From `user@example.com`, return-path must be `*@example.com` (not `*@bounce.example.com`).
3. If relaxed: From `user@example.com`, return-path can be `*@anything.example.com`.
4. Fix: either switch to relaxed alignment (`aspf=r; adkim=r`) or ensure all domains match exactly.
5. ApexMail uses `bounce.yourdomain.com` for return-path — this requires relaxed SPF alignment.

---

## Issue 13 — DMARC record published on wrong subdomain

**Symptoms:** DMARC reports not arriving. DMARC lookups fail.

**Root cause:** DMARC record must be at `_dmarc.<sending-domain>`. If sending from `mail.example.com`, DMARC goes on `_dmarc.mail.example.com`, NOT `_dmarc.example.com` (unless relying on organizational domain fallback with relaxed alignment).

**Resolution:**
1. Identify the exact sending domain (From header domain).
2. Place DMARC TXT record at `_dmarc.<sending-domain>`.
3. Note: DMARC does fall back to organizational domain — if no `_dmarc.mail.example.com` exists, it checks `_dmarc.example.com`. But for clarity, place it on the exact sending domain.

---

## Issue 14 — DNS provider filters or truncates TXT records causing DKIM failure

**Symptoms:** DKIM fails. `dig TXT apexmail._domainkey.yourdomain.com` returns nothing or truncated content.

**Root cause:** Some DNS providers truncate long TXT records or have restrictions on `_domainkey` subdomain TXT records. DKIM public keys are typically 256+ characters, which can hit registrar limits.

**Resolution:**
1. Check if the full public key is present: `dig TXT apexmail._domainkey.yourdomain.com +short`
2. If truncated: the registrar may have a character limit per TXT record string. The DKIM key must be entered as a single string; if the registrar has a 255-char limit, split into quoted parts within the same TXT record (RFC 7208 style).
3. Some registrars (e.g., cPanel/WHM-based hosts) split long TXT records automatically.
4. If no record found at all: confirm the record was saved correctly in the DNS provider's UI.
5. Recommend migrating DNS to Cloudflare (free) for reliable TXT record support.

---

## Issue 15 — DNSSEC misconfiguration breaks validation

**Symptoms:** DNS lookups fail or return SERVFAIL. Domain works in some resolvers but not others.

**Root cause:** DNSSEC is enabled but signatures are expired, key rollover failed, or DS record in parent zone doesn't match.

**Resolution:**
1. This is rare but devastating — breaks ALL DNS for the domain.
2. Check: https://dnsviz.net/d/yourdomain.com/dnssec/
3. If DNSSEC is misconfigured: customer must fix with their registrar/DNS provider.
4. Temporary fix: disable DNSSEC (if customer controls it) and re-enable after fixing.
5. ApexMail cannot fix DNSSEC issues — this is between the customer and their DNS provider.
6. Escalate to `contact@apexmail.ee` if customer needs assistance diagnosing.

---

## Issue 16 — DNS proxy (e.g., Cloudflare "orange cloud") interfering with verification

**Symptoms:** Domain verification fails.

**Root cause:** Cloudflare's proxy (orange cloud) intercepts DNS queries and returns Cloudflare IPs instead of actual record values. TXT records are not affected by proxy mode, but the verification TXT record may take longer to propagate.

**Resolution:**
1. SPF and DKIM TXT records are NOT affected by Cloudflare proxy mode.
2. The verification TXT record (`apexmail-verify=...`) should NOT be proxied (TXT records typically aren't).
3. If the bounce CNAME (`bounce.yourdomain.com → bounce.apexmail.ee`) is proxied, toggle it to gray (DNS Only).
4. After toggling, wait 5 minutes and retry verification.

---

## Issue 17 — Wrong TTL expectations ("I changed it 2 minutes ago, why not verified?")

**Symptoms:** Customer impatient, records just added.

**Root cause:** Misunderstanding of DNS propagation. TTL (Time To Live) controls caching duration. If the previous TTL was high (e.g., 86400 = 24 hours), old cached values persist until TTL expires.

**Resolution:**
1. Explain: "DNS propagation depends on the TTL (Time To Live) of your records. If your previous TTL was set to a high value (e.g., 24 hours), it can take up to that long for changes to be visible worldwide."
2. Typical propagation times:
   - Cloudflare: 5 minutes (auto-purge)
   - AWS Route 53: 60 seconds (low TTL)
   - GoDaddy: 1–4 hours
   - Namecheap: 30 minutes – 2 hours
   - Legacy providers: up to 48 hours
3. Suggest: "Please wait 30 minutes and try verifying again. If it still doesn't work after 4 hours, there may be a configuration issue."
4. Tip: before making changes, lower TTL to 300 (5 min) first, wait for old TTL to expire, then make changes.

---

## Issue 18 — Domain verified but later "falls out" due to record deletion or DNS migration

**Symptoms:** Domain was verified and working, but suddenly shows as unverified. Emails start failing.

**Root cause:** Customer deleted DNS records (accidentally or during migration), changed DNS providers without re-adding records, or domain expired.

**Resolution:**
1. Ask: "Did you recently change DNS providers, migrate your domain, or make any DNS changes?"
2. Check current DNS: `dig TXT yourdomain.com` — look for verification TXT record and SPF.
3. Check DKIM: `dig TXT apexmail._domainkey.yourdomain.com`.
4. If records are missing: customer must re-add all required DNS records.
5. If domain expired: customer must renew domain with registrar first.
6. After re-adding records: click "Re-verify" in Dashboard → Domains.
7. ApexMail periodically re-checks domain verification. If records disappear, domain status reverts to unverified automatically.

---

## Troubleshooting Decision Tree (Section A)

```
Domain issue reported
├── "Pending verification"
│   ├── Records added < 1 hour ago → Wait, check with dig
│   ├── Records added > 4 hours ago → Check record placement (Issue 2)
│   └── Records added > 48 hours ago → Likely misconfigured → Issues 3–6
├── "Was verified, now unverified"
│   └── DNS migration or record deletion → Issue 18
├── "DKIM fails"
│   ├── TXT record present? → Check value format (Issue 3)
│   ├── Wrong record type (CNAME instead of TXT)? → Issue 4
│   ├── Truncated key? → Issue 14
│   └── Record correct but fails → DNSSEC (Issue 15)
├── "SPF fails"
│   ├── Missing include? → Issue 5
│   ├── Multiple SPF records? → Issue 6
│   ├── > 10 lookups? → Issue 7
│   └── Record too long? → Issue 8
├── "DMARC fails"
│   ├── No DMARC record? → Issue 10
│   ├── Alignment failure? → Issue 11/12
│   └── Wrong subdomain? → Issue 13
└── "Everything looks right but still fails"
    ├── TTL not expired? → Issue 17
    └── DNSSEC broken? → Issue 15
```
