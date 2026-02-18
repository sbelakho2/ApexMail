# Link Branding, Tracking Domains, Click/Open Tracking & Unsubscribe Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Link branding, custom tracking domains, SSL for tracking, click/open tracking, bot filtering, List-Unsubscribe, suppression scope, return-path conflicts.
> **Last Updated:** 2026-02-16

---

## Reference: Tracking Architecture

| Component | Implementation | Code |
|-----------|---------------|------|
| Click tracking | URL rewrite to encrypted token → redirect via tracking service | `apps/tracking/src/routes.ts` |
| Open tracking | 1x1 GIF pixel injected into HTML body | `apps/tracking/src/routes.ts` |
| Unsubscribe | RFC 8058 one-click + landing page + List-Unsubscribe headers | `apps/tracking/src/routes.ts` |
| URL encoding | AES-128-GCM encrypted tokens, HMAC signatures, URL-safe base64 | `apps/tracking/src/codec.ts` |
| Event buffering | Redis WAL (Write-Ahead Log) with atomic LRANGE+LTRIM via Lua script | `apps/tracking/src/processor.ts` |
| Bot detection | UA pattern, IP reputation, timing analysis, honeypot links | `apps/analytics/src/bot-detection.ts` |

### Tracking Domain Configuration

| Setup | Link Domain | Recommended |
|-------|------------|-------------|
| Default (no custom) | `track.apexmail.io` | ❌ Less trustworthy to ISPs |
| Custom tracking domain | `track.yourdomain.com` via CNAME → `track.apexmail.io` | ✅ Recommended |
| Per-brand tracking | `track.brand-a.com`, `links.brand-b.com` | ✅ Enterprise/Scale |

---

## Issue C56 — "Link branding marked Default but not being used"

**Symptoms:** Customer configured a custom tracking domain and set it as default, but emails still use `track.apexmail.io`.

**Root cause:** Link branding requires: (1) DNS CNAME configured, (2) verified in dashboard, (3) SSL provisioned, (4) assigned to the sending domain or set as account default.

**Resolution:**
1. Check Dashboard → Settings → Tracking Domain → is the custom domain verified? ✅?
2. Check DNS:

```bash
dig CNAME track.yourdomain.com +short
# Expected: track.apexmail.io.
```

3. If DNS is correct but not verified: trigger re-verification in dashboard.
4. Check if the sending domain has this tracking domain assigned: Dashboard → Domains → select domain → Tracking Domain.
5. **Priority order:** Per-domain tracking domain > Account default tracking domain > System default (`track.apexmail.io`).
6. If the custom domain has SSL issues (cert not provisioned), the system falls back to the default.

---

## Issue C57 — "Why does another domain's link branding override my default?"

**Symptoms:** Customer has multiple domains. Link branding uses a different domain than expected.

**Root cause:** Tracking domain assignment has a precedence hierarchy.

**Resolution:**
1. **Precedence (highest to lowest):**
   - Per-message tracking domain (if specified in API request)
   - Per-sending-domain tracking domain (Dashboard → Domains → Tracking)
   - Account default tracking domain (Dashboard → Settings → Tracking)
   - System default (`track.apexmail.io`)
2. If a specific sending domain has a tracking domain assigned, it overrides the account default.
3. **Fix:** Set the desired tracking domain on each sending domain, or clear per-domain overrides to use the account default.

---

## Issue C58 — "Disable link branding—how, and what breaks?"

**Symptoms:** Customer wants to disable custom link branding, or disable link rewriting entirely.

**Resolution:**
1. **Disable custom branding (revert to default):** Dashboard → Settings → Tracking Domain → Remove custom domain. Links will use `track.apexmail.io`.
2. **Disable click tracking entirely:** Dashboard → Settings → Tracking → uncheck "Click Tracking".
   - ⚠️ This disables click analytics. No click events, no click webhooks.
   - Open tracking remains independent (separate setting).
3. **Disable per-message:** Include `"tracking": { "clicks": false }` in the API request.
4. **What breaks if click tracking is disabled:**
   - No click metrics in analytics.
   - No `message.clicked` webhook events.
   - Links are NOT rewritten — original URLs appear in the email.
   - UTM parameters work normally (they're in the original URL).

---

## Issue C59 — "Branded links return Not Found"

**Symptoms:** Recipients click a link in the email and see a 404 Not Found page.

**Root cause:** Tracking domain DNS is misconfigured or tracking service is down.

**Resolution:**
1. **Check DNS:**

```bash
dig CNAME track.yourdomain.com +short
# Must point to: track.apexmail.io.
```

2. **Check SSL:**

```bash
curl -I https://track.yourdomain.com/
# Should return 200 or redirect, NOT 404 or SSL error
```

3. **Common causes:**
   - CNAME was deleted or changed.
   - DNS registrar migration lost the record.
   - Cloudflare proxy mode enabled (should be DNS-only/gray cloud).
   - SSL certificate not provisioned or expired.
4. **Fix:** Re-add the CNAME and re-verify in dashboard.
5. **Check tracking service health:**

```bash
curl -s https://track.apexmail.io/health | jq .
```

---

## Issue C60 — "Branded link SSL ERR_CERT_COMMON_NAME_INVALID"

**Symptoms:** Browser shows SSL certificate error when clicking tracked links.

**Root cause:** SSL certificate for the custom tracking domain wasn't provisioned, or the cert doesn't cover the custom subdomain.

**Resolution:**
1. ApexMail auto-provisions SSL certificates for custom tracking domains via Let's Encrypt when the CNAME is correctly configured.
2. **Check cert status:**

```bash
echo | openssl s_client -connect track.yourdomain.com:443 -servername track.yourdomain.com 2>/dev/null | openssl x509 -noout -subject -dates
```

3. If cert shows `track.apexmail.io` instead of `track.yourdomain.com`: the cert wasn't provisioned for the custom domain.
4. **Fix:** Ensure CNAME is correct (DNS-only, not proxied), then re-verify the tracking domain in dashboard. Certificate provisioning happens automatically within 30 minutes.
5. If using Cloudflare: the custom domain MUST be in DNS-only mode (gray cloud). Cloudflare's proxy provides its own cert that covers `*.yourdomain.com` but may interfere with our cert.

---

## Issue C61 — "Wrong Link error after enabling SSL for branded links"

**Symptoms:** After enabling SSL on tracking domain, links redirect to wrong URLs or show errors.

**Root cause:** Mixed HTTP/HTTPS redirect configuration. Links in older emails may have been encoded with HTTP scheme.

**Resolution:**
1. **After enabling SSL:** New emails will use `https://track.yourdomain.com/...`. Old emails in recipients' inboxes may still have `http://` links.
2. ApexMail automatically redirects HTTP → HTTPS for tracking domains.
3. If links completely break: check if the tracking domain's DNS changed during the SSL setup.
4. **Verify redirect chain:**

```bash
curl -Lv http://track.yourdomain.com/test 2>&1 | grep -E "Location:|< HTTP"
```

---

## Issue C62 — "Cloudflare + link branding SSL misconfiguration"

**Symptoms:** Tracking links don't work, SSL errors, or redirect loops when using Cloudflare.

**Root cause:** Cloudflare's proxy mode and SSL settings interfere with ApexMail's tracking domain setup.

**Resolution:**
1. **The tracking domain CNAME MUST be DNS-only (gray cloud ☁️) in Cloudflare.**
2. If proxied (orange cloud 🟠): Cloudflare terminates SSL and may cause:
   - Certificate mismatch (Cloudflare cert vs ApexMail cert).
   - Redirect loops (Cloudflare's SSL mode vs ApexMail's redirects).
   - Cookie/header stripping.
3. **Fix:** In Cloudflare → DNS → find `track.yourdomain.com` → click the orange cloud to toggle to gray (DNS Only).
4. Wait 5 minutes for propagation, then test.
5. **If customer insists on proxying:** They must configure Cloudflare's SSL to "Full (Strict)" and ensure ApexMail's cert is provisioned for the subdomain.

---

## Issue C63 — "HTTPS works in browser but click tracking breaks in email clients"

**Symptoms:** Clicking tracking links in a browser works, but clicking from within email clients fails or shows errors.

**Root cause:** Email clients may use different HTTP user agents, follow redirects differently, or have proxy behavior.

**Resolution:**
1. **Common email client behaviors:**
   - Outlook: may not follow 302 redirects for security scanning links.
   - Gmail: proxies through `https://www.google.com/url?...` for safety scanning.
   - Apple Mail: generally follows redirects normally.
   - Corporate proxies: may intercept and block redirects to unknown domains.
2. **Check the redirect response:**

```bash
curl -A "Mozilla/5.0 (Windows NT 10.0)" -Lv "https://track.yourdomain.com/<TRACKING_TOKEN>" 2>&1 | grep "Location:"
```

3. Ensure redirects return `302 Found` (or `301`), not `303` or `307`.
4. Ensure the final destination URL is valid and accessible.

---

## Issue C64 — "Click tracking works but open tracking doesn't"

**Symptoms:** Click events fire normally, but open events are near-zero.

**Root cause:** Open tracking uses a 1x1 pixel image. Many email clients block images by default.

**Resolution:**
1. **Open tracking limitations:**
   - Outlook (desktop): blocks external images by default.
   - Many corporate email clients: strip images for security.
   - Apple Mail Privacy Protection (iOS 15+): pre-fetches ALL images, inflating open counts.
   - Ad blockers / privacy extensions: may block tracking pixels.
2. **Open tracking is inherently unreliable.** Industry accuracy: ~80% at best.
3. Focus on click tracking for more reliable engagement metrics.
4. Ensure open tracking is enabled: Dashboard → Settings → Tracking → ✅ "Open Tracking".
5. Verify pixel injection:

```bash
# Check if the tracking pixel is in the email HTML
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>" | \
  jq -r '.html_body' | grep -o 'track.*\.gif\|track.*\/o\/'
```

---

## Issue C65 — "Open tracking stopped after we changed CSP / proxy settings"

**Symptoms:** Open rates dropped to near zero after infrastructure changes.

**Root cause:** Content Security Policy, reverse proxy, or corporate filtering now blocks the tracking pixel.

**Resolution:**
1. If customer added a Content-Security-Policy that restricts `img-src`: the tracking pixel may be blocked.
2. CSP is applied at the customer's website, NOT in the email itself. But if the customer runs a webmail interface, CSP could block it.
3. **More common:** Corporate email gateway started stripping external images.
4. **Diagnosis:** Send a test email and view raw HTML — is the tracking pixel present? Try viewing in different clients.

---

## Issue C66 — "Link wrapping breaks our signed URLs"

**Symptoms:** Customer signs their URLs (HMAC, JWT, or similar), and click tracking modifies the URL, invalidating the signature.

**Root cause:** Click tracking wraps URLs in a redirect: `https://track.yourdomain.com/<token>` → `original-url`. The original URL is preserved, but when the URL is first proxied through the tracking redirect, timestamp or signature validation on the recipient's server may fail.

**Resolution:**
1. **Clarification:** ApexMail's tracking redirect does NOT modify the original URL. The user is redirected to the exact original URL.
2. If the signed URL includes a timestamp that expires quickly (< 30 seconds): the redirect adds latency (50-200ms), which shouldn't cause issues. But if the signature is based on the full URL and the URL was modified, it would break.
3. **Workaround:** Exclude specific URLs from click tracking:
   - API send: `"tracking": { "clicks": { "exclude_patterns": ["https://signed.example.com/*"] } }`
   - Or disable click tracking for the specific message.
4. **Best practice:** Sign URLs with a reasonable expiry (> 5 minutes) to account for redirect latency.

---

## Issue C67 — "Link wrapping breaks our unsubscribe links"

**Symptoms:** Unsubscribe links in email body are wrapped by click tracking, and the unsubscribe functionality breaks.

**Root cause:** ApexMail rewrites ALL `<a href>` links by default, including unsubscribe links.

**Resolution:**
1. ApexMail automatically detects `List-Unsubscribe` header links and handles them separately (not wrapped for tracking).
2. Body unsubscribe links: ApexMail wraps them for tracking but preserves the redirect destination.
3. If the unsubscribe endpoint is sensitive to the referrer or request path: the redirect may cause issues.
4. **Fix:** Add `data-tracking="false"` attribute to links you don't want tracked:
   ```html
   <a href="https://example.com/unsubscribe?token=abc" data-tracking="false">Unsubscribe</a>
   ```
5. Or exclude the URL pattern from tracking in the API request.

---

## Issue C68 — "Customers report 404 on tracking domain only from corporate networks"

**Symptoms:** Tracked links work for most users but fail for recipients on corporate networks.

**Root cause:** Corporate firewalls, DNS policies, or web proxies block the tracking domain.

**Resolution:**
1. **Corporate DNS filtering:** Some organizations block known email tracking domains. `track.apexmail.io` may be on blocklists.
2. **Solution:** Use a custom tracking domain (`track.yourdomain.com`). Custom domains are far less likely to be blocked.
3. **Corporate proxy issues:** Some proxies strip or modify redirect URLs.
4. **Diagnosis:** Ask the recipient to try the link from outside the corporate network (mobile data). If it works outside: corporate network is blocking.
5. **Customer action:** Ask their IT team to allowlist the tracking domain.

---

## Issue C69 — "Tracking domain flagged by security gateway—how to change/rotate?"

**Symptoms:** Customer's tracking domain is flagged by email security gateways (Proofpoint, Mimecast, Barracuda).

**Resolution:**
1. **Change tracking domain:** Set up a new CNAME for a different subdomain (e.g., `go.yourdomain.com` instead of `track.yourdomain.com`).
2. **Verify new domain:** Dashboard → Settings → Tracking Domain → add new domain.
3. **Old links:** Already-sent emails still use the old tracking domain. Those links will continue to work as long as the old CNAME remains active.
4. **Proactive:** Use a "clean" subdomain that isn't obviously a tracking domain (e.g., `click.yourdomain.com`, `links.yourdomain.com`).

---

## Issue C70 — "We want separate tracking domain per brand/tenant"

**Symptoms:** Multi-brand customer wants each brand's emails to use a tracking domain matching the brand.

**Resolution:**
1. **Supported on Scale and Enterprise plans.**
2. Setup: each brand's sending domain can have its own tracking domain.
   - `Brand A`: `track.brand-a.com` → `track.apexmail.io`
   - `Brand B`: `links.brand-b.com` → `track.apexmail.io`
3. Configure per-domain: Dashboard → Domains → select domain → Tracking Domain.
4. Each tracking domain needs its own CNAME and SSL verification.
5. **Plan limits for domains apply.**

---

## Issue C71 — "We want to disable click tracking for certain emails only"

**Symptoms:** Customer wants tracking on marketing emails but not transactional.

**Resolution:**
1. **Per-message control:** Include in the API request:
   ```json
   {
     "tracking": {
       "clicks": false,
       "opens": true
     }
   }
   ```
2. **Per-template:** Templates can have default tracking settings.
3. **Per-domain:** Different sending domains can have different tracking defaults.
4. **Common setup:**
   - Marketing stream: clicks ✅, opens ✅
   - Transactional stream: clicks ❌, opens ❌ (or opens only)

---

## Issue C72 — "Click tracking inflates because of scanners—need bot filtering"

**Symptoms:** Click rates are unnaturally high (50%+). URLs are "clicked" within seconds of delivery.

**Root cause:** Email security scanners (Barracuda, Proofpoint, Microsoft ATP) pre-click links to check for malware. These generate fake click events.

**Resolution:**
1. **ApexMail has built-in bot detection** (`apps/analytics/src/bot-detection.ts`):
   - User-Agent pattern matching (known scanner UAs).
   - IP reputation checking.
   - Timing analysis (clicks within <2s of delivery are flagged).
   - Honeypot link detection (invisible links that only bots click).
2. **In analytics:** Bot clicks are flagged and excluded from engagement metrics by default.
3. **In webhooks:** `message.clicked` events include `"is_bot": true/false` field.
4. **If bot detection isn't filtering enough:** Contact support to tune the detection parameters.
5. **Customer action:** Filter `is_bot: true` events in their webhook handler.

---

## Issue C73 — "Open tracking inflated because of prefetch—how to interpret?"

**Symptoms:** Open rate is unrealistically high (80-100%). Apple Mail users show near-100% open rate.

**Root cause:** Apple Mail Privacy Protection (MPP, since iOS 15) pre-fetches ALL email images, including tracking pixels. This registers an "open" for every email delivered to Apple Mail users.

**Resolution:**
1. **Explain:** "Apple Mail Privacy Protection loads tracking pixels automatically, regardless of whether the user actually reads the email. This inflates open rates."
2. **Impact:** ~50% of email recipients use Apple Mail. Open rates for these users are unreliable.
3. **Workarounds:**
   - Focus on click-through rate (CTR) as the primary engagement metric.
   - Use the `device` field in open events — if `device.client = "Apple Mail"` and the open is within seconds of delivery, it's likely MPP.
   - ApexMail's bot detection attempts to flag MPP opens.
4. **Industry reality:** Open rates as a metric are becoming less reliable. The industry is shifting toward click-based and conversion-based metrics.

---

## Issue C74 — "Tracking pixel blocked by privacy features—why opens are low"

**Symptoms:** Very low open rates despite good list quality and engagement.

**Resolution:**
1. See Issue C64 (open tracking limitations).
2. **Additional causes of low opens:**
   - Corporate email gateway strips external images (common in healthcare, finance, government).
   - GMX, Tutanota, ProtonMail block tracking pixels entirely.
   - Browser-based ad blockers in webmail (rare).
3. **Open tracking is a best-estimate metric.** True open rate is likely 20-40% higher than reported.
4. Focus on click rates, reply rates, and conversion metrics for accurate engagement measurement.

---

## Issue C75 — "Gmail image proxy causes duplicate opens"

**Symptoms:** Single-recipient emails show 2-3 open events.

**Root cause:** Gmail's image proxy caches and re-fetches tracking pixels, generating multiple open events.

**Resolution:**
1. ApexMail's tracking processor includes **deduplication** (`apps/tracking/src/processor.ts`):
   - Opens are deduplicated by `message_id + recipient` combination.
   - A Redis SETNX with TTL prevents counting the same open twice.
2. If customer sees duplicates in webhooks: the `message.opened` webhooks should have a `first_open: true/false` field.
3. **In analytics:** Only the first open per recipient is counted for unique open rate.
4. **In webhooks:** All opens fire (for tracking purposes), but `first_open` flag distinguishes unique vs repeat.

---

## Issue C76 — "UTM params duplicated after link wrapping"

**Symptoms:** URLs get double UTM parameters after click tracking is applied.

**Root cause:** If the customer adds UTM parameters AND ApexMail adds them via auto-UTM feature, parameters can be duplicated.

**Resolution:**
1. **ApexMail does NOT auto-add UTM parameters by default.** Link rewriting only wraps the URL for redirect tracking — it preserves the original URL including any UTM parameters.
2. If customer sees duplicate UTMs: their template or CMS is adding UTMs, AND they have a separate UTM tool or integration also adding them.
3. **Fix:** Ensure UTM parameters are added in only one place.
4. Verify the original URL before sending: `curl -s "https://api.apexmail.ee/v1/messages/<ID>" | jq '.html_body'` — check URLs in the body.

---

## Issue C77 — "Some links not rewritten—why partial tracking?"

**Symptoms:** Some links in the email are tracked (rewritten) and others aren't.

**Root cause:** ApexMail has rules for which links to rewrite.

**Resolution:**
1. **Links that are NOT rewritten:**
   - `mailto:` links (email addresses).
   - `tel:` links (phone numbers).
   - `#` anchor links (in-page navigation).
   - Links with `data-tracking="false"` attribute.
   - Links excluded via URL pattern matching in tracking config.
   - `List-Unsubscribe` header URLs (tracked separately).
2. **Links that ARE rewritten:**
   - All `http://` and `https://` URLs in `<a href>` tags.
   - Background image URLs are NOT tracked (not clickable).
3. If a valid HTTP link isn't being rewritten: check if it has syntax issues (malformed URL, missing protocol).

---

## Issue C78 — "Links rewritten but redirects blocked by recipient policy"

**Symptoms:** Tracked links are rewritten correctly, but recipients report they can't follow the link.

**Root cause:** Recipient's email client, security gateway, or browser blocks the redirect.

**Resolution:**
1. **Common blockers:**
   - Corporate web proxy blocks `track.apexmail.io` or customer's tracking domain.
   - Email security gateway (Proofpoint, Mimecast) rewrites the link again, causing double-redirect issues.
   - Browser extension blocks redirect (if link opens in browser).
2. **Fix:** Use a custom tracking domain (less likely to be blocked).
3. **Double-redirect issue:** If the security gateway wraps the already-wrapped link, the chain becomes: `security-proxy → track.yourdomain.com → original-url`. This usually works but adds latency.

---

## Issue C79 — "Tracking domain DNS misconfigured after registrar migration"

**Symptoms:** Tracking links break after customer moved their DNS to a new provider.

**Resolution:**
1. **Diagnosis:** The CNAME for the tracking domain was lost during migration.

```bash
dig CNAME track.yourdomain.com +short
# Should return: track.apexmail.io.
# If empty: CNAME is missing
```

2. **Fix:** Re-add the CNAME record at the new DNS provider:
   - Host/Name: `track` (or whatever subdomain was used)
   - Value/Target: `track.apexmail.io`
   - Proxy: DNS Only (gray cloud if Cloudflare)
3. After DNS propagation (5-30 min): re-verify in dashboard.
4. SSL certificate may need re-provisioning if it expired.

---

## Issue C80 — "CNAME flattening breaks tracking subdomain"

**Symptoms:** Tracking domain shows incorrect resolution. CNAME points to an IP instead of `track.apexmail.io`.

**Root cause:** DNS provider's CNAME flattening resolves the CNAME to an A record at query time. This breaks if ApexMail changes IPs.

**Resolution:**
1. Disable CNAME flattening for the tracking subdomain.
2. In Cloudflare: set to "DNS Only" (gray cloud) — this disables both proxying and flattening.
3. In other providers: check for "CNAME at apex" or "ALIAS" records and ensure the tracking subdomain uses a real CNAME.
4. Verify:

```bash
dig CNAME track.yourdomain.com +short
# Must return: track.apexmail.io. (the CNAME target, not an IP)
```

---

## Issue C81 — "Tracking subdomain proxied; signature validation fails"

**Symptoms:** Tracking links pass through a proxy that modifies request headers or body, causing AES-GCM decryption to fail on our tracking server.

**Resolution:**
1. The tracking domain MUST NOT be proxied. Set it to DNS Only.
2. Proxies (Cloudflare, Sucuri, Imperva) may:
   - Modify request headers
   - Add their own cookies
   - Change URL encoding
3. These modifications break the encrypted tracking token decryption.
4. **Fix:** DNS Only mode for the tracking CNAME.

---

## Issue C82 — "Custom tracking domain cert provisioning stuck"

**Symptoms:** Custom tracking domain added, CNAME correct, but SSL cert never provisions.

**Resolution:**
1. **Cert provisioning requirements:**
   - CNAME must resolve correctly from public DNS.
   - No Cloudflare proxy or CDN intercepting the domain.
   - DNS propagation must be complete.
2. **Check status:**

```bash
# Can we reach the domain?
curl -I http://track.yourdomain.com/.well-known/acme-challenge/test
```

3. **Common blockers:**
   - CAA DNS record restricting which CAs can issue certs. Add: `0 issue "letsencrypt.org"`.
   - Firewall blocking HTTP-01 validation on port 80.
   - DNS not propagated yet.
4. **Manual trigger:** Contact support to manually trigger cert provisioning.

---

## Issue C83 — "Need HSTS for tracking domain, but it breaks verification"

**Symptoms:** Customer wants HSTS on their tracking subdomain. This may interfere with cert provisioning.

**Resolution:**
1. **HSTS (HTTP Strict Transport Security):** Once enabled, browsers refuse HTTP connections. This can break cert renewal if HTTP-01 challenges are needed.
2. ApexMail handles SSL automatically. If customer controls HSTS on their parent domain with `includeSubDomains`, the tracking subdomain inherits it.
3. **This is fine** as long as SSL is working. HSTS + valid SSL = no issues.
4. **If cert provisioning fails** because of HSTS: the DNS-01 challenge method can be used instead of HTTP-01. Contact support.

---

## Issue C84 — "Need to support both http/https redirect"

**Symptoms:** Customer wants tracking domain to work for both HTTP and HTTPS links.

**Resolution:**
1. ApexMail's tracking service automatically redirects HTTP → HTTPS.
2. Old emails sent before SSL was enabled may have `http://` links. These are automatically upgraded via 301 redirect.
3. Both `http://track.yourdomain.com/...` and `https://track.yourdomain.com/...` work.
4. No customer action needed.

---

## Issue C85 — "Customer wants to host tracking on their own infra entirely"

**Symptoms:** Customer wants full control over tracking infrastructure for privacy/compliance reasons.

**Resolution:**
1. **Not supported as a managed feature.** ApexMail provides tracking as a platform service.
2. **Alternative:** Customer can disable ApexMail tracking and implement their own:
   - Disable click tracking (`"tracking": { "clicks": false }`).
   - Disable open tracking (`"tracking": { "opens": false }`).
   - Inject their own tracking pixel and URL redirect in the email content before sending via API.
3. **Enterprise custom:** For compliance-driven requirements, contact `contact@apexmail.ee` for custom arrangements.

---

## Issue C86 — "One-click unsubscribe not recognized by Gmail"

**Symptoms:** Gmail doesn't show the unsubscribe button at the top of the email.

**Root cause:** Missing or incorrect `List-Unsubscribe` and `List-Unsubscribe-Post` headers.

**Resolution:**
1. Gmail requires **both** headers for one-click:
   ```
   List-Unsubscribe: <https://track.yourdomain.com/u/TOKEN>
   List-Unsubscribe-Post: List-Unsubscribe=One-Click
   ```
2. ApexMail automatically adds these headers for marketing/promotional emails.
3. **If headers are missing:** Ensure the email is categorized as "marketing" (not transactional). Transactional emails intentionally don't include List-Unsubscribe.
4. **If headers are present but Gmail doesn't show the button:**
   - Gmail may take time to recognize a new sender's unsubscribe mechanism.
   - Gmail requires the unsubscribe endpoint to actually work (returns 200 on POST).
   - New senders (< 5,000 emails/day) may not see the button immediately.
5. **Verify headers:** Send a test email to Gmail, "Show Original" → search for `List-Unsubscribe`.

**Backend:** `apps/tracking/src/routes.ts` — implements RFC 8058 one-click unsubscribe with POST handler.

---

## Issue C87 — "List-Unsubscribe header malformed"

**Symptoms:** Email clients don't recognize the unsubscribe header. Raw header shows formatting issues.

**Resolution:**
1. **Correct format:**
   ```
   List-Unsubscribe: <https://track.yourdomain.com/u/TOKEN>, <mailto:unsub+TOKEN@bounce.apexmail.io>
   List-Unsubscribe-Post: List-Unsubscribe=One-Click
   ```
2. **Common malformations:**
   - Missing angle brackets `< >` around URLs.
   - Missing `List-Unsubscribe-Post` header (required for one-click).
   - URL not HTTPS (some clients require HTTPS).
3. ApexMail generates these headers automatically. If they're malformed, it may be a bug — escalate to engineering.
4. If customer sets custom `List-Unsubscribe` via API headers: their formatting overrides the automatic one. Verify their format.

---

## Issue C88 — "List-Unsubscribe-Post missing; one-click fails"

**Symptoms:** Unsubscribe header is present but one-click doesn't work. Gmail shows "unsubscribe" but it goes to a webpage instead of one-click.

**Root cause:** Missing `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header.

**Resolution:**
1. Both headers are required for one-click:
   - `List-Unsubscribe` — provides the unsubscribe URL
   - `List-Unsubscribe-Post` — tells the client to POST instead of GET
2. Without `List-Unsubscribe-Post`: the client opens the URL in a browser (two-click unsubscribe).
3. ApexMail adds both automatically for marketing emails. Check if the customer overrode the headers.

---

## Issue C89 — "Unsubscribe link clicked but user still gets emails—suppression scope confusion"

**Symptoms:** Recipient unsubscribed but continues receiving emails from the same sender.

**Root cause:** Unsubscribe may have been scoped to a specific campaign/list, not globally.

**Resolution:**
1. **Suppression scopes in ApexMail:**
   - **Global (tenant-level):** Recipient suppressed from ALL emails from this tenant.
   - **Domain-level:** Suppressed from emails sent from a specific domain.
   - **Campaign/list-level:** Suppressed from a specific campaign or mailing list only.
2. **Default unsubscribe behavior:** One-click unsubscribe adds recipient to **tenant-level** global suppression.
3. **If using per-campaign unsubscribe:** The recipient is only removed from that campaign's list, NOT globally suppressed. They can still receive other campaigns.
4. **Check suppression:**

```sql
SELECT id, email, scope, scope_id, reason, created_at
FROM suppression_list
WHERE tenant_id = '<TENANT_ID>'
  AND email = '<RECIPIENT_EMAIL>';
```

5. **Fix:** If customer intends global unsubscribe: ensure their unsubscribe implementation adds to tenant-level suppression.

---

## Issue C90 — "Unsubscribe is per-campaign but user expects global"

**Symptoms:** Recipient expects "unsubscribe" to stop ALL emails, but it only stops one campaign.

**Resolution:**
1. This is a business/design decision for the customer.
2. **Gmail/Yahoo requirements (Feb 2024+):** One-click unsubscribe for bulk senders must be honored. The interpretation (per-list vs global) is the sender's choice, but recipients expect it to be close to "global."
3. **Best practice:** Honor unsubscribe as broadly as possible. Per-campaign unsubscribe frustrates recipients and increases complaint rates.
4. **Recommendation:** Use global suppression for one-click unsubscribe. Offer preference centers for granular control (reduce frequency, choose topics).

---

## Issue C91 — "Complaint suppression not applied—why still sending?"

**Symptoms:** Recipient complained (spam report), but customer says they can still send to that address.

**Root cause:** Complaint suppression may not have been processed yet, or the complaint was received on a different identifier.

**Resolution:**
1. **Check FBL processing:**

```sql
SELECT id, email, reason, source, created_at
FROM suppression_list
WHERE tenant_id = '<TENANT_ID>'
  AND email = '<RECIPIENT_EMAIL>'
  AND reason = 'complaint';
```

2. If not in suppression list: Check if the complaint was received:

```sql
SELECT id, reported_email_id, source, created_at
FROM abuse_reports
WHERE tenant_id = '<TENANT_ID>'
ORDER BY created_at DESC LIMIT 20;
```

3. **Timing:** Complaints from ISPs (FBL) may take 24-48 hours to arrive. During this window, subsequent sends could still go through.
4. **Gmail caveat:** Gmail doesn't send traditional FBL reports for all complaints. Some complaints are reflected only in Google Postmaster Tools reputation, not as individual reports.
5. **Fix:** If complaint was received but suppression wasn't applied (bug): manually add to suppression:

```sql
INSERT INTO suppression_list (tenant_id, email, reason, source, created_at)
VALUES ('<TENANT_ID>', '<EMAIL>', 'complaint', 'manual_support', NOW());
```

---

## Issue C92 — "Suppression applied too broadly—tenant vs domain scope confusion"

**Symptoms:** Recipient is suppressed from all emails but should only be suppressed from one domain/campaign.

**Resolution:**
1. Check suppression scope:

```sql
SELECT id, email, scope, scope_id, reason FROM suppression_list
WHERE tenant_id = '<TENANT_ID>' AND email = '<EMAIL>';
```

2. If scope is `tenant` (global) but should be `domain` or `campaign`:
   - Delete the global suppression: `DELETE /v1/suppressions/<ID>`
   - Add domain-scoped suppression: `POST /v1/suppressions` with `"scope": "domain", "scope_id": "<DOMAIN_ID>"`
3. **Scoped suppression via API:**
   ```json
   {
     "email": "recipient@example.com",
     "scope": "domain",
     "scope_id": "example.com",
     "reason": "unsubscribe"
   }
   ```

**Backend:** `apps/api/src/routes/suppressions.ts` — supports scoped suppressions (tenant, domain, campaign).

---

## Issue C93 — "Custom return-path domain conflicts with tracking domain"

**Symptoms:** Customer configured both a return-path domain and tracking domain on the same subdomain, causing DNS conflicts.

**Resolution:**
1. Return-path uses CNAME: `bounce.yourdomain.com → bounce.apexmail.io`
2. Tracking uses CNAME: `track.yourdomain.com → track.apexmail.io`
3. These MUST be different subdomains. You cannot have two CNAMEs on the same subdomain.
4. **If customer used the same subdomain:** DNS conflict. One CNAME overwrites the other.
5. **Fix:** Use different subdomains (e.g., `bounce` for return-path, `track` for tracking).

---

## Issue C94 — "Subdomain verification done, but sending from root fails (alignment)"

**Symptoms:** Customer verified `mail.example.com` but tries to send from `user@example.com`. Fails or "via" shows.

**Resolution:**
1. Verification is per-domain. Verifying `mail.example.com` does NOT verify `example.com`.
2. **Fix:** Either:
   - Send from `user@mail.example.com` (the verified subdomain).
   - Verify `example.com` as well (add DNS records on root domain).
3. DMARC with relaxed alignment (`aspf=r; adkim=r`) allows subdomain return-paths to align with root domain. But the From domain still must be verified.

---

## Issue C95 — "Domain verified, but some endpoints still say 'not verified' (cache/replication delay)"

**Symptoms:** Customer verified the domain (dashboard shows ✅), but API calls return `sender_not_verified`.

**Root cause:** Domain verification status is cached in Redis (60s TTL). After verification, there may be a brief delay before all components see the new status.

**Resolution:**
1. Wait 60 seconds and retry.
2. If still failing after 2 minutes:

```bash
# Check Redis cache
redis-cli -h redis.apexmail.internal GET "domain:verified:example.com"
# If showing old status, clear it:
redis-cli -h redis.apexmail.internal DEL "domain:verified:example.com"
```

3. Check the database directly:

```sql
SELECT domain, verification_status, last_check_at FROM domains
WHERE domain = 'example.com';
```

4. If DB shows verified but API still rejects: restart the API service to clear in-memory caches.

---

## Troubleshooting Decision Tree

```
Link/Tracking/Unsubscribe issue
├── Link Branding
│   ├── Not being used → C56 (precedence, DNS, SSL)
│   ├── Another domain overrides → C57 (precedence rules)
│   ├── How to disable → C58
│   ├── Links return 404 → C59
│   ├── SSL cert error → C60
│   ├── Wrong link after SSL → C61
│   └── Cloudflare conflicts → C62
├── Click Tracking
│   ├── Works in browser, not in client → C63
│   ├── Bot inflation → C72
│   ├── Disable per-message → C71
│   ├── UTM duplication → C76
│   ├── Partial tracking → C77
│   └── Redirects blocked → C78
├── Open Tracking
│   ├── Click works, opens don't → C64
│   ├── CSP blocks pixel → C65
│   ├── MPP inflation → C73
│   ├── Low opens (privacy) → C74
│   └── Gmail duplicates → C75
├── Tracking Domain DNS
│   ├── After registrar migration → C79
│   ├── CNAME flattening → C80
│   ├── Proxied subdomain → C81
│   ├── Cert stuck → C82
│   ├── HSTS conflicts → C83
│   ├── HTTP+HTTPS → C84
│   └── Self-hosted tracking → C85
├── Link Wrapping
│   ├── Breaks signed URLs → C66
│   ├── Breaks unsubscribe → C67
│   └── 404 from corp networks → C68
├── Unsubscribe
│   ├── Gmail one-click not showing → C86
│   ├── Header malformed → C87
│   ├── Post header missing → C88
│   ├── Still getting emails → C89
│   ├── Per-campaign vs global → C90
│   └── Complaint not suppressed → C91
├── Suppression Scope
│   ├── Too broad → C92
│   ├── Tracking flagged → C69
│   └── Per-brand tracking → C70
└── Domain Conflicts
    ├── Return-path vs tracking → C93
    ├── Subdomain vs root → C94
    └── Cache delay → C95
```

---

## Related

- [A) Domain DNS Troubleshooting](a-domain-dns-troubleshooting.md) — DNS record setup
- [E) Webhooks & Events](e-webhooks-events-troubleshooting.md) — open/click events
- [F) Bounces & Suppressions](f-bounces-complaints-suppressions.md) — suppression management
- [G) Deliverability](g-deliverability-inbox-placement.md) — inbox placement, List-Unsubscribe requirements
- Internal: `apps/tracking/src/` — tracking service implementation
- Internal: `apps/analytics/src/bot-detection.ts` — bot filtering
- Internal: `apps/tracking/src/codec.ts` — URL encryption
