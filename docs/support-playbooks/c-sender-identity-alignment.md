# C) Sender Identity, From/Reply-To, Alignment Playbook (Issues 36–46)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** All issues related to sender identity configuration, From/Reply-To headers, and alignment.

---

## Issue 36 — From address uses display name or formatting that violates RFC syntax

**Symptoms:** Send fails with validation error or email delivered with garbled From display.

**Root cause:** RFC 5322 requires specific formatting for the From header. Invalid characters, unescaped special characters in display names, or malformed email syntax.

**Resolution:**
1. Valid From formats:
   - `user@example.com` — bare email
   - `"John Doe" <user@example.com>` — quoted display name
   - `John Doe <user@example.com>` — unquoted (only if no special chars)
2. Invalid examples:
   - `John "Johnny" Doe <user@example.com>` — unescaped quotes in display name
   - `user@example.com <user@example.com>` — email as display name
   - `<user@example.com>` — angle brackets without display name field
3. Special characters in display name (`,`, `.`, `@`, `"`) require quoting: `"O'Brien, John" <user@example.com>`
4. ApexMail API accepts `from` as `{ "email": "user@example.com", "name": "John Doe" }` — the API handles RFC formatting.

---

## Issue 37 — Reply-To domain differs and triggers internal policy checks

**Symptoms:** Customer sets Reply-To to a different domain. Emails may be flagged by recipient filters.

**Root cause:** Some corporate email gateways and spam filters flag emails where Reply-To domain differs significantly from From domain (possible phishing indicator).

**Resolution:**
1. Explain: "Having a different Reply-To domain is technically valid per RFC 5322, but some spam filters flag it as suspicious."
2. Best practice: use Reply-To on the same domain or a closely related domain (e.g., From `noreply@example.com`, Reply-To `support@example.com`).
3. If customer must use a different domain: ensure both domains have proper authentication (SPF, DKIM, DMARC).
4. ApexMail does NOT block different Reply-To domains — it's the recipient's filter making the decision.

---

## Issue 38 — Customer uses "free mailbox" From (gmail.com) for authenticated sending

**Symptoms:** Send fails with "sender not verified" or deliverability is very poor. Customer wants to send from their `@gmail.com` address.

**Root cause:** Free email providers (Gmail, Yahoo, Outlook.com) publish strict DMARC policies (`p=reject`). Sending email "from" these domains through ApexMail will fail DMARC because ApexMail is not authorized by Google/Yahoo/Microsoft.

**Resolution:**
1. Explain: "Gmail, Yahoo, and Outlook.com have strict DMARC policies that prevent third-party services from sending on their behalf. You cannot send authenticated email from a `@gmail.com` address through ApexMail."
2. Solution: use a domain you own (even a $10/year domain works).
3. Alternative: use Reply-To with the Gmail address and From with your own domain.
4. If customer has Google Workspace (custom domain like `user@company.com`): they CAN use that domain after verification.

---

## Issue 39 — Customer using plus-addressing and their system strips it

**Symptoms:** Replies don't reach the right inbox. Tracking breaks. Customer uses `user+tag@example.com` for From or Reply-To.

**Root cause:** Plus-addressing (`user+tag@example.com`) is valid per RFC 5321, but some legacy systems or email clients strip the `+tag` portion.

**Resolution:**
1. Plus-addressing is supported by ApexMail for both From and Reply-To.
2. If replies are not routing correctly: the recipient's mail server or the customer's own mail server may strip the plus tag.
3. Workaround: use dedicated email addresses instead of plus-addressing for critical routing.
4. For tracking purposes: use ApexMail's built-in tagging and metadata features instead of plus-addressing.

---

## Issue 40 — Return-Path domain mismatch vs customer security policy

**Symptoms:** Customer's corporate security team flags emails because Return-Path domain doesn't match From domain.

**Root cause:** ApexMail sets the return-path (envelope-from) to `bounce.yourdomain.com` (if bounce CNAME is configured) or to an ApexMail domain for bounce processing (VERP). This is different from the From domain.

**Resolution:**
1. Explain: "The Return-Path is used for bounce handling and is intentionally different from the From address. This is standard practice for all email service providers."
2. If customer configured the bounce CNAME (`bounce.yourdomain.com → bounce.apexmail.io`): the return-path will be on their subdomain, which should satisfy most security policies.
3. SPF should be checked against the return-path domain — ensure SPF include covers this.
4. DMARC with relaxed alignment (`aspf=r`) allows subdomain return-paths to align with the parent domain.

---

## Issue 41 — Customer expects "send on behalf of" another domain without delegation

**Symptoms:** Customer wants to send emails appearing as `user@partnerdomain.com` without the partner adding DNS records.

**Root cause:** Email authentication requires DNS control. Without it, emails will fail SPF/DKIM/DMARC.

**Resolution:**
1. Explain: "To send as `user@partnerdomain.com`, the owner of `partnerdomain.com` must add ApexMail's DNS records (SPF, DKIM, verification) to their domain."
2. Alternative approaches:
   - Partner adds ApexMail DNS records to their domain.
   - Customer sends from their own domain with Reply-To set to the partner domain.
   - Customer uses a subdomain arrangement: partner delegates `mail.partnerdomain.com` to customer's DNS.
3. For Enterprise: contact `contact@apexmail.ee` for custom delegation setups.

---

## Issue 42 — Messages appear as "via" or "on behalf of" in email clients

**Symptoms:** Gmail shows "via apexmail.io" or Outlook shows "on behalf of" next to the sender name.

**Root cause:** Email client displays "via" when the DKIM signing domain or the return-path domain differs from the From domain. This happens when domain alignment is incomplete.

**Resolution:**
1. To remove "via" indicator:
   - Ensure DKIM CNAME is properly set (`apexmail._domainkey.yourdomain.com → apexmail._domainkey.apexmail.io`) — this makes DKIM sign with customer's domain.
   - Ensure bounce CNAME is set (`bounce.yourdomain.com → bounce.apexmail.io`) — this aligns the return-path.
   - Ensure SPF includes `spf.apexmail.io`.
2. Once full domain authentication is complete (SPF + DKIM + DMARC all passing and aligned), the "via" indicator disappears.
3. This may take 24–48 hours after DNS changes for cached results to update.

---

## Issue 43 — Customer uses multiple brands; needs separate subdomains per brand

**Symptoms:** Customer sends email for multiple brands/products and wants reputation isolation between them.

**Root cause:** Using one domain for all brands means one brand's bad reputation (bounces, complaints) affects all other brands.

**Resolution:**
1. Best practice: use a separate subdomain per brand:
   - `mail.brand-a.com` for Brand A
   - `notifications.brand-b.com` for Brand B
   - `marketing.company.com` for marketing vs `transactional.company.com` for transactional
2. Each subdomain needs separate DNS setup (SPF, DKIM, DMARC, verification).
3. Plan domain limits: Growth allows 10 domains, Scale allows 25 — sufficient for most multi-brand setups.
4. For dedicated IP isolation: each brand can use its own dedicated IP (Scale plan includes 3).
5. Also separate transactional from marketing email to protect transactional deliverability.

---

## Issue 44 — Customer wants different Reply-To per message but SDK hardcodes it

**Symptoms:** All emails have the same Reply-To despite customer wanting per-message customization.

**Root cause:** Customer's code or SDK configuration hardcodes the Reply-To field.

**Resolution:**
1. ApexMail API supports per-message Reply-To: include `reply_to` in the `POST /v1/emails` body.
2. Node.js SDK: `apexmail.emails.send({ from: {...}, to: [...], reply_to: { email: 'support@example.com', name: 'Support' }, ... })`
3. Python SDK: `apexmail.emails.send(from_=..., to=[...], reply_to={"email": "support@example.com"}, ...)`
4. If using templates with SMTP: set the `Reply-To` header in the email headers.
5. Reply-To does NOT need to be a verified domain (but using verified domains improves trust).

---

## Issue 45 — Customer sets From to unverified address and wonders why it fails

**Symptoms:** API returns `422 sender_not_verified` error.

**Root cause:** The From email address's domain is not verified in ApexMail.

**Resolution:**
1. Check Dashboard → Domains — the domain in the From address must be verified.
2. Example: sending from `hello@mynewdomain.com` requires `mynewdomain.com` to be verified.
3. Verify the domain: add DNS records (SPF, DKIM, verification TXT) and click Verify.
4. Individual email verification is also possible but domain-level is recommended.
5. Error response includes: `{"error": "sender_not_verified", "message": "The sending domain 'mynewdomain.com' is not verified"}`

---

## Issue 46 — Customer expects custom envelope-from without configuring MAIL FROM

**Symptoms:** Customer wants the bounce address to use their custom domain but bounce/envelope-from still shows ApexMail's domain.

**Root cause:** Custom envelope-from (return-path) requires the bounce CNAME DNS record to be configured.

**Resolution:**
1. Customer must add CNAME record: `bounce.yourdomain.com → bounce.apexmail.io`
2. Once configured, the return-path in emails will use `bounce.yourdomain.com` instead of ApexMail's domain.
3. This also helps remove "via" indicators (Issue 42) and improves SPF alignment.
4. The bounce CNAME is part of the standard domain setup but is sometimes skipped because verification can succeed without it.
5. Verify: send a test email and check raw headers for the `Return-Path` value.

---

## Troubleshooting Decision Tree (Section C)

```
Sender identity issue
├── "sender_not_verified" error → Issue 45
├── "via" or "on behalf of" showing → Issue 42
├── Can't send from Gmail/Yahoo → Issue 38
├── Can't send from another company's domain → Issue 25 (Section B), 41
├── Reply-To not working per-message → Issue 44
├── Security team flags return-path → Issue 40
├── Multiple brands need isolation → Issue 43
├── RFC formatting error → Issue 36
└── Plus-addressing issues → Issue 39
```
