# B) DKIM / SPF / DMARC Correctness Playbook (Issues 19–35)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Authentication failures beyond initial DNS setup — real-world DKIM/SPF/DMARC breakage scenarios.

---

## Issue 19 — DKIM enabled for domain but sending from individually verified address changes behavior

**Symptoms:** Customer verified `example.com` with DKIM, but sends from `noreply@example.com` which was also individually verified as an email address. DKIM signatures are inconsistent or missing.

**Root cause:** When both a domain identity and an individual email identity exist, the email-level identity may take precedence depending on configuration. This can disable domain-level DKIM signing.

**Resolution:**
1. Ask: "Did you verify both the domain `example.com` AND the individual email `noreply@example.com`?"
2. If both exist: remove the individual email verification — domain verification covers all addresses on that domain.
3. Domain-level identity should be the canonical source for DKIM signing.
4. Verify in Dashboard → Domains that the domain shows DKIM ✅.

---

## Issue 20 — DKIM selector rotated but old selector still referenced (partial propagation)

**Symptoms:** DKIM passes for some recipients but fails for others. Intermittent failures.

**Root cause:** ApexMail rotated the DKIM signing key/selector, but DNS CNAME still points to old selector, or recipient DNS caches stale DKIM public key.

**Resolution:**
1. Since ApexMail uses CNAME delegation (`apexmail._domainkey → apexmail._domainkey.apexmail.io`), key rotation is handled automatically on our side.
2. If customer sees failures: ensure the CNAME still resolves — `dig CNAME apexmail._domainkey.yourdomain.com`
3. If the CNAME is correct, this is a transient caching issue. Wait for DNS TTL to expire (typically < 1 hour).
4. If customer manages their own DKIM keys (Enterprise): they must update the DNS TXT record with the new public key after rotation.

---

## Issue 21 — DKIM signature present but body hash fails

**Symptoms:** DKIM verification fails with "body hash did not verify" error in message headers.

**Root cause:** Something modified the email body after DKIM signing — footer injection by a relay, antivirus scanner, mailing list software, or corporate email gateway.

**Resolution:**
1. Ask: "Is the email passing through any intermediate systems — mailing lists, corporate gateways, antivirus scanners, or email relays?"
2. Any system that modifies the body (adds footers, rewrites URLs, strips attachments) will break the DKIM body hash.
3. Solutions:
   - Configure downstream systems to NOT modify message body.
   - Use ARC (Authenticated Received Chain) — ApexMail supports ARC headers for forwarding scenarios.
   - If a mailing list is involved, the list should re-sign with its own DKIM.

---

## Issue 22 — Forwarders/relays causing DKIM breaks; user blames ApexMail

**Symptoms:** Customer says "DKIM always fails" but only for certain recipients. Works fine for direct delivery.

**Root cause:** Email forwarding (e.g., university .edu forwarding to Gmail) breaks DKIM because the forwarder may modify headers or body. SPF also fails because the forwarder's IP isn't in the sender's SPF record.

**Resolution:**
1. Ask: "Do the failing recipients use email forwarding (e.g., `john@university.edu` forwards to `john@gmail.com`)?"
2. Explain: "Email forwarding breaks both SPF (wrong sending IP) and potentially DKIM (if body is modified). This is a known industry-wide issue, not specific to ApexMail."
3. Mitigation: DMARC with relaxed alignment helps. ARC (Authenticated Received Chain) preserves authentication across hops.
4. ApexMail adds ARC headers to help preserve authentication chain.
5. Ultimate fix: recipient should use IMAP/POP to pull mail instead of forwarding.

---

## Issue 23 — SPF passes but DKIM fails and DMARC fails due to strict alignment

**Symptoms:** SPF passes, DKIM fails, DMARC fails. Customer has `adkim=s` (strict) in DMARC.

**Root cause:** DMARC requires EITHER SPF-aligned OR DKIM-aligned pass. If DKIM fails and SPF alignment is also strict (`aspf=s`), the SPF pass doesn't help if the return-path domain doesn't exactly match the From domain.

**Resolution:**
1. Check DMARC record: `dig TXT _dmarc.yourdomain.com`
2. If `adkim=s` and DKIM is failing: fix DKIM (see Issues 3, 4, 14).
3. If both `adkim=s` and `aspf=s`: either fix DKIM OR change to relaxed alignment: `adkim=r; aspf=r`.
4. ApexMail recommends `adkim=r; aspf=r` (relaxed) for most customers because the return-path uses `bounce.yourdomain.com` (subdomain).

---

## Issue 24 — SPF fails because customer's SPF doesn't include return-path domain

**Symptoms:** SPF fails. Customer included `spf.apexmail.io` but return-path uses a different domain.

**Root cause:** SPF is checked against the domain in the envelope-from (return-path), NOT the From header. If the return-path is `bounce.yourdomain.com`, SPF must pass for `bounce.yourdomain.com`.

**Resolution:**
1. ApexMail sets return-path to `bounce.yourdomain.com` when the bounce CNAME is configured.
2. If customer didn't add the bounce CNAME (`bounce → bounce.apexmail.io`), return-path may use ApexMail's domain directly, and SPF should pass through ApexMail's own SPF.
3. If customer added bounce CNAME: SPF should be on the root domain — `include:spf.apexmail.io` in root domain's SPF covers subdomains.
4. Verify: `dig TXT yourdomain.com | grep spf` should show `include:spf.apexmail.io`.

---

## Issue 25 — Customer uses a 3rd-party "From" domain without rights to authenticate it

**Symptoms:** Customer tries sending from `user@nottheirdomain.com`. Domain verification fails.

**Root cause:** Customer doesn't control the DNS for the From domain, so they can't add SPF/DKIM/DMARC records.

**Resolution:**
1. Explain: "You can only send from domains you own and can verify. To verify a domain, you must add DNS records to it."
2. If they need to send on behalf of another organization: that organization must add the DNS records, or the customer should use their own domain.
3. Alternative: use Reply-To set to the other address while sending From their own verified domain.
4. For Enterprise customers with delegation needs: contact `contact@apexmail.ee` for custom arrangement.

---

## Issue 26 — DMARC set to p=reject while still testing

**Symptoms:** Legitimate mail is being rejected by recipients. Customer just started using ApexMail.

**Root cause:** Customer set DMARC policy to `p=reject` before confirming all authentication is working. Any SPF or DKIM failure causes immediate rejection.

**Resolution:**
1. **Immediately** change DMARC to `p=none` to stop rejections: `v=DMARC1; p=none; rua=mailto:dmarc@apexmail.io`
2. Monitor DMARC aggregate reports (`rua`) for 2–4 weeks.
3. Once reports show >99% pass rate: upgrade to `p=quarantine`.
4. After another 2 weeks of clean reports: upgrade to `p=reject`.
5. Recommended progression: `p=none` → `p=quarantine` → `p=reject`.

---

## Issue 27 — DMARC reporting addresses misformatted (rua/ruf)

**Symptoms:** Customer never receives DMARC aggregate reports despite having `rua` tag.

**Root cause:** Malformed `rua` / `ruf` tags. Common issues: missing `mailto:`, using `http://` instead, typo in email address, or external domain without proper DNS authorization.

**Resolution:**
1. Check format: `rua=mailto:dmarc-reports@yourdomain.com` (must have `mailto:` prefix).
2. If reporting to external domain (e.g., `rua=mailto:dmarc@apexmail.io`): the receiving domain should have a DNS TXT record: `yourdomain.com._report._dmarc.apexmail.io TXT "v=DMARC1"`. ApexMail already has this configured for `apexmail.io`.
3. Multiple addresses: `rua=mailto:addr1@example.com,mailto:addr2@example.com` (comma-separated, each with `mailto:`).
4. `rua` = aggregate reports (daily XML), `ruf` = forensic/failure reports (per-message, privacy-sensitive).

---

## Issue 28 — DMARC policy uses strict alignment but customer expects relaxed behavior

**Symptoms:** DMARC fails for subdomains. Customer says "I set up everything on my root domain."

**Root cause:** Strict alignment (`aspf=s; adkim=s`) requires exact domain match. If sending from `mail.example.com` but SPF/DKIM are on `example.com`, strict alignment fails.

**Resolution:**
1. Check alignment tags in DMARC: default is relaxed (`aspf=r; adkim=r`).
2. If customer explicitly set strict: explain that subdomains won't match parent domain.
3. Fix: change to `aspf=r; adkim=r` or add separate SPF/DKIM for the subdomain.
4. ApexMail recommends relaxed alignment for most use cases.

---

## Issue 29 — BIMI requested but DMARC not enforced → BIMI won't work

**Symptoms:** Customer wants their brand logo in email clients (BIMI) but it's not showing.

**Root cause:** BIMI requires DMARC at `p=quarantine` or `p=reject`. If DMARC is `p=none`, BIMI won't activate.

**Resolution:**
1. Check DMARC policy: must be at least `p=quarantine` (Gmail requires `p=quarantine` or `p=reject` for BIMI).
2. BIMI also requires a VMC (Verified Mark Certificate) for Gmail.
3. BIMI DNS record: TXT record at `default._bimi.yourdomain.com` with `v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem`.
4. Steps: Fix DMARC → Get VMC → Add BIMI DNS record.
5. ApexMail supports BIMI headers — once DNS is correct, logos will appear in supported clients.

---

## Issue 30 — MTA-STS record missing, policy file missing, or wrong HTTPS cert

**Symptoms:** MTA-STS validation fails. Some security-conscious senders may refuse to deliver to the domain.

**Root cause:** MTA-STS (RFC 8461) requires: (1) DNS TXT record at `_mta-sts.yourdomain.com`, (2) HTTPS policy file at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`, and (3) valid TLS certificate on the MX hosts. Any of these missing or misconfigured breaks MTA-STS.

**Resolution:**
1. MTA-STS is optional but recommended for security.
2. DNS record: `_mta-sts.yourdomain.com TXT "v=STSv1; id=20240101T000000"`
3. Policy file at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`:
   ```
   version: STSv1
   mode: enforce
   mx: mx1.apexmail.io
   mx: mx2.apexmail.io
   max_age: 604800
   ```
4. The id in the DNS record must change whenever the policy file changes.
5. Start with `mode: testing` before `mode: enforce`.

---

## Issue 31 — TLS-RPT record malformed (no reports arriving)

**Symptoms:** Customer set up TLS-RPT but receives no reports.

**Root cause:** Malformed `_smtp._tls` DNS record.

**Resolution:**
1. Correct format: TXT record at `_smtp._tls.yourdomain.com` → `v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com`
2. Common errors: missing `v=TLSRPTv1`, wrong record name, missing `mailto:` prefix.
3. Reports are sent by receiving MTAs (Gmail, Microsoft, etc.) — it may take days for the first report.

---

## Issue 32 — Reverse DNS expectations confused (dedicated IP scenarios)

**Symptoms:** Customer on Growth/Scale/Enterprise with dedicated IP asks about rDNS (PTR record). Worried about deliverability.

**Root cause:** Reverse DNS (PTR record) maps IP → hostname. For dedicated IPs, this should be set to match the sending hostname (e.g., `mail.example.com` or ApexMail's hostname).

**Resolution:**
1. For **shared IPs**: ApexMail manages rDNS. Customer doesn't need to do anything.
2. For **dedicated IPs** (Growth option, Scale 3 included, Enterprise unlimited): ApexMail sets the PTR record to our sending hostname. If customer wants custom rDNS (e.g., `mail.example.com`), contact `contact@apexmail.ee`.
3. rDNS should match the HELO/EHLO hostname used by the MTA.
4. Mismatched rDNS can hurt deliverability with some ISPs (especially Microsoft).

---

## Issue 33 — "Unauthenticated email not accepted" errors

**Symptoms:** Recipient server rejects email with messages like "unauthenticated mail not accepted", "550 5.7.26 unauthenticated email from domain is not accepted", or "authentication failure".

**Root cause:** Receiving server enforces DMARC/SPF/DKIM and the sender's authentication is failing.

**Resolution:**
1. Check all three: SPF, DKIM, DMARC.
2. Get message headers from a test email — look for `Authentication-Results` header.
3. Common causes:
   - SPF missing `include:spf.apexmail.io` → Issue 5
   - DKIM CNAME misconfigured → Issues 3, 4, 14
   - DMARC policy at `p=reject` with alignment failure → Issue 11
4. Fix authentication, then resend.
5. Gmail in particular enforces this strictly: `550-5.7.26 This mail is unauthenticated, which poses a security risk`.

---

## Issue 34 — Customer tries to send as no-reply@rootdomain but verified only subdomain

**Symptoms:** Send fails with "sender not verified" error. Customer verified `mail.example.com` but tries to send From `noreply@example.com`.

**Root cause:** Domain verification is specific. Verifying `mail.example.com` only allows sending from `*@mail.example.com`, not from `*@example.com`.

**Resolution:**
1. Verify the exact domain used in the From address.
2. If customer wants to send from `noreply@example.com`: verify `example.com` and add DNS records for the root domain.
3. If customer wants to send from `noreply@mail.example.com`: they already have this — just change the From address.
4. Customer can verify multiple domains in Dashboard → Domains.

---

## Issue 35 — Customer expects multiple From domains on one verified identity

**Symptoms:** Customer verified `example.com` and expects to also send from `example.org` or `anotherbrand.com` without additional verification.

**Root cause:** Each sending domain requires separate verification and DNS setup. Domain verification is per-domain, not per-account.

**Resolution:**
1. Explain: "Each domain you want to send from needs to be separately verified with its own DNS records."
2. Add each domain in Dashboard → Domains → Add Domain.
3. For each domain, add: SPF include, DKIM CNAME, DMARC TXT, verification TXT.
4. Plan limits apply: Free (1 domain), Starter (3), Pro (5), Growth (10), Scale (25), Enterprise (unlimited).
5. If customer needs more domains than their plan allows: upgrade plan or contact `contact@apexmail.ee`.

---

## Troubleshooting Decision Tree (Section B)

```
Authentication failure reported
├── DKIM fails
│   ├── Body hash mismatch → Email modified downstream (Issue 21)
│   ├── Signature not found → Check CNAME (Section A Issues 3, 4, 14)
│   ├── Selector not found → Rotation/propagation (Issue 20)
│   └── Only fails for forwarded mail → Forwarder issue (Issue 22)
├── SPF fails
│   ├── Return-path domain mismatch → Issue 24
│   ├── Missing include → Section A Issue 5
│   └── Can't add records → Not their domain (Issue 25)
├── DMARC fails
│   ├── Both SPF and DKIM fail → Fix both
│   ├── Strict alignment with subdomain → Issue 23, 28
│   ├── p=reject during testing → Issue 26
│   └── Reports not arriving → Issue 27
├── "Unauthenticated" rejection → Issue 33
├── "Sender not verified" → Wrong domain scope (Issue 34, 35)
└── BIMI not showing → Issue 29
```
