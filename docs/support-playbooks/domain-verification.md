# Domain Verification Playbook

> **Audience:** Internal ops/support team  
> **Last updated:** 2026-02-09  
> **Owner:** Engineering & support team  
> **Severity default:** P3 (escalate to P2 if blocking Enterprise onboarding)

---

## Symptoms

- Customer reports domain verification fails in the ApexMail dashboard
- DNS records "not found" error after customer claims they added them
- Verification status stuck in "Pending" for >24 hours
- Customer unable to send emails because domain is unverified
- DKIM/SPF/DMARC checks fail despite records being added
- Dashboard shows partial verification (e.g., SPF passes but DKIM fails)

### How customers typically report this

- "I added the DNS records but it still says pending"
- "Domain verification failed, I don't know what's wrong"
- "I can't figure out where to add the CNAME record"
- "My registrar doesn't have an option for this type of record"
- "It's been 48 hours and my domain still isn't verified"
- "I added the records exactly as shown but it's not working"

---

## Diagnosis

### Step 1: Identify the domain and required records

```sql
-- Look up the domain and its verification status
SELECT
  d.id,
  d.domain,
  d.tenant_id,
  d.verification_status,   -- 'pending', 'verified', 'failed'
  d.spf_verified,
  d.dkim_verified,
  d.dmarc_verified,
  d.return_path_verified,
  d.verification_token,
  d.created_at,
  d.last_check_at,
  d.failure_reason
FROM domains d
WHERE d.domain = 'example.com'
   OR d.tenant_id = 'TENANT_ID';
```

**Required DNS records for full verification:**

| Record | Type | Host/Name | Value |
|--------|------|-----------|-------|
| SPF | TXT | `@` (root) | `v=spf1 include:_spf.apexmail.ee ~all` |
| DKIM | TXT | `{selector}._domainkey` | `v=DKIM1; k=rsa; p={public key from dashboard}` |
| DMARC | TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.ee` |
| Return-Path | CNAME | `bounce` | `bounce.apexmail.ee` |
| Verification | TXT | `@` (root) | `apexmail-verify=TOKEN_VALUE` |

### Step 2: Check DNS propagation

```bash
# Replace 'example.com' with the customer's domain

# Check verification TXT record
dig TXT example.com +short
# Look for: "apexmail-verify=abc123..."

# Check SPF record
dig TXT example.com +short | grep "v=spf1"
# Expected: "v=spf1 include:_spf.apexmail.ee ~all"
# Or if they have existing SPF: "v=spf1 include:_spf.apexmail.ee include:_spf.google.com ~all"

# Check DKIM TXT record
dig TXT apexmail._domainkey.example.com +short
# Expected: "v=DKIM1; k=rsa; p=..."

# Check DMARC
dig TXT _dmarc.example.com +short
# Expected: "v=DMARC1; p=quarantine; ..."

# Check Return-Path CNAME
dig CNAME bounce.example.com +short
# Expected: bounce.apexmail.ee.
```

**Use multiple DNS resolvers to rule out propagation delays:**

```bash
# Check against Google DNS
dig @8.8.8.8 TXT example.com +short

# Check against Cloudflare DNS
dig @1.1.1.1 TXT example.com +short

# Check against authoritative nameserver
dig NS example.com +short
# Then query the authoritative server directly:
dig @ns1.example-registrar.com TXT example.com +short
```

### Step 3: Check TTL and propagation timing

```bash
# Check TTL on existing records
dig TXT example.com | grep -A1 "ANSWER SECTION"
# Look at the TTL value (in seconds)
# 300 = 5 minutes, 3600 = 1 hour, 86400 = 24 hours
```

**Propagation expectations:**

| TTL | Expected propagation | Notes |
|-----|---------------------|-------|
| 300 (5 min) | 5-15 minutes | Most modern registrars |
| 3600 (1 hour) | 1-4 hours | Common default |
| 14400 (4 hours) | 4-12 hours | Some older registrars |
| 86400 (24 hours) | 24-48 hours | Worst case |

If the customer just added records, ask when they added them and compare against the TTL.

### Step 4: Identify common issues

#### Issue: Wrong value format in DKIM TXT record

The DKIM record must have a specific format. Verify the content is correct:

```bash
dig TXT apexmail._domainkey.example.com +short
# Expected: "v=DKIM1; k=rsa; p=MIGf..."
```

The value must start with `v=DKIM1; k=rsa; p=` followed by the base64 public key shown in the ApexMail dashboard. Copy the value exactly as displayed — do not add or remove spaces.

#### Issue: Wrong subdomain / host field

Customers often confuse what to put in the "Host" or "Name" field:

| Registrar | Host field for `apexmail._domainkey.example.com` |
|-----------|--------------------------------------------------|
| GoDaddy | `apexmail._domainkey` |
| Namecheap | `apexmail._domainkey` |
| Cloudflare | `apexmail._domainkey` |
| Google Domains | `apexmail._domainkey` |
| Route 53 | `apexmail._domainkey.example.com` (FQDN required) |
| Hetzner DNS | `apexmail._domainkey` |

**Common mistakes:**
- Entering full domain: `apexmail._domainkey.example.com.example.com` (doubled)
- Missing the underscore: `apexmail.domainkey` instead of `apexmail._domainkey`
- Adding the record to the wrong domain/zone

#### How to find the DKIM public key for the customer

ApexMail generates a unique DKIM keypair per domain. The customer must add a TXT record with the exact public key shown in the dashboard:

```bash
# Retrieve the DKIM key for a domain via admin API
curl -s "http://api.apexmail.internal/admin/domains/example.com/dkim-key" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.public_key'
```

The customer adds a TXT record:
- Host: `{selector}._domainkey` (e.g., `apexmail._domainkey`)
- Value: `v=DKIM1; k=rsa; p={public key from dashboard}`

Note: Different domains have different DKIM public keys. Never reuse the key from another domain.

#### Issue: SPF record conflicts

If the customer already has an SPF record, they must **merge** rather than add a second one (only one SPF record is allowed per domain):

```bash
# Check for multiple SPF records (this is an error)
dig TXT example.com +short | grep "v=spf1" | wc -l
# Should be exactly 1
```

**Merging SPF records:**
- ❌ Wrong: Two separate TXT records with `v=spf1`
- ✅ Correct: `v=spf1 include:_spf.apexmail.ee include:_spf.google.com ~all`

#### Issue: Registrar-specific quirks

| Registrar | Known issue | Workaround |
|-----------|-------------|------------|
| GoDaddy | Strips underscores from subdomains | Use "Host" field exactly as shown, contact GoDaddy support if stripped |
| Wix | Limited DNS record types | Customer must use external DNS (recommend Cloudflare) |
| Squarespace | Limited DNS record types for `_domainkey` | Use external DNS (recommend Cloudflare) |
| AWS Route 53 | Requires FQDN with trailing dot | Enter `apexmail._domainkey.example.com.` |
| Hetzner DNS Console | Sometimes caches old records | Wait 10 minutes, clear browser cache |

### Step 5: Trigger a re-verification

```bash
# Force re-check via admin API
curl -X POST "http://api.apexmail.internal/admin/domains/example.com/verify" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

```sql
-- Check the verification attempt log
SELECT
  attempt_at,
  check_type,
  result,
  failure_reason,
  dns_response
FROM domain_verification_attempts
WHERE domain = 'example.com'
ORDER BY attempt_at DESC
LIMIT 10;
```

---

## Resolution

### DNS records are correctly configured

1. Trigger re-verification via the admin API
2. If verification passes, notify the customer
3. If it still fails despite correct records, check if our verification service has a caching issue:
   ```bash
   # Clear DNS cache on the API server
   systemctl restart systemd-resolved
   ```

### DNS records are misconfigured

1. Identify the specific issue (see Step 4 above)
2. Send the customer clear, registrar-specific instructions
3. Offer to walk them through it on a screen-share if needed
4. Set a reminder to re-check in 24 hours if TTL is high

### Customer cannot add required record type

1. Determine which record type is unsupported by their registrar
2. Provide alternative record format (e.g., TXT instead of CNAME for DKIM)
3. If the registrar is severely limited, recommend migrating DNS to Cloudflare (free tier works):
   - Point nameservers to Cloudflare
   - Replicate existing records
   - Add ApexMail records
   - Keep registrar for domain registration only

### Domain is stuck in "Pending" state

```sql
-- Reset verification status to allow fresh attempts
UPDATE domains
SET verification_status = 'pending',
    last_check_at = NULL,
    failure_reason = NULL
WHERE domain = 'example.com';
```

Then trigger re-verification.

---

## Escalation

| Condition | Action |
|-----------|--------|
| Records correct but verification keeps failing | Escalate to engineering — possible bug |
| Registrar actively blocks required DNS records | Escalate to engineering for alternative verification method |
| Enterprise customer onboarding blocked | P2 — escalate to engineering and notify account manager |
| Multiple customers reporting same issue | Possible platform bug — escalate to engineering |
| Customer's DNS provider is under DDoS/outage | Document and wait, notify customer of external issue |

---

## Related

- [Deliverability Triage](deliverability-triage.md) — DNS issues affect deliverability
- [Bounce Investigation](bounce-investigation.md) — authentication failures cause bounces
- [API Errors](api-errors.md) — domain verification API endpoints
- User-facing domain setup guide: `https://docs.apexmail.ee/guides/domain-setup`
- Domain verification source: `apps/api/src/routes/domains/`
- MTA authentication checks: `apps/mta/src/`

---

## Appendix: Registrar-specific guides

### Cloudflare

1. Log in to Cloudflare dashboard → Select domain → DNS
2. Click "Add record"
3. For TXT (DKIM): Type=TXT, Name=`apexmail._domainkey`, Content=`v=DKIM1; k=rsa; p={key from dashboard}`, Proxy=DNS Only (gray cloud)
4. For TXT (SPF): Type=TXT, Name=`@`, Content=`v=spf1 include:_spf.apexmail.ee ~all`
5. **Important:** DKIM TXT record must be "DNS Only" (gray cloud), not proxied

### GoDaddy

1. My Products → Domain → DNS → Manage
2. Click "Add" under DNS Records
3. For TXT (DKIM): Type=TXT, Name=`apexmail._domainkey`, Value=`v=DKIM1; k=rsa; p={key from dashboard}`, TTL=1 Hour
4. For TXT (SPF): Type=TXT, Name=`@`, Value=`v=spf1 include:_spf.apexmail.ee ~all`, TTL=1 Hour

### Namecheap

1. Domain List → Manage → Advanced DNS
2. Click "Add New Record"
3. For TXT (DKIM): Type=TXT Record, Host=`apexmail._domainkey`, Value=`v=DKIM1; k=rsa; p={key from dashboard}`, TTL=Automatic
4. For TXT (SPF): Type=TXT Record, Host=`@`, Value=`v=spf1 include:_spf.apexmail.ee ~all`, TTL=Automatic

### Hetzner DNS Console

1. DNS Console → Select zone → Add record
2. For TXT (DKIM): Type=TXT, Name=`apexmail._domainkey`, Value=`v=DKIM1; k=rsa; p={key from dashboard}`
3. For TXT (SPF): Type=TXT, Name=`@`, Value=`v=spf1 include:_spf.apexmail.ee ~all`
