# Tool Contract: Zone.ee

> Internal engineering document — specifies the interface contract between ApexMail and Zone.ee DNS services.

## Summary

| Aspect | Value |
|--------|-------|
| **Provider** | [Zone.ee](https://www.zone.ee/) (Estonian registrar & DNS provider) |
| **Services used** | DNS hosting, domain registration |
| **API** | Zone.ee DNS API |
| **Managed zones** | `apexmail.ee`, `apexmail.dev` |
| **Location** | Estonia (EU) |

---

## 1. DNS Management

All DNS records are managed via the **Zone.ee control panel or API** — manual ad-hoc edits outside the documented process are prohibited.

### Record Types in Use

| Record Type | Purpose | Example |
|-------------|---------|---------|
| `A` | API server, web app | `api.apexmail.ee → <Hetzner IP>` |
| `AAAA` | IPv6 for API/web | `api.apexmail.ee → <IPv6>` |
| `CNAME` | Customer domain verification | `apx._domainkey.customer.com` |
| `MX` | Inbound email routing | `apexmail.ee → mail.apexmail.ee` |
| `TXT` | SPF, DMARC, domain verification | `v=spf1 include:spf.apexmail.ee ~all` |
| `SRV` | Service discovery (internal) | `_smtp._tcp.apexmail.ee` |

### Customer Domain Verification

- When a customer adds a domain, the API generates a verification TXT record value.
- The customer adds this TXT record at their own registrar (not at Zone.ee).
- ApexMail verifies via DNS lookup — Zone.ee is not involved in customer DNS.

---

## 2. SSL/TLS

- SSL certificates are managed via **Let's Encrypt** (ACME protocol) with `certbot`.
- Certificates are issued directly to the Hetzner server — no proxy or CDN in the path.
- Auto-renewal runs via cron every 60 days.
- Certificate covers: `apexmail.ee`, `*.apexmail.ee`, `apexmail.dev`, `*.apexmail.dev`.

---

## 3. DNS-Based Failover

Zone.ee does not provide health-check-based DNS failover natively. Failover is managed by the **HA service** (`apps/ha/`):

1. HA service monitors health endpoints on both Finland and Germany servers.
2. On detected failure, HA service updates the A/AAAA records via Zone.ee API.
3. DNS TTL is kept low during degraded state (60s) to speed propagation.
4. Under normal operation, TTL is 300s (5 minutes).

### TTL Management

| State | TTL | Rationale |
|-------|-----|-----------|
| Healthy | 300s | Standard caching, reduces DNS query load |
| Degraded | 60s | Faster failover if the situation worsens |
| Failover active | 60s | Minimise stale cache impact |
| Recovery | 60s | Verify stability before raising TTL |

---

## 4. Security

- Zone.ee account secured with MFA.
- API credentials stored in secrets management (not in code).
- DNSSEC: enabled on `apexmail.ee` zone if supported by Zone.ee for the TLD.
- Access restricted to infrastructure team only.

---

## 5. Limitations

- **No CDN**: Zone.ee is a DNS registrar, not a CDN. Static assets are served directly from the Hetzner server.
- **No WAF**: Application-level rate limiting and security are handled by the Hono API middleware and Hetzner firewall rules.
- **No DDoS protection at edge**: Basic protection is provided by Hetzner's network-level DDoS mitigation. Application-level protection is handled by rate limiting middleware.
- **No traffic splitting**: Canary deployments use application-level routing, not DNS-based traffic splitting.

---

## 6. Related Contracts

- [Hetzner](./hetzner.md) — server infrastructure and firewall rules
- [SES](./ses.md) — DNS records for SES DKIM verification
