# IP Pool Rotation

ApexMail rotates sending across multiple IP addresses to maintain deliverability and provide resilience.

## Shared IP Pools

On Shared EU Cloud plans, your email is sent from ApexMail's shared IP pools:

- **Multiple IP addresses** across different subnets.
- **Automatic load balancing** across available IPs.
- **Automatic warming** of new IPs added to the pool.
- **Reputation monitoring** — low-reputation IPs are automatically removed.
- **No configuration needed** — works out of the box.

## Dedicated IPs

Scale and Enterprise plans can use dedicated IPs:

- **Exclusive IP addresses** — not shared with other customers.
- **Full control** over sending reputation.
- **Predictable volume capacity**.
- **Required warm-up** — 2–4 weeks.

### Request Dedicated IPs

1. **Dashboard → Domains → [domain] → IP Configuration**.
2. Select "Dedicated IPs."
3. Specify the number of IPs (minimum 2 recommended for redundancy).
4. Plan the warm-up schedule with ApexMail's deliverability team.

### Dedicated IP Rotation

Dedicated IPs automatically rotate within your pool:

- Emails are distributed across all dedicated IPs.
- If an IP's reputation degrades, it's temporarily removed from rotation.
- ApexMail monitors IP health and alerts on reputation degradation.
- Manual rotation is available via API (Enterprise only).

```bash
curl -s -X POST https://api.apexmail.ee/v1/ips/rotate \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "action": "pause"}' \
  | jq .
```

## IP Pool Configuration

| Plan | IP Type | Rotation |
|---|---|---|
| Free | Shared | Automatic |
| Starter | Shared | Automatic |
| Scale | Shared or Dedicated | Automatic (shared) / Automatic + Manual (dedicated) |
| Enterprise | Dedicated | Automatic + Manual + Custom policies |

## Reputation Management

ApexMail monitors:

- IP blacklist status (Spamhaus, Barracuda, etc.).
- Complaint rates per IP.
- Bounce rates per IP.
- Delivery success rates.
- Engagement rates (opens, clicks).

## Warm-Up Schedule for Dedicated IPs

| Day | Volume | Type |
|---|---|---|
| 1–3 | 50–100 | High-engagement recipients only |
| 4–7 | 200–500 | Increasing daily |
| 8–14 | 1,000–5,000 | Broader audience |
| 15–21 | 10,000–50,000 | Full send volume |
| 22–28 | Full volume | Full audience |

Increase volume only if bounce/complaint rates remain within acceptable limits.

## Related

- [DKIM](dkim.md)
- [SPF](spf.md)
- [DMARC](dmarc.md)
- [Provider Troubleshooting](provider-troubleshooting.md)
