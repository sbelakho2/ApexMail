# DMARC Configuration

Domain-based Message Authentication, Reporting, and Conformance (DMARC) tells receiving mail servers how to handle email that fails SPF or DKIM authentication.

## What DMARC Does

DMARC builds on SPF and DKIM to:

1. **Verify alignment** — the `From` header domain must match the SPF-authenticated domain or DKIM-signed domain.
2. **Enforce policy** — tell receivers what to do when authentication fails (`none`, `quarantine`, `reject`).
3. **Provide reports** — receive aggregate and forensic reports about email authentication results.

## Required DMARC Record

Add a TXT record to your DNS:

| Type | Host | Value |
|---|---|---|
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; pct=100` |

## Policy Tags

| Tag | Value | Description |
|---|---|---|
| `v` | `DMARC1` | Protocol version |
| `p` | `none` / `quarantine` / `reject` | Policy for failed authentication |
| `rua` | `mailto:...` | Aggregate report recipient |
| `ruf` | `mailto:...` | Forensic report recipient |
| `pct` | `1-100` | Percentage of email to apply policy to |
| `sp` | `none` / `quarantine` / `reject` | Subdomain policy |
| `adkim` | `r` (relaxed) / `s` (strict) | DKIM alignment mode |
| `aspf` | `r` (relaxed) / `s` (strict) | SPF alignment mode |

## Recommended Rollout

| Phase | Policy | Duration |
|---|---|---|
| 1 | `p=none` | 1–2 weeks |
| 2 | `p=quarantine; pct=25` | 1 week |
| 3 | `p=quarantine; pct=50` | 1 week |
| 4 | `p=quarantine; pct=100` | 2 weeks |
| 5 | `p=reject` | Permanent |

Monitor DMARC aggregate reports at each phase to identify legitimate email that fails authentication.

## Interpreting Reports

DMARC aggregate reports (XML) show:

- How many emails passed/failed SPF and DKIM.
- Sending IP addresses.
- Disposition applied (none, quarantine, reject).

Use a DMARC report analyzer (e.g., `parsedmarc`) to process these reports:

```bash
pip install parsedmarc
parsedmarc --file dmarc-report.xml
```

## DMARC Alignment Checks

For DMARC to pass, at least one of these must align with the `From` header domain:

1. **SPF alignment**: The `Return-Path` domain must match (relaxed) or be identical to (strict) the `From` domain.
2. **DKIM alignment**: The `d=` domain in the DKIM signature must match (relaxed) or be identical to (strict) the `From` domain.

ApexMail handles alignment automatically when domains are properly configured.

## Related

- [SPF](spf.md)
- [DKIM](dkim.md)
- [Return Path](return-path.md)
- [Email Authentication Guide](../../security/email-authentication.md)
