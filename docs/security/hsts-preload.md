# HSTS Preload Readiness

ApexMail production TLS endpoints advertise a preload-ready HSTS policy for domain-owner submission to the browser preload list.

## Current HSTS Header

The application server (`api-server`) sets the following HSTS header on all HTTPS responses:

`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

This is configured in [`services/mail-server/crates/api-server/src/app.rs`](../../services/mail-server/crates/api-server/src/app.rs:558).

## HSTS Preload Requirement

To submit a domain to the browser HSTS preload list at <https://hstspreload.org>, the following header is required:

`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

The header now satisfies all three preload requirements:
- `max-age=63072000` (2 years) — exceeds the minimum of 1 year
- `includeSubDomains` — covers all subdomains
- `preload` — signals readiness for hardcoded preloading

## Preload Submission Checklist

1. Confirm `https://apexmail.ee` and all HTTPS subdomains serve valid certificates.
2. Confirm every HTTP endpoint redirects to HTTPS.
3. ✅ HSTS header updated to `max-age=63072000; includeSubDomains; preload` in the application code.
4. Submit `apexmail.ee` at `https://hstspreload.org` from a domain-owner account.
5. Record the accepted preload status in the release notes for that deployment.

## Local Preflight

Run:

```sh
python3 tools/check_hsts_preload.py https://apexmail.ee
```

The check validates the response header shape needed before the external submission step.
