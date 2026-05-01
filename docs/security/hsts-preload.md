# HSTS Preload Readiness

ApexMail production TLS endpoints must advertise a preload-ready HSTS policy before domain-owner submission to the browser preload list.

## Required Header

`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

The nginx production config sets this header on HTTPS server blocks in `deploy/nginx/nginx.conf`.

## Submission Checklist

1. Confirm `https://apexmail.ee` and all HTTPS subdomains serve valid certificates.
2. Confirm every HTTP endpoint redirects to HTTPS.
3. Confirm the HSTS header includes `max-age` of at least `31536000`, `includeSubDomains`, and `preload`.
4. Submit `apexmail.ee` at `https://hstspreload.org` from a domain-owner account.
5. Record the accepted preload status in the release notes for that deployment.

## Local Preflight

Run:

```sh
python3 tools/check_hsts_preload.py https://apexmail.ee
```

The check validates the response header shape needed before the external submission step.
