# Delivery Options

ApexMail is deployed with one delivery transport at a time. Operators select
the transport with `EMAIL_TRANSPORT_TYPE`; the current deployment default is
AWS SES (`ses`). ApexMail does not automatically choose SES or SMTP per
message, tenant, plan, or dedicated-IP assignment.

## AWS SES

With `EMAIL_TRANSPORT_TYPE=ses`, every verified domain has an SES identity
configured with bring-your-own DKIM (BYODKIM) and a custom MAIL FROM domain.
SES signs messages using the domain's generated private key after SES reports
the identity and MAIL FROM domain ready.

## SMTP relay

With `EMAIL_TRANSPORT_TYPE=smtp`, the worker sends through the configured SMTP
relay and signs each message locally with the same per-domain DKIM key. SMTP
must not be enabled unless local DKIM signing is enabled.

## DNS requirements

After creating a domain, retrieve `GET /v1/domains/:id/dns-records`. It is the
authoritative source for that domain's generated selector and public key.

| Type | Host | Value |
|------|------|-------|
| TXT | `bounce` | `v=spf1 include:amazonses.com ~all` |
| MX | `bounce` | `10 feedback-smtp.<aws-region>.amazonses.com` |
| TXT | `<selector>._domainkey` | `v=DKIM1; k=rsa; p=<domain-specific-public-key>` |
| TXT | `_dmarc` | A DMARC policy for your domain |

The MX hostname includes the SES region selected by the operator. Do not use a
generic ApexMail SPF include, an ApexMail return-path CNAME, or SES Easy-DKIM
CNAME records. DNS records are not interchangeable between domains.

## Related

- [Getting Started](getting-started.md)
- [Quickstart — Send Your First Email](../quickstart.md)
