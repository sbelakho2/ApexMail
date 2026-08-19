# Platform sender readiness

The platform sender `noreply@apexmail.ee` is a normal sender domain owned by
`system_internal_tenant01`. It is **not** a global-key exception. Account
verification, password-reset, and email-MFA messages are admitted only when
this domain meets the same current readiness requirements as customer mail.

## Safety invariants

- The system-domain migration creates a **pending** row only.
- Bootstrap generates a fresh 2048-bit per-domain RSA key pair and stores the
  private PKCS#8 PEM encrypted with `DKIM_PRIVATE_KEY_ENCRYPTION_KEY`.
- The exact generated DKIM TXT value is the only supported DKIM record. Never
  use a CNAME, a static selector, or an ApexMail-hosted DKIM target.
- In SES deployments, readiness additionally requires external (BYODKIM)
  SES signing and the generated `bounce.apexmail.ee` SPF/MX custom MAIL FROM
  records.
- In explicit SMTP deployments, direct DKIM plus DMARC are required; SES-only
  bounce records are not used.
- No route may mark the system domain verified by editing its database flags.

## Controlled bootstrap

The bootstrap operation is idempotent. It preserves valid encrypted material
and replaces incomplete, mismatched, or legacy plaintext material. It does
not mark the sender verified and does not send mail.

Use exactly one of these privileged operations:

1. Set `SYSTEM_SENDER_BOOTSTRAP_ON_STARTUP=true` for one API-server startup.
   The startup log reports only the domain, readiness, and DNS-record count;
   retrieve the record values from the control-plane endpoint below.
2. Call `POST /v1/admin/system-sender/bootstrap` as a control-plane operator
  with wildcard scope.

Then call `GET /v1/admin/system-sender`. It returns the generated DNS records
and a `ready` flag, but never returns private material. Publish those exact
records at the ApexMail zone authority. Set the startup variable back to
`false` after bootstrap.

## Verification

After DNS propagation, call `POST /v1/admin/system-sender/verify`, then query
`GET /v1/admin/system-sender` again.

The domain is usable only when both are true:

- the response `status` is `verified`; and
- the response `ready` is `true`.

For SES, a first verification attempt can remain pending while SES evaluates
DNS. Repeat only after the DNS records are externally visible. A successful
SES API request is not proof of readiness.

## Operational failure behavior

When the sender is absent, pending, encrypted with a different key, missing
its DNS records, or not SES-ready when SES is selected:

- account registration is rejected before user/tenant creation;
- password-reset requests return a service-level failure before account lookup;
- email-MFA challenges are not created; and
- no system message or queue row is inserted.

This is intentional. It prevents a `202`/`250` acknowledgement for mail that
the unified worker would later reject. Resolve the status endpoint findings;
do not reintroduce a global sender key or manually set `verified=true`.
