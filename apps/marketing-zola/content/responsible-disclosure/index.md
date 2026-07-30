+++
title = "Responsible Disclosure"
description = "ApexMail Responsible Disclosure Policy — how to report security vulnerabilities."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 1. Policy

ApexMail takes the security of our systems and customers' data seriously. We welcome reports from security researchers and the public about potential vulnerabilities. This policy describes how to report security issues and what you can expect from us.

## 2. Scope

This policy applies to:

- `apexmail.ee` and all subdomains
- `api.apexmail.ee`
- `smtp.apexmail.ee`
- `app.apexmail.ee`
- `cdn.apexmail.ee`
- The ApexMail API and web application

Services not operated by ApexMail (e.g., third-party integrations) are out of scope unless the vulnerability is in our integration with that service.

## 3. How to Report

Send vulnerability reports to **[security@apexmail.ee](mailto:security@apexmail.ee)** .

Please include:

- A detailed description of the vulnerability.
- Steps to reproduce, including any proof-of-concept code.
- The affected domain, endpoint, or component.
- Your assessment of the potential impact.
- Any suggested remediation.

Encrypt sensitive reports using our [PGP key](/pgp-key.asc).

## 4. What We Promise

- Acknowledge receipt within **48 hours**.
- Provide an initial assessment within **5 business days**.
- Keep you informed of progress toward resolution.
- Not pursue legal action against researchers who follow this policy.
- Credit researchers who report valid vulnerabilities (unless you prefer to remain anonymous).

## 5. What We Ask

- Do not access, modify, or delete data that does not belong to you.
- Do not degrade the service or disrupt other users.
- Do not publicly disclose the vulnerability until we have had reasonable time to address it (target: 90 days).
- Do not test physical security, social engineering, or denial of service.

## 6. Recognition

We recognize and thank security researchers who help us improve. Valid vulnerability reports are acknowledged on this page (with the reporter's consent).

## 7. Out of Scope

The following are generally considered out of scope but will be reviewed:

- Issues without a clear security impact.
- Missing HTTP security headers that do not present a direct risk.
- Self-XSS or attacks requiring physical access to a victim's device.
- Theoretical vulnerabilities without proof of concept.
