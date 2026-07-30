# Responsible Disclosure Policy

**Last Updated:** {{LAST_UPDATED}}

## 1. Introduction

ApexMail takes the security of our platform seriously. We value the work of security researchers who help us identify and fix vulnerabilities. This policy describes how to report security issues and what you can expect.

## 2. Contact

- **Security email**: {{SECURITY_EMAIL}}
- **PGP key**: Available at `/.well-known/security.txt` and at `https://keys.openpgp.org/`
  - Key fingerprint: `AB12 CD34 EF56 7890 1234 5678 90AB CDEF 1234 5678`
  - Key ID: `0x12345678ABCDEF01`
- **Encryption**: We strongly recommend encrypting all vulnerability reports with our PGP key before sending.

## 3. Scope

### 3.1 In-Scope Systems

| System | Description |
|---|---|
| `*.apexmail.ee` | All web application endpoints (dashboard, documentation, marketing, trust center) |
| `api.apexmail.com` | REST API and all API endpoints |
| `smtp.apexmail.com` | SMTP relay infrastructure |
| `app.apexmail.com` | Customer dashboard application |
| `status.apexmail.com` | Status page infrastructure |
| `support.apexmail.com` | Support portal |

Services covered: REST API, SMTP relay, message queue, dashboard, authentication, domain verification, templates, inbound email processing, analytics, email grader, dedicated IP service, webhooks, support portal.

### 3.2 Out-of-Scope Systems

- Third-party services we do not own or operate (Stripe, Hetzner Cloud, Let's Encrypt).
- Subdomains not listed in section 3.1.
- Systems not owned or operated by {{LEGAL_NAME}}.
- Social media accounts, marketing microsites not hosted on `apexmail.ee` or `apexmail.com`.
- Physical security testing of data center facilities.

### 3.3 Out-of-Scope Vulnerability Classes

- Missing security headers that do not present a demonstrable exploit (e.g., missing `X-Frame-Options` on non-sensitive pages). Exceptions: headers listed in our Security Measures document (CSP, HSTS, CORS) are in scope.
- Clickjacking on pages with no sensitive actions.
- Self-XSS (where the attacker must social-engineer the victim into pasting code into the browser console).
- Denial of Service via resource exhaustion without a practical impact demonstration.
- Theoretical vulnerabilities without a proof of concept.
- Issues already known to us and under remediation (we will notify you if this is the case).

## 4. Prohibited Testing

When researching vulnerabilities, you must not:

### 4.1 Denial of Service

- Do not perform any testing that could degrade, disrupt, or deny service to other users.
- Do not use automated scanners that generate high volumes of traffic (rate-limit: 10 requests per second maximum).
- Do not test DoS or DDoS attack vectors.
- Do not send bulk or spam email through the platform.
- Do not attempt to exhaust API rate limits or SMTP connection limits.

### 4.2 Data Handling

- Do not access, modify, delete, or exfiltrate data that does not belong to you.
- If you accidentally access customer data, stop testing immediately, do not view further, and report the access path in your submission.
- Do not create test accounts using real personal data of third parties.
- If you identify a vulnerability that allows data access, do not enumerate or aggregate data beyond the minimum needed to demonstrate the issue.
- Do not store, share, or retain any ApexMail data obtained during testing beyond the time needed for reporting.

### 4.3 Social Engineering

- Do not attempt phishing, vishing, or smishing attacks against ApexMail personnel or customers.
- Do not impersonate ApexMail staff or support personnel.
- Do not attempt to gain access to employee devices or accounts.
- Do not test physical security controls.
- Do not attempt credential harvesting or password guessing attacks.

### 4.4 Other Restrictions

- Do not exploit vulnerabilities beyond the minimum needed to confirm the issue.
- Do not publicly disclose vulnerabilities before we have resolved them (see Section 7).
- Do not use vulnerabilities to attack other parties.
- Comply with all applicable laws and regulations.

## 5. Reporting Format

Submit reports to {{SECURITY_EMAIL}}. Your report should include:

1. **Subject line**: `[VULNERABILITY] Short description of the issue`
2. **Summary**: Brief description of the vulnerability (1–3 sentences).
3. **Affected system**: Which in-scope system(s) are affected (URLs, API endpoints, or service names).
4. **Vulnerability type**: e.g., XSS, SQL Injection, CSRF, IDOR, Authentication bypass, etc.
5. **Severity assessment**: Your assessment using CVSS 3.1 scoring or a qualitative rating (Critical / High / Medium / Low / Informational).
6. **Proof of concept**: Step-by-step reproduction instructions and any supporting material (screenshots, request/response captures, proof-of-concept code).
7. **Impact**: Description of the potential impact if exploited.
8. **Suggested remediation**: Optional — your recommendation for fixing the issue.
9. **Contact information**: Name/handle and email for follow-up communication.
10. **Disclosure preference**: Whether you plan to disclose after resolution and your preferred coordination timeline.

**Language**: Reports may be submitted in English or Estonian.

## 6. Response Process

### 6.1 Acknowledgment

- **Target**: Initial acknowledgment within 48 hours of receipt.
- You will receive a confirmation email with a reference ID.

### 6.2 Triage

- **Target**: Triage and initial severity assessment within 5 business days.
- We will validate the report and assign a severity level.

### 6.3 Updates

- **Target**: Status updates at least every 14 calendar days during investigation.
- You will be notified when the issue is validated, when a fix is being developed, and when the fix is deployed.

### 6.4 Resolution

- Critical vulnerabilities: Resolution target within 7 calendar days.
- High-severity vulnerabilities: Resolution target within 30 calendar days.
- Medium-severity vulnerabilities: Resolution target within 90 calendar days.
- Low-severity and informational: Resolution at our discretion, aligned with development sprints.

If resolution timelines cannot be met, we will communicate the reason and revised timeline.

## 7. Disclosure Coordination

- We request that you do not publicly disclose the vulnerability until we have deployed a fix and published any relevant advisory.
- We will coordinate the disclosure timeline with you.
- We will credit you in any public advisory or changelog entry, using your preferred name/handle and a link of your choice, unless you request anonymity.
- If we do not respond within 90 days of your initial report, you may disclose at your discretion.

## 8. Safe Harbor

{{LEGAL_NAME}} (trading as {{TRADING_NAME}}) provides the following safe harbor provisions for security researchers who comply with this policy:

1. We will not pursue legal action or file a complaint against you for activities conducted in accordance with this policy.
2. We will not suspend or terminate your ApexMail account for good-faith testing on your own account, provided the testing does not violate Section 4 (Prohibited Testing).
3. We consider activities conducted under this policy to constitute authorized access under applicable computer fraud and abuse laws.
4. If a third party files a legal complaint against you for activities conducted under this policy, we will make it known that your actions were authorized.
5. We will not seek to identify anonymous researchers who comply with this policy.

Safe harbor does not apply to activities that violate this policy, applicable law, or involve non-ApexMail systems.

## 9. Rewards

ApexMail does not currently operate a paid bug bounty program. Reports are acknowledged with:

- Credit in the release notes or security advisory (if desired).
- Listing on our Security Researcher Hall of Fame (if desired).
- A letter of appreciation, if requested.

We may offer discretionary rewards for exceptional reports at our sole discretion. The existence of a reward program is reviewed annually.

## 10. Hall of Fame

ApexMail gratefully acknowledges the following researchers who have responsibly disclosed security issues:

*This list will be updated as reports are received and resolved.*

| Researcher | Contribution | Date Acknowledged |
|---|---|---|
| *(Your name here)* | *(Report summary)* | *(Date)* |

## 11. Scope Updates

This policy is reviewed quarterly. Scope changes, new in-scope/out-of-scope items, and procedural updates are published here with the `Last Updated` date incremented.

Last reviewed: {{LAST_UPDATED}}
Next review: {{NEXT_REVIEW_DATE}}
