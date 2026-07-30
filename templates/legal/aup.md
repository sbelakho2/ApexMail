# Acceptable Use Policy (AUP)

**Last Updated:** {{LAST_UPDATED}}

This Acceptable Use Policy ("AUP") defines acceptable and prohibited uses of the ApexMail email infrastructure platform (the "Service"), operated by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, registered at **{{ADDRESS}}**, Republic of Estonia.

By using the Service, you agree to comply with this AUP. Violation may result in suspension or termination of your account.

## 1. Purpose

This AUP protects the integrity, deliverability, and reputation of the ApexMail platform and its users, and ensures compliance with applicable EU and Estonian law.

## 2. Email Categories

### 2.1 Marketing/Promotional Email

Email sent for promotional, advertising, or informational bulk purposes (newsletters, product announcements, promotional offers, survey invitations).

**Customer remains responsible for classifying email as marketing or transactional and for maintaining a lawful basis for each classification under applicable law.**

| Requirement | Detail |
|---|---|
| Consent | Explicit opt-in consent required before sending. Pre-checked boxes are not valid consent. Double opt-in recommended. |
| Lawful basis | Sender must identify, document, and maintain the lawful basis for processing (e.g., consent under GDPR Article 6(1)(a), legitimate interest where legally valid). Sender bears sole responsibility for ensuring a valid lawful basis exists for each marketing communication. |
| Unsubscribe | Required — functional unsubscribe link in every email. Requests must be processed immediately or within 24 hours. One-click unsubscribe (RFC 8058) is mandatory. |
| List-Unsubscribe | Required — List-Unsubscribe header (mailto + URL) per RFC 8058 one-click. |
| Consent records | Must be maintained (timestamp, IP, source, consent wording). |
| Sender identification | `From` name and address must accurately identify the sender. Physical mailing address required for commercial email. |
| Purchased lists | **Prohibited.** Sending to email addresses purchased, rented, or obtained from third-party list providers is forbidden. |
| Suppression | Recipients who have unsubscribed or complained must be suppressed from all marketing sends. Address must not be re-added without a new, documented opt-in. |
| Content | Marketing content only. Must not be sent through transactional streams. |

### 2.2 Transactional/Service Email

Email triggered by a user action or system event that the recipient expects to receive because the email is necessary for the service the recipient requested (password resets, security alerts, invoices, account notifications, order confirmations, receipts, welcome/onboarding emails).

**Customer remains responsible for classifying email as transactional. An email is transactional only if it is necessary for the service. Disguised marketing in a transactional email is a violation.**

| Requirement | Detail |
|---|---|
| Consent | Not required — implied by user action (e.g., placing an order, requesting password reset). Must be directly necessary for the service provided. |
| Unsubscribe | Not required for service-necessary transactional email (e.g., password reset, account security notice). Recommended for non-security transactional email (e.g., welcome messages). If provided, must be honored. |
| List-Unsubscribe | Recommended but not required. |
| Sender identity | `From` name and address must accurately identify the sender. Deceptive or misleading sender identities are prohibited. |
| Content restriction | Must not contain marketing or promotional content. Transactional emails are for service-related information only. No promotional cross-sells, upsells, or marketing copy disguised as service communication. |
| Retention | Data must be retained only for as long as necessary to fulfil the service purpose or comply with legal obligations. Routine transactional data (e.g., delivery receipts, authentication logs) must not be retained beyond operational and legal necessity. |
| Purpose-specific treatment | Each message category is treated according to its specific legal purpose. Authentication codes are security measures (GDPR Art. 32). Invoices are financial records subject to retention. Service confirmations are contract-performance communications. Sender must apply the correct framework per category. |
| Misclassification | Sending marketing email through a transactional stream is prohibited and will result in suspension. |

### 2.3 Legally Required Communications

Email sent to comply with a legal obligation (privacy policy updates, terms of service changes, data breach notifications required by law, regulatory disclosures).

| Requirement | Detail |
|---|---|
| Consent | Not required — sent as a legal obligation. |
| Unsubscribe | Not applicable — recipients cannot opt out of legally mandated communications. |
| Content restriction | Must be limited to the legally required information. Must not contain marketing or promotional content. |
| Frequency | Limited to what is legally necessary. |

### 2.4 Security and Authentication Messages

Email sent for account security purposes (MFA/2FA codes, login alerts, password change confirmations, suspicious activity notifications, API key rotation notices, session termination alerts).

| Requirement | Detail |
|---|---|
| Consent | Not required — sent as a security measure. |
| Unsubscribe | Not applicable — recipients cannot opt out of security messages. |
| Content restriction | Must be limited to security-relevant information. Must not contain marketing or promotional content. Must not link to promotional materials. |
| Delivery priority | Security messages should be sent with highest delivery priority and must not be batched or delayed. |

## 3. Prohibited Activities

The following are expressly prohibited.

### 3.1 Data Quality Violations

- **Purchased lists**: Sending to email addresses purchased, rented, or obtained from third-party list providers.
- **Scraped lists**: Sending to email addresses harvested from websites, social media, or public directories without consent.
- **Address harvesting**: Automated or manual collection of email addresses from public sources for unsolicited mailing.
- **List bombing**: Subscribing a target email address to large numbers of mailing lists.
- **Recycled or stale lists**: Sending to lists that have not been engaged with in the past 12 months without re-verification.

### 3.2 Deceptive Practices

- **Phishing**: Emails designed to fraudulently obtain personal information, credentials, or financial data.
- **Impersonation**: Sending email that falsely claims to originate from another person, organization, or brand without authorization.
- **Snowshoe spam**: Distributing spam across many IP addresses and domains to evade rate limits and reputation filters.
- **Affiliate spam**: Sending unsolicited commercial email promoting third-party products or services for commission.
- **Advance-fee fraud**: "419" scams, lottery scams, inheritance scams, or other fraudulent schemes.
- **Cryptocurrency scams**: Emails promoting fraudulent cryptocurrency investments, giveaways, or schemes.

### 3.3 Malicious Content

- **Malware**: Emails containing viruses, trojans, ransomware, worms, or other malicious code.
- **Malicious attachments**: Attachments designed to compromise recipient systems.
- **Exploit links**: Links to websites hosting malware, exploit kits, or phishing pages.

### 3.4 Evasion and Abuse

- **Suppression evasion**: Attempting to send to suppressed or unsubscribed addresses by modifying the address (e.g., `user+1@example.com`).
- **Content obfuscation**: Using invisible text, hash-busting, or image-only emails to evade spam filters.
- **Undisclosed third-party sending**: Using ApexMail to send email on behalf of undisclosed third parties.
- **Sandboxing and burner accounts**: Creating accounts solely to test or abuse platform limits.
- **Feedback loop abuse**: Ignoring or suppressing complaint feedback loop data.

### 3.5 Legal Violations

- Sending content that violates applicable laws, including:
  - EU General Data Protection Regulation (GDPR).
  - ePrivacy Directive (2002/58/EC, as amended).
  - Estonian Information Society Services Act (Infoühiskonna teenuse seadus).
  - CAN-SPAM Act (for email sent to US recipients).
  - CASL (for email sent to Canadian recipients).
  - Any applicable local anti-spam or data protection legislation.

### 3.6 Platform Abuse

- Attempting to bypass rate limits, quotas, or throttling.
- Sharing API keys or credentials with unauthorized parties.
- Using the Service for DDoS attacks, network scanning, or infrastructure probing.
- Reverse engineering, decompiling, or attempting to extract source code.
- Exceeding the scope of authorized API access.

## 4. Sending Requirements

### 4.1 All Email

- Sender identity must be clearly and accurately stated.
- `From` address must use a verified domain.
- Subject lines must not be deceptive or misleading.
- A physical mailing address or valid P.O. box must be included for commercial email.
- Reply-to address must be functional and monitored.

### 4.2 Marketing/Broadcast Email

- Recipients must have given explicit opt-in consent (no pre-checked boxes).
- Every email must include a clear, functional unsubscribe mechanism.
- Unsubscribe requests must be processed immediately or within 24 hours.
- List-Unsubscribe header (RFC 8058 one-click) must be present.
- Consent records must be maintained (timestamp, IP, source, consent wording).

## 5. Enforcement

### 5.1 Monitoring

ApexMail monitors sending patterns, content signatures, and account behavior to detect violations. Monitoring includes:

- Automated spam and phishing content analysis.
- Bounce and complaint rate tracking.
- Sending pattern anomaly detection.
- Recipient engagement analysis.
- Domain and IP reputation monitoring.

### 5.2 Violation Response

| Severity | Action |
|---|---|
| Minor first offense | Warning with remediation guidance |
| Repeated minor offenses | Temporary throttling of sending capability |
| Moderate offense | Account suspension pending remediation |
| Serious violation | Immediate account termination |
| Illegal activity | Termination and report to relevant authorities |

### 5.3 Appeals

Accounts suspended or terminated under this AUP may appeal by contacting **{{ABUSE_EMAIL}}**. Appeals must include the reason the action is believed to be in error and any supporting evidence.

### 5.4 Acceptable Thresholds

| Metric | Threshold |
|---|---|
| Bounce rate (hard) | < 2% |
| Complaint rate | < 0.1% (0.08% for marketing email) |
| Spam trap hits | 0 |
| Invalid recipient rate | < 1% |

Accounts exceeding these thresholds are subject to review and may be throttled or suspended.

## 6. Reporting Violations

Report AUP violations to: **{{ABUSE_EMAIL}}**

Include: nature of the abuse, full email headers, and any supporting evidence.

## 7. Changes

This AUP may be updated from time to time. Material changes are communicated via email to account holders and by updating the "Last Updated" date.

## 8. Contact

**{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**)
{{ADDRESS}}
Registry code: {{REGISTRY_CODE}}
VAT: {{VAT_NUMBER}}
Abuse reports: **{{ABUSE_EMAIL}}**
Support: **{{SUPPORT_EMAIL}}**
