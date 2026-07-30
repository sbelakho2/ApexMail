+++
title = "Acceptable Use Policy"
description = "ApexMail Acceptable Use Policy — rules governing how the email service may be used, organized by message category."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

This Acceptable Use Policy ("AUP") defines prohibited and acceptable uses of the ApexMail email infrastructure. Violation may result in suspension or termination. This AUP distinguishes between Marketing and Promotional Email and Transactional and Service Email — each category carries different consent, unsubscribe, and sending obligations as described below.

## Marketing & Promotional Email

Marketing and promotional email includes newsletters, product announcements, offers, event invitations, and any message whose primary purpose is commercial promotion or customer engagement beyond the direct fulfilment of a service.

**Requirements for all Marketing and Promotional Email:**

- **Opt-in consent.** Senders must obtain and retain proof of opt-in consent before sending. Where the recipient's jurisdiction or the sender's regulatory obligations require express consent (e.g., GDPR Article 7 for direct marketing to individuals in the EEA, CAN-SPAM in the US), the sender must obtain such consent.
- **Lawful basis.** Senders must identify, document, and maintain the lawful basis for processing recipient data under all applicable laws (e.g., consent under GDPR Article 6(1)(a), legitimate interest where legally valid). The sender bears sole responsibility for ensuring a valid lawful basis exists for each marketing communication before sending.
- **Sender identification.** Each message must clearly identify the sending organization and provide accurate `From`, `Reply-To`, and physical postal address headers.
- **Working unsubscribe mechanism.** Each message must include a one-click unsubscribe mechanism that processes removal requests promptly and permanently. Unsubscribe links must remain functional for at least 30 days after sending.
- **No purchased, scraped, or harvested lists.** Lists acquired through purchase, rental, scraping, or harvesting are not permitted. All recipient addresses must be collected directly by the sender through an opt-in process.
- **Complaint handling.** Senders must monitor abuse complaints and keep the complaint rate below 0.1% (calculated as complaints ÷ delivered messages per sending domain per day).
- **Suppression compliance.** Senders must suppress recipients who have unsubscribed or complained. ApexMail maintains a platform-wide suppression list; customers must not re-add suppressed addresses.

## Transactional & Service Email

Transactional and service email includes messages necessary to provide a service the recipient has requested or that the sender is legally required to send. These messages are not primarily promotional.

**Examples of Transactional and Service Email:**

- Password resets and account recovery links
- Authentication codes (one-time passwords, two-factor tokens)
- Security alerts (unrecognized sign-in, device change, account suspension notice)
- Purchase receipts and order confirmations
- Invoices, payment receipts, and billing notices
- Account status notifications (trial expiration, plan change, data export completion)
- Service confirmations (domain verification, webhook endpoint validation)
- Legally mandated messages (privacy policy updates where notification is required, data breach notifications)

**Requirements for Transactional and Service Email:**

- **Must be necessary for the service.** The message must directly relate to the recipient's account, transaction, or legal obligation. Promotional or marketing content must not be disguised as a transactional message.
- **Must not contain disguised marketing.** If a transactional message also contains promotional content (e.g., a password reset that also advertises a new product), the entire message is treated as marketing and must comply with the Marketing & Promotional Email section.
- **Accurate sender identity.** Sender identity must be clearly stated with correct domain and header information.
- **Customer responsibility for classification.** The customer is responsible for correctly classifying their messages (transactional vs. marketing) and for identifying the appropriate legal basis. ApexMail provides message category tags in the API; using a transactional tag for marketing content violates this AUP.
- **Appropriate retention.** Senders must retain transactional message data only for as long as necessary to fulfil the service purpose or comply with applicable legal obligations. Routine transactional data (e.g., delivery receipts, authentication logs) must be retained no longer than required for operational integrity and legal compliance.
- **Message-purpose-specific legal treatment.** Each transactional message category is treated according to its specific legal purpose. Authentication codes are security measures under GDPR Article 32. Invoices are financial records subject to retention requirements. Service confirmations are contract-performance communications. The sender must apply the correct legal framework for each message category. Using an inappropriate message category to circumvent legal requirements (e.g., tagging marketing content as transactional) constitutes a violation of this AUP.

## Prohibited Content (All Categories)

You may not use ApexMail to send:

- **Spam:** Unsolicited bulk email without the required opt-in consent described in the Marketing & Promotional Email section.
- **Phishing:** Emails designed to fraudulently obtain personal or financial information.
- **Malware:** Emails containing viruses, trojans, ransomware, or malicious attachments or links.
- **Illegal content:** Content that violates applicable laws in Estonia, the EU, or the recipient's jurisdiction.
- **Harassment:** Threatening, abusive, defamatory, or discriminatory content.

## General Sending Requirements

These requirements apply to all message categories:

- Sender identity must be clearly stated (no domain or header spoofing).
- Bounce rates must remain below 2% per sending domain per day.
- Complaints must remain below 0.1% per sending domain per day.
- Sending domains must be verified with valid SPF, DKIM, and DMARC records.

## Infrastructure Protection

- Do not attempt to bypass rate limits, quotas, or sending volume caps.
- Do not use the service for DDoS attacks, network abuse, or port scanning.
- Do not share API keys or credentials. Each user must have their own scoped API key.
- Do not attempt to access or interfere with other customers' data, accounts, or sending configurations.

## Enforcement

We monitor sending patterns and will:

1. Warn for first-time minor violations (e.g., elevated bounce rate).
2. Throttle sending for repeated issues or sustained policy violations.
3. Suspend sending (with notice where feasible) for serious violations, including spam complaints, phishing, or circumvention attempts.
4. Terminate accounts for egregious, repeated, or criminal violations.

## Reporting

Report abuse or AUP violations to: **abuse@apexmail.ee**

All reports are reviewed within 1 business day. Reporters receive an acknowledgement and, where appropriate, a summary of action taken.
