# Acceptable Use Policy (AUP)

> **Classification:** Internal Policy / Customer-Facing (summary published in ToS)
> **Owner:** Trust & Safety, Bel Consulting OÜ
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16192499, Tallinn, Estonia
> **Last Reviewed:** 2026-02-09
> **Review Cycle:** Semi-annually

---

## 1. Purpose

This Acceptable Use Policy defines the rules governing the use of the ApexMail
email marketing platform. It protects our customers, their recipients, and the
reputation of our shared sending infrastructure. Violations are enforced
progressively as described in §7.

---

## 2. Scope

This policy applies to all ApexMail accounts, including free trials, paid plans,
and enterprise agreements. It covers all email content sent through ApexMail, all
recipient lists stored on the platform, and all use of the ApexMail API.

---

## 3. Prohibited Content

The following content types are **strictly prohibited** and result in immediate
account termination without warning:

### 3.1 Zero Tolerance (Immediate Termination)

- **Phishing:** Emails designed to deceive recipients into revealing credentials,
  financial information, or other sensitive data.
- **Malware distribution:** Emails containing or linking to malicious software,
  ransomware, or exploit kits.
- **Child Sexual Abuse Material (CSAM):** Any content depicting or promoting the
  sexual exploitation of minors. Reported to law enforcement immediately.
- **Terrorism and violent extremism:** Content promoting, inciting, or providing
  material support for terrorist acts.

### 3.2 Prohibited Content Categories

- Illegal goods or services (narcotics, unlicensed weapons, counterfeit goods).
- Fraud, pyramid schemes, and deceptive financial schemes.
- Content that violates intellectual property rights at scale.
- Pharmaceutical products without proper licensing and regulatory compliance.
- Sexually explicit content sent to recipients who have not explicitly opted in.
- Hate speech, harassment, or content inciting violence against protected groups.
- Counterfeit or replica branded goods.

---

## 4. Prohibited Sending Practices

### 4.1 List Acquisition

The following list acquisition methods are **prohibited**:

- **Purchased or rented lists:** Lists obtained from third-party brokers, data
  providers, or list rental services.
- **Scraped or harvested addresses:** Email addresses collected via web scraping,
  crawling, or automated extraction from websites, forums, or directories.
- **Appended lists:** Adding email addresses to existing records via third-party
  data append services without direct, verifiable consent.
- **Co-registration lists:** Addresses obtained through pre-checked opt-in boxes
  on third-party forms.

### 4.2 Consent Requirements

All recipients must have provided consent through one of:

- **Express opt-in:** Recipient actively submitted their email address and agreed
  to receive the specific type of communication.
- **Double opt-in (recommended):** Recipient confirmed their subscription via a
  confirmation email. Required for accounts sending >10,000 emails/month.
- **Transactional relationship:** Recipient has an existing business relationship
  and is receiving transactional or service-related messages.

### 4.3 Prohibited Techniques

- Sending to role-based addresses (info@, sales@, admin@) for marketing purposes.
- Dictionary attacks (guessing email addresses by pattern).
- Snowshoe sending (distributing volume across many IPs/domains to circumvent
  reputation systems).
- Using deceptive "From" names, addresses, or subject lines.
- Obfuscating unsubscribe mechanisms or making them non-functional.
- Sending from domains that impersonate other brands or organisations.

---

## 5. Sending Limits and Thresholds

### 5.1 Volume Limits by Plan

| Plan | Daily Limit | Monthly Limit | Burst Rate (per minute) |
|------|-------------|---------------|------------------------|
| Free Trial | 200 | 1,000 | 10 |
| Starter | 5,000 | 50,000 | 100 |
| Growth | 25,000 | 250,000 | 500 |
| Business | 100,000 | 1,000,000 | 1,000 |
| Enterprise | Custom | Custom | Custom |

### 5.2 Warm-up Requirements

New accounts and new sending domains must follow a warm-up schedule:

- **Week 1:** 25% of plan daily limit.
- **Week 2:** 50% of plan daily limit.
- **Week 3:** 75% of plan daily limit.
- **Week 4+:** Full plan limit.

Exceeding warm-up limits triggers automatic throttling.

### 5.3 Reputation Thresholds

| Metric | Acceptable | Warning | Suspension Trigger |
|--------|-----------|---------|-------------------|
| Spam complaint rate | < 0.05% | 0.05% – 0.1% | > 0.1% |
| Hard bounce rate | < 2% | 2% – 5% | > 5% |
| Unsubscribe rate | < 1% | 1% – 2% | > 2% (reviewed) |
| Spam trap hits | 0 | 1–2 (investigated) | > 2 (per campaign) |

The **0.1% spam complaint rate** is a hard threshold aligned with major mailbox
provider requirements (Google, Yahoo, Microsoft). Exceeding this rate triggers
automatic sending suspension pending review.

---

## 6. Content Scanning and Monitoring

### 6.1 Automated Scanning

All outbound email is subject to automated scanning for:

- **Phishing indicators:** Suspicious URLs, brand impersonation, credential
  harvesting patterns.
- **Malware links:** URLs checked against threat intelligence feeds.
- **Spam signatures:** Content patterns associated with known spam campaigns.
- **Compliance markers:** Presence of unsubscribe links, physical address
  (CAN-SPAM), and sender identification.

### 6.2 Manual Review

Accounts may be flagged for manual review based on:

- Automated scanning alerts.
- Recipient complaints.
- Unusual sending patterns (volume spikes, geographic anomalies).
- Spam trap hits.

### 6.3 Privacy Safeguards

Content scanning is automated and does not involve human review of email content
unless:

- An automated system flags a potential violation.
- A formal complaint or legal request requires investigation.
- The account owner requests a review as part of an appeal.

All manual reviews are logged and restricted to authorised Trust & Safety personnel.

---

## 7. Enforcement Actions

Violations are handled through a progressive enforcement model unless the
violation falls under zero-tolerance categories (§3.1).

### 7.1 Enforcement Ladder

| Stage | Action | Trigger | Recovery |
|-------|--------|---------|----------|
| **1. Warning** | Email notification with details of the violation and required corrective action. | First minor violation, threshold warning. | Acknowledge and remediate within 48h. |
| **2. Throttle** | Sending rate reduced to 25% of plan limit. | Second violation, or failure to remediate after warning. | Submit remediation plan, reviewed within 24h. |
| **3. Suspend** | Sending halted. Account accessible for data export. | Third violation, exceeding hard thresholds, or continued non-compliance. | Appeal within 14 days (see §8). |
| **4. Terminate** | Account permanently closed. Data deleted per retention policy. | Repeated violations, zero-tolerance content, or failed appeal. | No recovery. |

### 7.2 Automatic Enforcement

The following triggers result in **automatic** action without manual review:

- Spam complaint rate > 0.1% → Automatic sending suspension.
- Hard bounce rate > 5% → Automatic sending suspension.
- Phishing/malware detection → Immediate account suspension.
- Spam trap hits > 2 per campaign → Automatic throttle + review.

### 7.3 Account-Level vs Campaign-Level

- **Campaign-level:** Individual campaigns may be paused or blocked while the
  account remains active.
- **Account-level:** Repeated or severe violations affect the entire account.

---

## 8. Appeal Process

### 8.1 Filing an Appeal

Suspended or terminated users may appeal by:

1. Submitting an appeal via email to trust@apexmail.com within **14 days** of
   the enforcement action.
2. Including: account identifier, description of the situation, evidence of
   corrective action taken, and a plan to prevent recurrence.

### 8.2 Review Process

- Appeals are reviewed by the Trust & Safety Lead within **5 business days**.
- The reviewer was not involved in the original enforcement decision.
- The customer is notified of the outcome in writing.
- Decisions on zero-tolerance violations (§3.1) are final and not subject to
  appeal.

### 8.3 Reinstatement

If an appeal is successful:

- The account is reinstated with a probationary period of 90 days.
- Sending limits may be reduced during the probationary period.
- A second violation during probation results in immediate termination.

---

## 9. Reporting Violations

### 9.1 Abuse Reports

Recipients or third parties may report AUP violations via:

- **Abuse email:** abuse@apexmail.com
- **Unsubscribe complaints:** Processed automatically via feedback loops.
- **Postmaster reports:** Via postmaster@apexmail.com.

### 9.2 Response SLA

- **Acknowledgement:** Within 24 hours.
- **Investigation and resolution:** Within 72 hours for standard reports, 4 hours
  for phishing/malware reports.

---

## 10. Policy Updates

This policy may be updated at any time. Material changes are communicated to
customers via email with 30 days' notice. Continued use of the platform after the
notice period constitutes acceptance.
