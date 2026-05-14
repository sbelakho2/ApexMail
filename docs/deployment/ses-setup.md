# AWS SES Setup Guide

> Last updated: 2026-03-02

Step-by-step guide to configuring AWS SES for **shared-pool email delivery** in ApexMail.

> **Note:** Dedicated IPs are provisioned via Hetzner Cloud, not SES. See [Hetzner Tool Contract](../tool-contracts/hetzner.md) for dedicated IP setup.

---

## Prerequisites

- An AWS account with SES access
- A verified sending domain (or at least one verified email address for sandbox testing)
- IAM credentials with the required permissions

---

## 1. Create an IAM User

Create a dedicated IAM user (e.g. `apexmail-ses`) with the following policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ApexMailSES",
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail",
        "ses:GetAccount",
        "ses:GetSendStatistics",
        "ses:GetSendQuota",
        "ses:CreateEmailIdentity",
        "ses:DeleteEmailIdentity",
        "ses:GetEmailIdentity",
        "ses:PutEmailIdentityDkimSigningAttributes",
        "ses:PutEmailIdentityConfigurationSetAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ApexMailSNS",
      "Effect": "Allow",
      "Action": [
        "sns:Subscribe",
        "sns:ConfirmSubscription"
      ],
      "Resource": "arn:aws:sns:*:*:apexmail-*"
    }
  ]
}
```

> **Note:** Dedicated IPs are provisioned via Hetzner Cloud API, not SES. See [Hetzner Tool Contract](../tool-contracts/hetzner.md) for dedicated IP setup. The IAM policy above has been updated to remove dedicated IP permissions that are no longer applicable.

Save the access key and secret key.

---

## 2. Move Out of SES Sandbox

New SES accounts start in sandbox mode (can only send to verified addresses). Request production access:

1. Go to **SES Console** → **Account dashboard** → **Request production access**
2. Describe your use case (transactional email platform)
3. AWS typically approves within 24 hours

---

## 3. Verify Your Sending Domain

ApexMail automatically creates SES domain identities when users add domains via the dashboard. However, you can also verify manually:

```bash
aws sesv2 create-email-identity --identity-type DOMAIN --identity yourdomain.com
```

This returns DKIM CNAME records to add to your DNS. SES uses Easy DKIM with 2048-bit RSA keys.

---

## 4. Create a Configuration Set

```bash
aws sesv2 create-configuration-set --configuration-set-name apexmail-production
```

### Add SNS Event Destination

Create an SNS topic for delivery events:

```bash
aws sns create-topic --name apexmail-ses-events
```

Then add it as an event destination:

```bash
aws sesv2 create-configuration-set-event-destination \
  --configuration-set-name apexmail-production \
  --event-destination-name sns-events \
  --event-destination '{
    "Enabled": true,
    "MatchingEventTypes": ["SEND", "DELIVERY", "BOUNCE", "COMPLAINT", "REJECT"],
    "SnsDestination": {
      "TopicArn": "arn:aws:sns:eu-west-1:ACCOUNT_ID:apexmail-ses-events"
    }
  }'
```

### Subscribe the ApexMail Webhook

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:eu-west-1:ACCOUNT_ID:apexmail-ses-events \
  --protocol https \
  --notification-endpoint https://api.apexmail.ee/v1/ses/notifications
```

SES will send a `SubscriptionConfirmation` request to the endpoint. ApexMail automatically confirms it.

---

## 5. Configure Environment Variables

Add these to your `.env` file:

```dotenv
EMAIL_TRANSPORT_TYPE=ses
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=eu-west-1
SES_CONFIGURATION_SET=apexmail-production
```

---

## 6. DNS Records

For each sending domain, add:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| CNAME | `*._domainkey` | (provided by SES) | DKIM |
| TXT | `@` | `v=spf1 include:amazonses.com ~all` | SPF |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com` | DMARC |

---

## 7. Dedicated IPs

> **Dedicated IPs are no longer provisioned via SES.**

Dedicated IPs are managed via Hetzner Cloud floating IPs for cost efficiency (~$4/mo vs $24.95/mo) and full control over rDNS.

See:
- [Hetzner Tool Contract](../tool-contracts/hetzner.md) for Hetzner Cloud API configuration
- [Hybrid Email Infrastructure](../architecture/hybrid-email-infrastructure.md) for architecture overview
- [Delivery Transport](../architecture/delivery-transport.md) for routing details

Dedicated IPs are auto-provisioned when a customer upgrades their plan (handled by the billing service's Stripe webhook).

---

## 8. Monitoring

Key SES metrics to monitor:

| Metric | Alert Threshold | Source |
|--------|----------------|--------|
| Bounce rate | > 5% | SES → SNS → `/v1/ses/notifications` |
| Complaint rate | > 0.1% | SES → SNS → `/v1/ses/notifications` |
| Send quota utilisation | > 80% | `ses:GetSendQuota` |
| Delivery latency | > 30s p99 | Application metrics |

---

## Troubleshooting

### "Email address is not verified"
The sender domain hasn't been verified in SES. Add the domain via the ApexMail dashboard or run `aws sesv2 create-email-identity`.

### "Account sending paused"
SES has paused sending due to high bounce/complaint rates. Review your suppression list and reduce sends to invalid addresses.

### "Throttling — Maximum sending rate exceeded"
Your SES account's per-second sending rate has been reached. Request a limit increase via the SES console.

---

## Related Documents

- [Delivery Transport Architecture](../architecture/delivery-transport.md)
- [ADR 0011 — Dual Delivery](../adr/0011-dual-delivery-ses-primary.md)
- [SES Tool Contract](../tool-contracts/ses.md)
- [Configuration Reference](configuration.md)
