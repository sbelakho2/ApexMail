# Production Checklist

Complete this checklist before sending production email through ApexMail.

## 1. Domain Configuration

- [ ] Domain verified in ApexMail.
- [ ] SPF record configured (`v=spf1 include:spf.apexmail.ee ~all`).
- [ ] Every DKIM record currently shown for the domain in the dashboard is published.
- [ ] DMARC policy set (`p=quarantine` initially, then `p=reject`).
- [ ] Custom return-path domain configured.
- [ ] Custom tracking domain configured.
- [ ] MX records not modified (ApexMail does not handle inbound email by default).

## 2. Email Authentication

- [ ] SPF passes for test emails (check `Authentication-Results` header).
- [ ] DKIM signatures validate (check `dkim=pass`).
- [ ] DMARC alignment confirmed (check `dmarc=pass`).
- [ ] MTA-STS policy published (optional, for strict TLS enforcement).
- [ ] DANE/TLSA records published (optional, for DANE verification).

## 3. Sending Configuration

- [ ] Transactional streams created for each email type (password reset, welcome, notification, etc.).
- [ ] Broadcast streams created for marketing campaigns (if applicable).
- [ ] Default `from` address configured per stream.
- [ ] Reply-to address configured.
- [ ] Unsubscribe header configured for broadcast streams.
- [ ] List-Unsubscribe header (mailto + URL) configured.

## 4. Webhooks

- [ ] Webhook endpoint deployed and publicly accessible via HTTPS.
- [ ] Signature verification implemented.
- [ ] All relevant event types subscribed (at minimum: `bounced`, `complained`, `delivered`).
- [ ] Idempotency handling implemented (deduplicate by `event.id`).
- [ ] Retry resilience — endpoint returns 2xx within 10 seconds.
- [ ] Webhook secret stored securely (environment variable or secrets manager).

## 5. Error & Bounce Handling

- [ ] Hard bounce handling: remove invalid addresses from your database.
- [ ] Soft bounce handling: defer or retry based on bounce classification.
- [ ] Complaint handling: suppress complaining addresses immediately.
- [ ] Suppression list sync implemented.
- [ ] Rate limit errors (429) handled with exponential backoff.

## 6. Monitoring & Alerting

- [ ] Delivery rate monitored (target ≥ 99%).
- [ ] Bounce rate alert set (threshold < 2%).
- [ ] Complaint rate alert set (threshold < 0.1%).
- [ ] Webhook delivery latency monitored.
- [ ] API error rate monitored.

## 7. Security

- [ ] API keys scoped to minimum required permissions.
- [ ] SMTP credentials stored separately from API keys.
- [ ] API keys rotated at least every 90 days.
- [ ] 2FA enabled on all team accounts.
- [ ] IP allowlist configured (if supported on your plan).
- [ ] Audit logging enabled.

## 8. Compliance

- [ ] Privacy policy updated to disclose ApexMail as email subprocessor.
- [ ] DPA signed (if required under GDPR).
- [ ] Data retention policy aligned with business requirements.
- [ ] Tracking consent configured if required in recipient jurisdictions.

## 9. Warm-Up (Dedicated IPs)

If using dedicated IPs:

- [ ] Warm-up schedule defined (start low, increase daily).
- [ ] Initial volume: 50–100 emails/day to engaged recipients.
- [ ] Increase by 50–100% daily based on engagement metrics.
- [ ] Warm-up period: 2–4 weeks minimum.
- [ ] Monitor IP reputation continuously during warm-up.

## 10. Go-Live

- [ ] Test mode disabled, production access granted.
- [ ] Billing method added and validated.
- [ ] Send a test campaign to internal team.
- [ ] Verify all events appear in dashboard and webhook endpoint.
- [ ] Document rollback plan and support escalation path.

## Related

- [Overview](overview.md)
- [Domain Verification](domain-verification.md)
- [SPF Configuration](../domains/spf.md)
- [DKIM Configuration](../domains/dkim.md)
- [DMARC Configuration](../domains/dmarc.md)
