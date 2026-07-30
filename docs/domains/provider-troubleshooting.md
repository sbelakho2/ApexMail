# Provider Troubleshooting

Troubleshoot deliverability issues with specific mailbox providers.

## General Diagnostic Steps

1. Send a test email through ApexMail to the affected provider.
2. Check the email's headers for `Authentication-Results`.
3. Verify SPF, DKIM, and DMARC all pass.
4. Check ApexMail analytics for bounce/complaint reasons.
5. Use the Email Grader tool in the dashboard.

## Gmail / Google Workspace

### Issue: Email goes to spam

**Check:**
- Postmaster Tools (https://postmaster.google.com) for your domain's reputation.
- SPF, DKIM, DMARC all pass in `Authentication-Results`.
- Domain age — new domains (<30 days) face stricter filtering.
- List-Unsubscribe header is present for broadcast email.

**Fix:**
- Ensure DMARC policy is at least `p=quarantine`.
- Ensure sending IPs are not on common blocklists.
- Review content for spam-like patterns (URL shorteners, excessive images, misleading subjects).
- Request Gmail Feedback Loop enrollment.

### Issue: Email rejected (550)

**Check:**
- `Authentication-Results: dkim=permerror` or `spf=permerror` — DNS configuration issue.
- Return-path domain resolves correctly.
- Sending IP not listed on Spamhaus.

**Fix:**
- Correct DNS records and wait for propagation.
- Request removal from Spamhaus if listed.
- Verify domain hasn't been flagged for abuse in Postmaster Tools.

## Microsoft (Outlook / Office 365 / Exchange Online)

### Issue: Email goes to junk

**Check:**
- SNDS (Smart Network Data Services) for your IP.
- JMRP (Junk Mail Reporting Program) enrollment.
- SPF, DKIM, DMARC all pass.
- Sender domain has a valid website with contact information.

**Fix:**
- Enroll in SNDS and JMRP via Microsoft.
- Ensure DMARC `p=reject` — Microsoft favors strict policies.
- Reduce sending of pure HTML/image-only emails.
- Don't use link shorteners.

### Issue: Email throttled or deferred (451)

**Check:**
- Sending volume — Microsoft applies aggressive throttling to new IPs.
- IP reputation in SNDS.

**Fix:**
- Implement warm-up for dedicated IPs.
- Reduce sending rate; Microsoft responds to throttling after 24–48 hours of compliant sending.
- Open support ticket with Microsoft via their sender support form.

## Yahoo / AOL / Verizon Media

### Issue: Email bounced (550/554)

**Check:**
- Yahoo's Complaint Feedback Loop enrollment.
- DKIM signing is critical — Yahoo requires DKIM.
- SPF pass.
- Domain not on internal blocklists.

**Fix:**
- Enroll in Yahoo's Complaint Feedback Loop.
- Ensure DKIM is configured and passing.
- Use consistent sending volumes — Yahoo flags volume spikes.
- Request delisting via Yahoo's bulk sender form.

## Apple Mail / iCloud

### Issue: Blocked or marked as spam

**Check:**
- Apple's postmaster feedback (limited).
- DKIM and DMARC.
- Content quality.

**Fix:**
- Ensure DKIM passes.
- Apple Mail Privacy Protection means open tracking is unreliable — do not use open rates as a primary metric.
- Send consistent, engaged volume.

## Common Blocklists

Check if your IP or domain is listed:

| Blocklist | Check URL |
|---|---|
| Spamhaus | https://check.spamhaus.org |
| Barracuda | https://www.barracudacentral.org/lookups |
| Spamcop | https://www.spamcop.net/bl.shtml |
| SORBS | http://www.sorbs.net/lookup.shtml |
| Invaluement | https://www.invaluement.com |

## Escalation

If issues persist after following provider-specific guidance:

1. Contact ApexMail support at `support@apexmail.ee` with delivery issue specifics.
2. Include message IDs, bounce reasons, and affected providers.
3. Enterprise customers receive prioritized deliverability support.

## Related

- [SPF](spf.md)
- [DKIM](dkim.md)
- [DMARC](dmarc.md)
- [Rotation](rotation.md)
- [Email Authentication Guide](../../security/email-authentication.md)
