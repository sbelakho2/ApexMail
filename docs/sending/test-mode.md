# Test Mode

Test mode allows you to integrate and test the ApexMail API without sending real emails to unverified recipients or incurring charges.

## Test Mode Limits

| Limit | Value |
|---|---|
| Daily sending limit | 100 emails |
| Recipient restriction | Verified addresses only |
| Billing required | No |
| Production domains required | No |
| Webhook delivery | Yes |

## Verified Recipients

In test mode, you can only send to verified email addresses. Add recipients in **Dashboard → Settings → Test Recipients** or via API:

```bash
curl -s -X POST https://api.apexmail.ee/v1/test-recipients \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@example.org"}' \
  | jq .
```

The recipient receives a verification email. Once confirmed, you can send to that address in test mode.

## Test Mode Behavior

- Emails include a `[TEST]` prefix in the subject line.
- `X-ApexMail-Test: true` header is added to all test emails.
- Webhooks fire normally — useful for testing your webhook endpoint.
- Real DNS records (SPF, DKIM) are not required — ApexMail handles authentication in test mode.
- Test emails are not counted in analytics for production domains.

## Switching to Production

When your integration is ready:

1. Navigate to **Dashboard → Settings → Production Access**.
2. Verify your domain if not already done.
3. Add a payment method.
4. Click **Enable Production Access**.

Your API keys remain the same — no code changes needed.

## Detecting Test Mode in Webhooks

```json
{
  "type": "delivered",
  "data": {
    "test_mode": true
  }
}
```

## Test Mode Sandbox Credentials

Use these for CI/CD and automated testing:

```bash
export APEXMAIL_API_KEY="am_test_xxxxxxxxxxxxxxxxxxxx"
```

Test API keys have the `am_test_` prefix and are limited to 100 emails/day regardless of plan.

## Related

- [Account Creation](../getting-started/account-creation.md)
- [First REST Email](../getting-started/first-rest-email.md)
- [Production Checklist](../getting-started/production-checklist.md)
