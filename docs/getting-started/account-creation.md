# Account Creation

Create an ApexMail account to start sending email.

## Sign Up

1. Visit [https://apexmail.ee](https://apexmail.ee) and click **Start free**.
2. Enter your email address, name, and a secure password.
3. Verify your email address by clicking the link sent to your inbox.
4. Choose a workspace name (your organization or project name).

## Test Mode

Integration testing without real delivery is provided by the test
addresses and test keys (see [Test Mode](../sending/test-mode.md)):

- Send to deterministic `@test.apexmail.ee` addresses
  (`delivered@`, `soft-bounce@`, `hard-bounce@`, ...) to exercise every
  lifecycle outcome — no external mail leaves the platform.
- Messages sent with an `am_test_` API key are routed through test mode
  regardless of recipient.

Regular accounts can send immediately after verifying a sending domain;
there is no separate account-level "test mode" gate on recipients.

## Moving to Production

When ready to send real email to unverified recipients:

1. Complete [domain verification](domain-verification.md).
2. Add a payment method in **Dashboard → Billing**.
3. Request production access from **Dashboard → Settings → Production Access**.

## API Keys

After account creation, generate API keys from **Dashboard → Settings → API Keys**:

1. Click **Create API Key**.
2. Give the key a descriptive name.
3. Choose the appropriate scopes (e.g. `messages:send`, `messages:read`,
   `domains:read`, `events:read`, `webhooks:write` — or the `*` wildcard).
4. Copy the key immediately — it won't be shown again.

```bash
export APEXMAIL_API_KEY="am_live_xxxxxxxxxxxxxxxxxxxx"
```

## Example: Verify the Key Works

```bash
curl -s https://api.apexmail.ee/v1/domains \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  | jq .
```

Expected response: HTTP 200 with a JSON array of your sending domains
(empty until you add one). (`GET /v1/account` does not exist; profile
information lives at `GET /v1/account/profile`, which is session-cookie
authenticated, not API-key authenticated.)

## Related

- [Overview](overview.md)
- [Domain Verification](domain-verification.md)
- [First REST Email](first-rest-email.md)
