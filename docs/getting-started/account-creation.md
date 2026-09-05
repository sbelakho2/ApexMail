# Account Creation

Create an ApexMail account to start sending email.

## Sign Up

1. Visit [https://apexmail.ee](https://apexmail.ee) and click **Start free**.
2. Enter your email address, name, and a secure password.
3. Verify your email address by clicking the link sent to your inbox.
4. Choose a workspace name (your organization or project name).

## Test Mode

New accounts start in **Test Mode**. In test mode:

- You can send up to 100 emails per day.
- Emails are only delivered to verified recipient addresses.
- No billing is required.
- All features are available for integration testing.

## Moving to Production

When ready to send real email to unverified recipients:

1. Complete [domain verification](domain-verification.md).
2. Add a payment method in **Dashboard → Billing**.
3. Request production access from **Dashboard → Settings → Production Access**.

## API Keys

After account creation, generate API keys from **Dashboard → Settings → API Keys**:

1. Click **Create API Key**.
2. Give the key a descriptive name.
3. Choose the appropriate scopes (`send`, `read`, `admin`).
4. Copy the key immediately — it won't be shown again.

```bash
export APEXMAIL_API_KEY="am_live_xxxxxxxxxxxxxxxxxxxx"
```

## Example: Verify Account Works

```bash
curl -s https://api.apexmail.ee/v1/account \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  | jq .
```

Expected response:

```json
{
  "id": "acct_xxxxxxxxxxxx",
  "name": "My Workspace",
  "mode": "test",
  "created_at": "2026-01-15T10:30:00Z"
}
```

## Related

- [Overview](overview.md)
- [Domain Verification](domain-verification.md)
- [First REST Email](first-rest-email.md)
