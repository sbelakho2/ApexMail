# Headers

Set custom email headers for every email sent through ApexMail.

## Custom Headers

Add arbitrary headers via the `headers` field in the REST API:

```json
{
  "from": "hello@example.com",
  "to": ["recipient@example.org"],
  "subject": "Hello",
  "text_body": "...",
  "headers": {
    "X-Custom-Header": "value",
    "X-Entity-Ref-ID": "order-12345",
    "X-Priority": "1"
  }
}
```

## SMTP Custom Headers

When sending via SMTP, include any standard email header:

```
X-ApexMail-Stream: transactional
X-Custom-Header: value
```

## Reserved Headers

The following headers are managed by ApexMail and cannot be overridden:

| Header | Managed By |
|---|---|
| `Return-Path` | ApexMail (MAIL FROM) |
| `DKIM-Signature` | ApexMail signing |
| `Message-ID` | ApexMail |
| `Date` | ApexMail |
| `Received` | MTAs |

## Tracking Headers

Control tracking behavior via headers:

```json
{
  "headers": {
    "X-ApexMail-Track-Opens": "false",
    "X-ApexMail-Track-Clicks": "false"
  }
}
```

## List-Unsubscribe Headers

For broadcast streams, ApexMail automatically sets:

```
List-Unsubscribe: <mailto:unsubscribe@example.com>, <https://example.com/unsubscribe?recipient=...>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

You can override the List-Unsubscribe value:

```json
{
  "headers": {
    "List-Unsubscribe": "<mailto:unsubscribe@yourdomain.com>, <https://yourdomain.com/unsub>"
  }
}
```

## Using Headers for Threading

Set `References` and `In-Reply-To` for email threading:

```json
{
  "headers": {
    "In-Reply-To": "<original-message-id@example.com>",
    "References": "<original-message-id@example.com>"
  }
}
```

## Related

- [SMTP Relay](smtp.md)
- [Tags](tags.md)
- [Metadata](metadata.md)
