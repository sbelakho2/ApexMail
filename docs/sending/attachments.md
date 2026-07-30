# Attachments

Include file attachments with your emails via the REST API.

## Adding Attachments

Each attachment requires:

- `filename` — the display name of the attachment.
- `content` — base64-encoded file content.
- `content_type` — MIME type of the attachment.

```json
{
  "from": "hello@example.com",
  "to": ["recipient@example.org"],
  "subject": "Your invoice",
  "text_body": "Please find your invoice attached.",
  "attachments": [
    {
      "filename": "invoice-2026-001.pdf",
      "content": "JVBERi0xLjQKJeLjz9MKNCAwIG9iago8PC9UeXBlL1hPYmplY3Q...",
      "content_type": "application/pdf"
    }
  ]
}
```

## Encoding Attachments

### Python

```python
import base64

with open("report.pdf", "rb") as f:
    content = base64.b64encode(f.read()).decode("utf-8")

payload = {
    "attachments": [{
        "filename": "report.pdf",
        "content": content,
        "content_type": "application/pdf"
    }]
}
```

### Node.js

```javascript
import { readFileSync } from "fs";

const content = readFileSync("report.pdf").toString("base64");

const payload = {
  attachments: [{
    filename: "report.pdf",
    content,
    content_type: "application/pdf"
  }]
};
```

## Multiple Attachments

```json
{
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content": "...",
      "content_type": "application/pdf"
    },
    {
      "filename": "terms.pdf",
      "content": "...",
      "content_type": "application/pdf"
    }
  ]
}
```

## Limits

| Limit | Value |
|---|---|
| Max attachments per email | 10 |
| Max attachment size (each) | 10 MB |
| Max total email size (including body) | 25 MB |
| Allowed content types | All MIME types except `text/html`, `application/x-msdownload`, `application/x-msdos-program` |

## Content-Disposition

ApexMail sets `Content-Disposition: attachment` for all attachments. Inline images should be embedded as CID references in the HTML body.

## Inline Images

For images displayed in the email body (not as downloads), use `content_id`:

```json
{
  "html_body": "<p>Here is the chart:</p><img src=\"cid:chart.png\" />",
  "attachments": [
    {
      "filename": "chart.png",
      "content": "...",
      "content_type": "image/png",
      "content_id": "chart.png"
    }
  ]
}
```

## Related

- [REST API](rest-api.md)
- [Headers](headers.md)
