# First SMTP Email

Send your first email through the ApexMail SMTP relay.

## Prerequisites

- [Account created](account-creation.md) with SMTP credentials.
- [Domain verified](domain-verification.md) (or use test mode with verified recipients).

## SMTP Credentials

SMTP credentials are separate from API keys. Generate them in **Dashboard → Settings → SMTP Credentials**:

- **Username**: `am_smtp_xxxxxxxxxxxxxxxxxxxx`
- **Password**: `am_smtp_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- **Host**: `smtp.apexmail.ee`
- **Port**: `587` (STARTTLS)

## Send via curl (with msmtp-style wrapper)

Use `swaks` (Swiss Army Knife for SMTP) for testing:

```bash
swaks --to recipient@example.org \
      --from hello@example.com \
      --server smtp.apexmail.ee:587 \
      --auth-user am_smtp_xxxxxxxxxxxxxxxxxxxx \
      --auth-password am_smtp_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
      --tls \
      --header "Subject: Hello from SMTP" \
      --body "This is your first email sent via ApexMail SMTP relay."
```

## Send via Python

```python
import smtplib
from email.mime.text import MIMEText

smtp_user = "am_smtp_xxxxxxxxxxxxxxxxxxxx"
smtp_pass = "am_smtp_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
host = "smtp.apexmail.ee"
port = 587

msg = MIMEText("This email was sent via ApexMail SMTP relay.")
msg["Subject"] = "Hello from Python SMTP"
msg["From"] = "hello@example.com"
msg["To"] = "recipient@example.org"

with smtplib.SMTP(host, port) as server:
    server.starttls()
    server.login(smtp_user, smtp_pass)
    server.send_message(msg)
```

## Send via Node.js (Nodemailer)

```javascript
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.apexmail.ee",
  port: 587,
  secure: false,
  auth: {
    user: process.env.APEXMAIL_SMTP_USER,
    pass: process.env.APEXMAIL_SMTP_PASS
  }
});

await transporter.sendMail({
  from: "hello@example.com",
  to: "recipient@example.org",
  subject: "Hello from Node.js SMTP",
  text: "This email was sent via ApexMail SMTP relay."
});
```

## SMTP Features

The ApexMail SMTP relay supports:

- STARTTLS (required on port 587).
- Custom headers via `X-ApexMail-*` headers.
- Tags via `X-ApexMail-Tag`.
- Stream routing via `X-ApexMail-Stream`.
- Metadata via `X-ApexMail-Metadata`.

## Related

- [SMTP Reference](../sending/smtp.md)
- [First REST Email](first-rest-email.md)
- [Headers](../sending/headers.md)
