# Cookie Policy

**Last Updated:** {{LAST_UPDATED}}

This Cookie Policy explains how **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, registered at **{{ADDRESS}}**, Republic of Estonia, uses cookies and similar technologies on the ApexMail website and dashboard.

## 1. What Are Cookies

Cookies are small text files placed on your device when you visit a website. They are widely used to make websites work efficiently and provide information to site operators. Similar technologies include localStorage, sessionStorage, and IndexedDB.

## 2. Cookies on the ApexMail Website (apexmail.ee)

### 2.1 Strictly Necessary Cookies

These cookies are essential for the website to function and cannot be disabled.

| Cookie | Purpose | Duration | Type |
|---|---|---|---|
| `session_id` | Session management for dashboard authentication | Session | First-party, HTTP-only, Secure |
| `csrf_token` | Cross-site request forgery protection | Session | First-party, HTTP-only, Secure |
| `locale` | Language preference (remembered across sessions via localStorage) | Persistent (1 year) | First-party |

### 2.2 Analytics Cookies

We use self-hosted Plausible Analytics, which does not use cookies and does not collect personal data. No analytics cookies are set.

### 2.3 Marketing and Advertising Cookies

We do not use third-party advertising cookies, retargeting cookies, or social media tracking cookies on our website.

## 3. Cookies on the ApexMail Dashboard

The ApexMail dashboard (app.apexmail.ee) uses:

| Storage | Purpose |
|---|---|
| `auth_token` (cookie) | Authentication session |
| `csrf_token` (cookie) | CSRF protection |
| `preferences` (localStorage) | Dashboard UI preferences (theme, sidebar state, column layout) |
| `recent_views` (localStorage) | Recently accessed pages for quick navigation |

## 4. Third-Party Cookies

The ApexMail platform does not set third-party cookies. The only exception is if you embed ApexMail forms on your own website — those forms may set a `session_id` cookie scoped to your domain for CSRF protection.

## 5. Email Tracking

### 5.1 Open Tracking

When a Customer enables open tracking, a transparent 1x1 pixel image is embedded in the email. When the Recipient's email client downloads the image, we record:
- Timestamp of the open event.
- IP address and inferred geographic location.
- User agent of the email client.

This data is processed on behalf of the Customer (the data controller).

### 5.2 Click Tracking

When a Customer enables click tracking, links in the email are rewritten to pass through a tracking domain. When clicked, we record:
- Timestamp of the click event.
- IP address and inferred geographic location.
- User agent.

This data is processed on behalf of the Customer.

### 5.3 Recipient Options

Recipients who prefer not to be tracked can:
- Disable image loading in their email client (disables open tracking).
- Not click links in tracked emails (disables click tracking).
- Use an email client with privacy protection features (e.g., Apple Mail Privacy Protection).

## 6. Managing Cookies

### 6.1 Browser Controls

Most browsers allow you to control cookies through settings. You can:
- Delete cookies from your device.
- Block cookies by default.
- Set exceptions for specific websites.
- Browse in private/incognito mode.

Note: blocking strictly necessary cookies may prevent the ApexMail website and dashboard from functioning.

### 6.2 Do Not Track

We honor the Do Not Track (DNT) header for requests to our marketing website. When DNT is enabled, we disable analytics and session recording even where those mechanisms would not normally set cookies.

### 6.3 Cookie Consent

Under the ePrivacy Directive, we obtain consent for non-essential cookies. Since we do not use non-essential cookies on the marketing website, no cookie consent banner is required under our current cookie usage. If this changes, we will implement a consent mechanism.

## 7. Changes

This Cookie Policy may be updated from time to time. Material changes are communicated via the website and by updating the "Last Updated" date.

## 8. Contact

**{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**)
{{ADDRESS}}
Registry code: {{REGISTRY_CODE}}
Privacy inquiries: **{{PRIVACY_EMAIL}}**
