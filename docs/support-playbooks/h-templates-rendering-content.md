# H) Templates, Rendering & Content Playbook (Issues 109–120)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Email template creation, Handlebars/MJML rendering, HTML rendering across clients, content encoding, attachments, and formatting issues.

---

## Reference: Template System

| Feature | Details |
|---------|---------|
| Template engine | Handlebars |
| Responsive framework | MJML (compiled to HTML) |
| Helpers | `if`, `unless`, `each`, `formatDate`, `formatCurrency`, `uppercase`, `lowercase` |
| Personalization | `{{variable_name}}` syntax |
| Conditional blocks | `{{#if variable}}...{{/if}}`, `{{#unless variable}}...{{/unless}}` |
| Loops | `{{#each items}}{{this.name}}{{/each}}` |
| Max attachments | 25 MB total per message |
| Max recipients | 100 per API call |
| Supported attachment types | PDF, images, ZIP, CSV, common document formats (base64-encoded) |

---

## Issue 109 — Template variable not rendering (shows raw `{{variable}}`)

**Symptoms:** Recipient sees literal `{{first_name}}` instead of the actual first name. Template personalization not working.

**Root cause:** Variable name mismatch, missing data, or syntax error in the template.

**Resolution:**
1. Check that the variable name in the template EXACTLY matches the merge data key.
   - Template: `Hello {{first_name}}` 
   - API data: `"merge_data": {"first_name": "Alice"}` ✓
   - Common mistake: `{{firstName}}` vs `{"first_name": "..."}` — case and underscore matter.
2. Check for typos: `{{frist_name}}` won't match `first_name`.
3. If using nested objects: `{{user.name}}` requires `"merge_data": {"user": {"name": "Alice"}}`.
4. Test in Dashboard → Templates → Preview with sample data before sending.
5. Use `{{#if first_name}}Hello {{first_name}}{{else}}Hello there{{/if}}` for graceful fallbacks.

---

## Issue 110 — Handlebars syntax errors or broken conditionals

**Symptoms:** Template fails to render, throws error, or shows unexpected content. Partial blocks visible.

**Root cause:** Malformed Handlebars syntax — unclosed blocks, incorrect helper names, or nesting errors.

**Resolution:**
1. Common syntax errors:
   - Missing closing tag: `{{#if active}}...` without `{{/if}}` → error
   - Mismatched tags: `{{#if active}}...{{/unless}}` → error
   - Invalid helper: `{{#forEach items}}` → should be `{{#each items}}`
   - Extra spaces in helper: `{{ # if active }}` → should be `{{#if active}}`
2. Correct patterns:
   ```handlebars
   {{#if condition}}
     Content when true
   {{else}}
     Content when false
   {{/if}}
   
   {{#each items}}
     {{this.name}} — {{this.value}}
   {{/each}}
   
   {{#unless unsubscribed}}
     Marketing content
   {{/unless}}
   ```
3. Use ApexMail's template editor (Dashboard → Templates) which has syntax validation.
4. Test with sample data before sending.

---

## Issue 111 — HTML injection / XSS concern in templates

**Symptoms:** Customer worried that user-supplied merge data could inject HTML or JavaScript into emails.

**Root cause:** Legitimate security concern. User-provided data rendered in templates could contain HTML tags.

**Resolution:**
1. Handlebars automatically HTML-escapes variables by default:
   - `{{name}}` → HTML-escaped (safe). `<script>` becomes `&lt;script&gt;`.
   - `{{{name}}}` (triple braces) → raw, unescaped (UNSAFE for user input).
2. Guidance:
   - Always use double braces `{{variable}}` for user-supplied data.
   - Only use triple braces `{{{html_content}}}` for trusted, internally-generated HTML.
   - Never put user input in triple braces.
3. Email clients strip JavaScript anyway (all major email clients block `<script>` tags), but clean HTML is still important for proper rendering.
4. If customer needs to include formatted content: sanitize on their side before passing as merge data.

---

## Issue 112 — Preheader text not showing correctly

**Symptoms:** Email preview text in the inbox shows HTML code, random text, or missing preheader.

**Root cause:** Preheader text (the snippet shown after the subject line in inbox preview) not properly defined, or hidden preheader CSS technique not working consistently.

**Resolution:**
1. Preheader best practices:
   - Set preheader in ApexMail API: `"preheader": "Your preview text here"`.
   - If using HTML templates: place preheader text immediately after `<body>` in a hidden `<div>`:
     ```html
     <div style="display: none; max-height: 0px; overflow: hidden;">
       Your preheader text here
       <!-- Padding with invisible characters to prevent body text from showing -->
       &nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;...
     </div>
     ```
2. If preheader is missing: email clients will pull the first visible text from the body.
3. Keep preheader between 40–130 characters for best display across clients.
4. Common mistake: `display:none` stripped by some email clients → use the `max-height:0` + `overflow:hidden` technique.

---

## Issue 113 — CSS compatibility across email clients

**Symptoms:** Email looks different in Gmail vs Outlook vs Apple Mail. Layout is broken in some clients.

**Root cause:** Email clients have vastly different CSS support. Outlook uses Word's rendering engine (limited CSS). Gmail strips `<style>` blocks in some contexts.

**Resolution:**
1. Safe CSS (works everywhere):
   - Inline styles (`style="color: red;"`)
   - Table-based layouts
   - Basic properties: `color`, `font-family`, `font-size`, `background-color`, `padding`, `margin`, `border`, `text-align`, `width`
2. Unsafe/limited CSS:
   - `position`, `float` → limited in Outlook
   - `flexbox`, `grid` → not supported in Outlook
   - `border-radius` → not in Outlook
   - CSS animations → not in most email clients
   - `<style>` blocks → inlined by Gmail for non-AMP
   - Media queries → limited support, best effort
3. Recommendations:
   - Use MJML framework (ApexMail supports it) — generates cross-client compatible HTML.
   - Always use inline styles.
   - Test with multiple clients (Litmus, Email on Acid, or manual testing).
   - Use tables for layout structure (yes, this is 2024 and tables are still required in email).
4. Dark mode considerations:
   - Add `meta name="color-scheme" content="light dark"` and `meta name="supported-color-schemes"`.
   - Avoid hard-coding white backgrounds — use transparent where possible.

---

## Issue 114 — Emoji rendering issues

**Symptoms:** Emojis in subject lines or body display as `?`, `□`, or are replaced with text.

**Root cause:** Character encoding issues, or the receiving email client doesn't support certain Unicode characters.

**Resolution:**
1. Ensure `Content-Type` includes `charset=utf-8` (ApexMail sets this automatically).
2. Common emoji issues:
   - Windows Outlook desktop: limited emoji support, may show black-and-white versions.
   - Older email clients: may not render newer Unicode emojis.
   - Subject line emojis: generally safe for Gmail, Apple Mail, Yahoo. Risky in older Outlook.
3. Tips:
   - Use widely-supported emojis (Unicode 5.0–8.0 for maximum compatibility).
   - Don't rely on emojis for critical meaning — some clients won't render them.
   - Test subject line emojis by sending to yourself across different clients.
4. Encoding: emojis should be UTF-8 encoded in the API request. Don't HTML-encode them in the subject.

---

## Issue 115 — Attachment size limit or encoding errors

**Symptoms:** API returns error when attaching files. Or attachment arrives corrupted/unreadable.

**Root cause:** Attachment exceeds size limit, or incorrect base64 encoding.

**Resolution:**
1. Limits:
   - Maximum total message size: **25 MB** (including all attachments + body).
   - Practical limit: keep attachments under 10 MB for reliable delivery (some ISPs reject large emails).
   - Max recipients per API call: 100.
2. Encoding:
   - Attachments must be **base64-encoded** in the API request.
   - Include correct MIME type: `"content_type": "application/pdf"`.
   - Include filename: `"filename": "invoice.pdf"`.
3. Common errors:
   - Base64 string contains line breaks or whitespace → strip them.
   - Wrong MIME type → file opens as wrong application.
   - File too large → API returns 413 or validation error.
4. Alternative for large files: host the file and include a download link instead of attaching.

---

## Issue 116 — Inline images (CID) not displaying

**Symptoms:** Email has broken image icons. Images referenced via `cid:` not rendering.

**Root cause:** Content-ID (CID) inline images require embedding the image in the MIME message and referencing it by Content-ID. If the implementation is incorrect, images break.

**Resolution:**
1. CID inline image format:
   - Attach the image with a Content-ID header.
   - Reference in HTML: `<img src="cid:logo123">`.
   - The attachment must have `"content_id": "logo123"` and `"disposition": "inline"`.
2. Common issues:
   - Missing `cid:` prefix in the `src` attribute.
   - Content-ID mismatch between attachment and HTML reference.
   - Angle brackets in Content-ID: `<logo123>` in MIME but `cid:logo123` in HTML (without brackets).
3. Alternative approach: host images on a web server and use `https://` URLs instead of CID.
   - More reliable across email clients.
   - Enables image load tracking (open tracking).
   - Some corporate email clients block external images by default, but this is also true for CID in some configurations.
4. Gmail limitation: historically strips some CID images. External hosting is more reliable.

---

## Issue 117 — ICS calendar invitations not rendering properly

**Symptoms:** Calendar event attachment doesn't show as a meeting invite. Instead, it shows as a file attachment.

**Root cause:** ICS (iCalendar) invitations must be sent with specific MIME types and structure to be recognized as calendar events.

**Resolution:**
1. Correct implementation:
   - Content-Type: `text/calendar; method=REQUEST` (for invitations).
   - The ICS content should be an alternative MIME part, NOT an attachment.
   - Structure:
     ```
     multipart/mixed
     ├── multipart/alternative
     │   ├── text/plain
     │   ├── text/html
     │   └── text/calendar; method=REQUEST
     └── application/ics (optional fallback attachment)
     ```
2. Common mistakes:
   - Sending ICS as a regular attachment (shows as downloadable file, not inline invite).
   - Missing `method=REQUEST` in Content-Type.
   - Invalid ICS format (missing VCALENDAR, VEVENT, or required fields).
3. Required ICS fields:
   ```
   BEGIN:VCALENDAR
   VERSION:2.0
   PRODID:-//ApexMail//EN
   METHOD:REQUEST
   BEGIN:VEVENT
   DTSTART:20240115T090000Z
   DTEND:20240115T100000Z
   SUMMARY:Meeting Title
   ORGANIZER:mailto:organizer@example.com
   ATTENDEE:mailto:recipient@example.com
   UID:unique-event-id@example.com
   END:VEVENT
   END:VCALENDAR
   ```
4. Not all email clients render inline ICS identically — Outlook and Apple Mail handle it best.

---

## Issue 118 — Content encoding / garbled characters

**Symptoms:** Email body or subject shows garbled characters: `Ã©`, `â€™`, mojibake, or question marks.

**Root cause:** Character encoding mismatch between what the customer sends and how it's processed/displayed.

**Resolution:**
1. ApexMail uses UTF-8 throughout. Ensure:
   - API requests use UTF-8 encoding for all text fields.
   - If sending raw MIME: `Content-Type: text/html; charset=utf-8`.
   - JSON request body should be UTF-8 (not ISO-8859-1 or Windows-1252).
2. Common encoding issues:
   - Smart quotes ("), em dashes (—), accented characters (é, ñ) from Word/Pages copy-paste.
   - Solution: ensure the data source sends UTF-8, or convert before sending.
3. If using SDK:
   - Node.js SDK: handles UTF-8 natively.
   - Python SDK: ensure strings are Python 3 str (Unicode), not bytes.
4. Subject line: if encoding issues only in subject, check that the subject is UTF-8 and not being double-encoded.

---

## Issue 119 — Custom headers (X-headers) not visible to recipients

**Symptoms:** Customer adds custom headers (e.g., `X-Campaign-ID`) but recipients don't see them.

**Root cause:** Custom headers are part of the email's technical headers, not visible in the email body. They're used for tracking/routing purposes.

**Resolution:**
1. Explain: "Custom X-headers are included in the email's raw headers. Recipients don't see them in normal email viewing — they're only visible in 'View Source' or 'Show Original.'"
2. Use cases for custom headers:
   - Internal tracking: `X-Campaign-ID`, `X-User-ID`
   - Processing rules: `X-Priority`, `X-Mailer`
   - Webhook correlation: headers are included in webhook event data
3. ApexMail preserves customer-set X-headers through delivery.
4. Some headers are reserved and cannot be overridden: `From`, `To`, `Date`, `Message-ID`, `DKIM-Signature`, `Received`.
5. Setting custom headers via API: `"headers": {"X-Campaign-ID": "summer-2024"}`.

---

## Issue 120 — Email renders differently across clients (general)

**Symptoms:** Email looks perfect in Gmail but broken in Outlook. Or vice versa.

**Root cause:** Each email client has its own HTML/CSS rendering engine with different capabilities and quirks.

**Resolution:**
1. Key rendering engines:
   - **Gmail**: strips `<style>` blocks (web), inline styles only; Gmail app retains some styles.
   - **Outlook (desktop)**: uses Microsoft Word rendering engine. Limited CSS support. No `border-radius`, `flexbox`, `grid`.
   - **Apple Mail**: best CSS support. Webkit-based, closest to browser rendering.
   - **Yahoo Mail**: moderate CSS support, similar to Gmail.
   - **Outlook.com (web)**: better than desktop Outlook but still limited.
2. Defensive coding practices:
   - Use tables for layout (not `div` + CSS).
   - Inline all CSS.
   - Use safe fonts: Arial, Helvetica, Georgia, Times New Roman, Verdana.
   - Avoid web fonts (Google Fonts) — only supported in Apple Mail, iOS, some Android.
   - Add `role="presentation"` to layout tables for accessibility.
   - Use `Margin: 0` and `padding: 0` on `<body>` and `<table>`.
3. Use MJML: ApexMail's supported MJML framework generates cross-client compatible HTML automatically.
4. Test strategy:
   - Test in Gmail (web + app), Outlook (desktop + web), Apple Mail (Mac + iOS).
   - Use Litmus or Email on Acid for comprehensive testing (not an ApexMail feature, external tools).
5. Outlook-specific MSO conditionals:
   ```html
   <!--[if mso]>
   <table><tr><td>
   <![endif]-->
   <!-- your content -->
   <!--[if mso]>
   </td></tr></table>
   <![endif]-->
   ```

---

## TPL.GMAIL.CLIPPING — "Gmail clips the email / 'View entire message' link shown"

**Symptoms:** Gmail shows `[Message clipped] View entire message` at the bottom. Content beyond the clipping point is hidden.

**Root cause:** Gmail clips HTML emails exceeding approximately **102 KB** (after encoding). This includes all HTML, CSS, and invisible content.

**Resolution:**

1. **Check message size:**
   - Use the message detail API: `GET /v1/messages/<MSG_ID>` — check the `size` field.
   - Target **under 80 KB** of HTML (leaving margin for Gmail's threshold).

2. **Common size inflators:**
   - Inline CSS repeated across many elements (Gmail doesn't support `<style>` blocks reliably, so inlining is necessary but can bloat the file)
   - Base64-encoded images (use hosted images instead of embedding)
   - Bloated HTML from WYSIWYG editors (nested `<div>` and `<span>` tags)
   - Tracking pixels and hidden content (each adds ~200–500 bytes)
   - Large `<style>` blocks that get inlined during processing

3. **Reduction strategies:**
   - **Use MJML** — generates clean, minimal HTML (~30–50% smaller than WYSIWYG output)
   - **Minify HTML** — remove comments, whitespace, and unused CSS
   - **Host images** — replace `data:image/...` with hosted URLs
   - **Limit template sections** — keep emails focused; link to web version for long content
   - **Remove hidden preheader text** if it's excessively long

4. **Testing:** Send a test email to a Gmail account and check if clipping occurs. Use Gmail's "Show original" to see raw HTML size.

5. **Impact:** Clipped content may include the unsubscribe footer — this can cause CAN-SPAM compliance issues. Always keep the unsubscribe link in the first 80 KB.

---

## TPL.ICS.RSVP — "Calendar ICS with RSVP / interactive meeting invite"

**Symptoms:** Customer wants to send a calendar invite with RSVP buttons that work in Gmail, Outlook, and Apple Mail.

**Root cause:** ICS calendar invites with `METHOD:REQUEST` support varies significantly across email clients.

**Resolution:**

1. **Basic ICS structure** (already covered in Issue 117). This section adds RSVP-specific guidance.

2. **RSVP-capable ICS requirements:**
   ```ics
   BEGIN:VCALENDAR
   VERSION:2.0
   PRODID:-//ApexMail//EN
   METHOD:REQUEST
   BEGIN:VEVENT
   DTSTART:20260315T140000Z
   DTEND:20260315T150000Z
   SUMMARY:Product Demo
   ORGANIZER;RSVP=TRUE:mailto:organizer@example.com
   ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:recipient@example.com
   UID:unique-event-id@example.com
   SEQUENCE:0
   STATUS:CONFIRMED
   END:VEVENT
   END:VCALENDAR
   ```

3. **Client support for RSVP:**

   | Client | RSVP Buttons | Notes |
   |--------|-------------|-------|
   | Gmail (web) | ✅ Yes/Maybe/No | Only with `METHOD:REQUEST` and valid `ORGANIZER` |
   | Outlook (desktop) | ✅ Accept/Tentative/Decline | Best support, handles updates/cancellations |
   | Outlook (web) | ✅ | Same as desktop |
   | Apple Mail | ✅ | Integrates with Calendar.app |
   | Yahoo Mail | ⚠️ Limited | Must download .ics file |
   | Thunderbird | ✅ | Via Lightning add-on |

4. **Critical requirements for RSVP to work:**
   - `ORGANIZER` must be a real, deliverable email address (RSVP responses are sent to this address)
   - `UID` must be unique and consistent for updates (`SEQUENCE` incremented for changes)
   - `METHOD:REQUEST` — not `PUBLISH` (publish is informational only, no RSVP)
   - The ICS must be a `text/calendar; method=REQUEST` MIME part, not just an attachment

5. **MIME structure for ICS with RSVP** (see Issue 117 for base structure):
   ```
   multipart/mixed
   ├── multipart/alternative
   │   ├── text/plain (event details in plain text)
   │   ├── text/html (event details as HTML)
   │   └── text/calendar; method=REQUEST (the ICS content)
   └── application/ics (optional: downloadable .ics attachment)
   ```

6. **Cancellation:** Send a new ICS with `METHOD:CANCEL`, same `UID`, incremented `SEQUENCE`, and `STATUS:CANCELLED`.

---

## Troubleshooting Decision Tree (Section H)

```
Template/rendering/content issue
├── Variable shows raw {{...}} → Issue 109 (name mismatch, typo, missing data)
├── Template syntax error → Issue 110 (unclosed blocks, wrong helpers)
├── Security concern (XSS) → Issue 111 (use double braces, escape by default)
├── Preheader not showing → Issue 112 (hidden div technique, API field)
├── CSS broken in Outlook → Issue 113 (inline styles, tables, MJML)
├── Emoji rendering → Issue 114 (UTF-8, client support varies)
├── Attachment errors → Issue 115 (25MB limit, base64 encoding)
├── Inline images broken → Issue 116 (CID format, consider hosted images)
├── Calendar invite → Issue 117 (ICS method=REQUEST, MIME structure)
│   └── RSVP buttons → TPL.ICS.RSVP
├── Garbled characters → Issue 118 (UTF-8, encoding mismatch)
├── Custom headers → Issue 119 (X-headers, not visible in UI)
├── Rendering differs by client → Issue 120 (tables, inline CSS, MJML, test)
└── Gmail clips message → TPL.GMAIL.CLIPPING
```
