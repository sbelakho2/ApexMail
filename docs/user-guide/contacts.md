# Contact Management

This guide covers everything you need to know about managing contacts in ApexMail — from importing your first list to maintaining long-term list hygiene and staying compliant with privacy regulations.

---

## Contact Lists

Every ApexMail account comes with a set of default lists, and you can create as many custom lists as you need.

### Default Lists

| List              | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| **All Contacts**  | Every contact in your account, regardless of list membership. |
| **Newsletter**    | Contacts subscribed to your newsletter content.              |
| **VIP**           | High-value contacts flagged for priority treatment.          |
| **Product Updates** | Contacts who opted in to product release and changelog emails. |

### Custom Lists

Create custom lists to match your business needs:

1. Navigate to **Contacts → Lists**.
2. Click **Create List**.
3. Enter a name, optional description, and default tags.
4. Click **Save**.

Custom lists support the same filtering, segmentation, and bulk-action capabilities as default lists.

> **Tip:** Use lists for broad audience categories and tags for fine-grained segmentation within those lists.

---

## Adding Contacts

### Individual Contact

1. Go to **Contacts → All Contacts**.
2. Click **Add Contact**.
3. Fill in the required fields (at minimum, an email address).
4. Assign to one or more lists.
5. Click **Save**.

**Via API:**

```bash
curl -X POST https://api.apexmail.ee/v1/contacts \
  -H "X-API-Key: am_live_<hex>" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "jane@example.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "lists": ["newsletter", "product-updates"],
    "tags": ["early-adopter"],
    "metadata": {
      "company": "Acme Inc.",
      "role": "CTO"
    }
  }'
```

### CSV Import

For bulk additions, use CSV import:

1. Go to **Contacts → Import**.
2. Upload a `.csv` file (max 25 MB / 100,000 rows per import).
3. Map CSV columns to ApexMail contact fields.
4. Choose the target list(s).
5. Select the conflict resolution strategy:
   - **Skip** — ignore rows whose email already exists.
   - **Update** — merge new data into existing contacts.
   - **Overwrite** — replace existing contact data entirely.
6. Click **Start Import**.

The import runs asynchronously. You will receive a summary email and can monitor progress under **Contacts → Imports**.

**Required CSV columns:**

| Column   | Required | Notes                        |
| -------- | -------- | ---------------------------- |
| `email`  | Yes      | Must be a valid email format |

All other columns are optional and will be mapped to standard or custom fields during the mapping step.

---

## Contact Fields and Metadata

### Standard Fields

| Field            | Type     | Description                                  |
| ---------------- | -------- | -------------------------------------------- |
| `email`          | string   | Primary identifier (unique per account)      |
| `firstName`      | string   | Contact's first name                         |
| `lastName`       | string   | Contact's last name                          |
| `phone`          | string   | Phone number (E.164 format recommended)      |
| `company`        | string   | Company or organization name                 |
| `status`         | enum     | `active`, `unsubscribed`, `bounced`, `complained` |
| `source`         | string   | How the contact was acquired (e.g., `csv-import`, `api`, `signup-form`) |
| `createdAt`      | datetime | When the contact was first added             |
| `lastActivityAt` | datetime | Timestamp of last open, click, or reply      |

### Custom Metadata

You can store arbitrary key-value metadata on any contact using the `metadata` object. Metadata is useful for:

- Enrichment data (industry, job title, company size)
- Internal identifiers (CRM ID, Stripe customer ID)
- Segmentation attributes (plan tier, signup cohort)

Metadata values can be strings, numbers, or booleans. Nested objects are not supported.

```json
{
  "metadata": {
    "plan": "enterprise",
    "mrr": 4999,
    "signupCohort": "2025-Q4",
    "isBetaUser": true
  }
}
```

---

## Contact Scoring

ApexMail assigns each contact an **engagement score** (0–100) that reflects how actively they interact with your emails. The score is recalculated periodically based on:

| Signal             | Weight | Description                              |
| ------------------ | ------ | ---------------------------------------- |
| Opens              | Low    | Contact opened an email                  |
| Clicks             | Medium | Contact clicked a link in an email       |
| Replies            | High   | Contact replied to an email              |
| Recency            | High   | How recently the last interaction occurred |
| Frequency          | Medium | How often the contact engages            |
| Complaint          | Negative | Contact marked an email as spam        |
| Unsubscribe        | Negative | Contact unsubscribed from a list       |

### Score Tiers

| Score Range | Tier         | Recommended Action                        |
| ----------- | ------------ | ----------------------------------------- |
| 80–100      | **Hot**      | Prioritize; ideal for upsell/cross-sell   |
| 50–79       | **Warm**     | Nurture with regular content              |
| 20–49       | **Cool**     | Consider re-engagement campaign           |
| 0–19        | **Cold**     | Sunset candidate; reduce send frequency   |

Use scores in segments to target high-engagement contacts or to trigger re-engagement automations for low-scoring ones.

---

## Status Filters

Every contact has a `status` that controls whether they can receive emails.

| Status           | Can Receive Email? | Description                                                   |
| ---------------- | :-: | ------------------------------------------------------------- |
| **Active**       | ✅ | Contact is in good standing and eligible for sends.           |
| **Unsubscribed** | ❌ | Contact opted out. Honoring this is legally required.         |
| **Bounced**      | ❌ | Email address hard-bounced and was auto-suppressed.           |
| **Complained**   | ❌ | Contact filed a spam complaint (FBL report received).         |

Filter contacts by status in the UI using the status dropdown, or via API:

```bash
GET /v1/contacts?status=active&list=newsletter
```

> **Note:** Contacts with `unsubscribed`, `bounced`, or `complained` status are automatically excluded from sends even if they appear in a target list. You do not need to manually filter them.

---

## Tags and Segmentation

### Tags

Tags are lightweight labels you can attach to contacts for flexible grouping.

- Tags are free-form strings (e.g., `webinar-attendee`, `enterprise`, `churned`).
- A contact can have unlimited tags.
- Tags are case-insensitive and trimmed of whitespace.

**Adding tags:**

- **UI:** Select contacts → **Actions** → **Add Tag**.
- **API:** `PATCH /v1/contacts/:id` with `{ "tags": { "add": ["new-tag"] } }`.
- **CSV Import:** Include a `tags` column with comma-separated values.

### Segments

Segments are dynamic groups defined by filter rules. Unlike lists, segments update automatically as contacts match or stop matching the criteria.

Example segment: *"Active contacts on the Newsletter list with a score above 60 who clicked an email in the last 30 days."*

Segment filters can combine:

- List membership
- Status
- Tags (has / does not have)
- Engagement score (above / below threshold)
- Metadata fields (equals, contains, greater than, etc.)
- Activity date ranges (last open, last click, created date)
- Geographic data (country, timezone)

---

## Bulk Actions

Select multiple contacts (or an entire filtered view) and apply bulk actions:

| Action          | Description                                              |
| --------------- | -------------------------------------------------------- |
| **Add Tag**     | Apply one or more tags to selected contacts.             |
| **Remove Tag**  | Remove a tag from selected contacts.                     |
| **Add to List** | Add selected contacts to a list.                         |
| **Remove from List** | Remove selected contacts from a list.               |
| **Send Email**  | Compose and send an email to the selected contacts.      |
| **Export**       | Download selected contacts as a CSV file.                |
| **Delete**       | Permanently delete selected contacts. *Irreversible.*    |

Bulk actions on more than 10,000 contacts run asynchronously. You'll receive a notification when the action completes.

---

## List Hygiene Best Practices

Maintaining a clean contact list is critical for deliverability. Follow these practices:

### 1. Remove Hard Bounces

Hard bounces (permanent delivery failures) are **automatically suppressed** by ApexMail. When a hard bounce is detected:

- The contact's status is set to `bounced`.
- The email address is added to the [suppression list](#suppression-list-integration).
- No further sends are attempted to that address.

You do not need to take manual action, but you should periodically review bounced contacts and remove them from your lists to keep counts accurate.

### 2. Monitor Soft Bounces

Soft bounces (temporary failures) are retried automatically with exponential backoff (30s base, 30-minute cap, up to 3 retries). If a contact soft-bounces repeatedly across multiple campaigns, investigate:

- Mailbox full (suggest the contact use a different address)
- Temporary server issue (usually resolves itself)
- Contacts that soft-bounce on 3+ consecutive campaigns should be flagged for review.

### 3. Run Re-engagement Campaigns

For contacts who haven't opened or clicked in 60–90 days:

1. Create a segment with the filter: `lastActivityAt < 90 days ago AND status = active`.
2. Send a dedicated re-engagement email ("We miss you", special offer, preference update prompt).
3. Give contacts 14–30 days to re-engage.
4. If they don't re-engage, consider moving them to a reduced-frequency list or sunsetting them.

### 4. Sunset Policy

Establish a sunset policy — a clear rule for when inactive contacts are removed:

| Recommended Policy                | Action                                   |
| --------------------------------- | ---------------------------------------- |
| No activity in **90 days**        | Move to re-engagement segment            |
| No activity in **120 days**       | Reduce frequency to monthly digest only  |
| No activity in **180 days**       | Unsubscribe and remove from active lists |

A strict sunset policy protects your sender reputation by reducing bounces and complaints from disengaged recipients.

### 5. Validate on Import

- Reject obviously invalid addresses during CSV import (syntax check is automatic).
- Consider integrating a third-party email verification service before large imports.
- Remove role-based addresses (`info@`, `admin@`, `support@`) unless they are explicitly opted in.

---

## Suppression List Integration

The suppression list is a global, account-wide list of email addresses that must never receive email. It takes precedence over all contact lists and segments.

Addresses are added to the suppression list when:

- A **hard bounce** occurs (automatic).
- A **spam complaint** (FBL) is received (automatic).
- A contact **unsubscribes** (automatic).
- You **manually add** an address via the UI or API.
- A **bulk suppression import** is performed.

### Managing the Suppression List

```bash
# Check if an address is suppressed
GET /v1/suppressions/check?email=user@example.com

# Add to suppression list
POST /v1/suppressions
{ "email": "user@example.com", "reason": "manual", "comment": "Requested removal" }

# Bulk add
POST /v1/suppressions/bulk
{ "entries": [{ "email": "a@example.com", "reason": "manual" }, ...] }

# Import suppressions from CSV (up to 100,000 entries)
POST /v1/suppressions/import

# Export suppression list
GET /v1/suppressions/export
```

> **Warning:** Removing an address from the suppression list re-enables sending to that address. Only do this if you have explicit, documented consent from the recipient.

---

## Subscription Preferences

ApexMail supports a **preference center** — a hosted page where contacts can manage their subscription preferences without fully unsubscribing.

### Per-Category Toggles

Configure subscription categories that contacts can individually enable or disable:

| Category           | Default | Description                          |
| ------------------ | ------- | ------------------------------------ |
| Newsletter         | On      | Weekly newsletter content            |
| Product Updates    | On      | Product releases and changelogs      |
| Marketing          | On      | Promotions, offers, and events       |
| Transactional      | Always On | Receipts, password resets (cannot unsubscribe) |

### Setting Up the Preference Center

1. Go to **Settings → Subscription Preferences**.
2. Add or edit categories.
3. Customize the hosted preference center page (logo, colors, copy).
4. The preference center URL is automatically included in the `{{{unsubscribe_url}}}` and `{{{preferences_url}}}` template variables.

When a contact updates their preferences, ApexMail automatically respects those choices on future sends. Emails tagged with a category the contact has disabled will be skipped for that contact.

---

## GDPR Compliance

ApexMail provides built-in tools to help you meet your obligations under the General Data Protection Regulation (GDPR) and similar privacy laws (CCPA, etc.).

### Right of Access (Article 15)

Contacts have the right to request a copy of all personal data you hold about them.

- **UI:** Go to the contact's profile → **Actions** → **Export Data**. This generates a JSON file containing all stored data.
- **API:** `GET /v1/contacts/:id/export` returns a complete data export.

### Right to Data Portability (Article 20)

Contacts can request their data in a machine-readable format. The export endpoint returns JSON, which satisfies the portability requirement.

### Right to Erasure (Article 17) — "Right to Be Forgotten"

Contacts can request deletion of all their personal data.

- **UI:** Go to the contact's profile → **Actions** → **Delete Contact**. This permanently removes all personal data.
- **API:** `DELETE /v1/contacts/:id` permanently deletes the contact record.

On deletion:

- All personal data fields are erased.
- The email address hash is retained in the suppression list to prevent accidental re-addition.
- Aggregated, anonymized analytics data is retained (e.g., total send counts are not decremented).
- Deletion is irreversible.

### Consent Management

- Store consent proof in contact metadata (timestamp, source, IP address).
- Use the `source` field to document how consent was obtained (e.g., `signup-form`, `double-opt-in`).
- ApexMail does not send to contacts with `unsubscribed` or `complained` status, ensuring withdrawn consent is honored.

### Data Retention

Configure automatic data retention policies under **Settings → Privacy**:

- Set a retention period for contact activity logs.
- Automatically anonymize event data older than the retention period.
- Audit logs are retained for the minimum period required by your compliance framework.

---

## Contact Lifecycle Management

Understanding where each contact is in their lifecycle helps you send the right message at the right time.

### Lifecycle Stages

```
┌───────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐
│   New      │───▶│  Active   │───▶│  Cooling  │───▶│  Sunset   │
│ (0–7 days) │    │ (engaged) │    │ (inactive)│    │ (removed) │
└───────────┘    └───────────┘    └───────────┘    └───────────┘
                       │                                  │
                       │          ┌───────────┐           │
                       └─────────▶│ Suppressed│◀──────────┘
                                  │ (bounced/ │
                                  │ complained)│
                                  └───────────┘
```

### Recommended Actions by Stage

| Stage        | Criteria                          | Recommended Action                          |
| ------------ | --------------------------------- | ------------------------------------------- |
| **New**      | Added in the last 7 days          | Welcome series, onboarding emails           |
| **Active**   | Opened/clicked in the last 30 days | Regular content, promotional campaigns      |
| **Cooling**  | No activity in 31–90 days         | Re-engagement campaign, preference update   |
| **Sunset**   | No activity in 90+ days           | Final re-engagement attempt, then remove    |
| **Suppressed** | Bounced, complained, or unsubscribed | No action; contact is excluded from sends |

### Automating Lifecycle Transitions

Use segments and automation rules to move contacts through lifecycle stages automatically:

1. **Welcome flow:** Trigger when `source = signup-form` and `createdAt < 7 days ago`.
2. **Re-engagement flow:** Trigger when `lastActivityAt > 60 days ago` and `status = active`.
3. **Sunset flow:** Trigger when re-engagement campaign was sent and no activity after 30 days.

---

## Further Reading

- [Troubleshooting](troubleshooting.md) — solutions for common delivery issues
- [Glossary](glossary.md) — definitions of email and ApexMail terms
- [API Changelog](../api/changelog.md) — latest API updates
- [Suppression API Reference](../api/changelog.md) — suppression endpoints
- [Compliance Documentation](../compliance/) — detailed compliance framework
