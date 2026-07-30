# Analytics Event Taxonomy

> Last updated: 2026-07-29
> All events use snake_case naming. Events fire once per intended action.

## Funnel Events

| Event Name | Trigger | Required Fields |
|-----------|---------|-----------------|
| `homepage_viewed` | User lands on homepage | user_id, session_id, timestamp, page, referrer |
| `pricing_viewed` | User views pricing page | user_id, session_id, timestamp, page, referrer |
| `documentation_viewed` | User views any docs page | user_id, session_id, timestamp, page, referrer |
| `sdk_viewed` | User views SDK documentation | user_id, session_id, timestamp, page, sdk_language |
| `signup_started` | User clicks signup/register | user_id, session_id, timestamp, page, referrer, utm_source, utm_medium, utm_campaign |
| `signup_completed` | Account successfully created | user_id, session_id, timestamp, auth_method |
| `email_verified` | User confirms email address | user_id, session_id, timestamp |
| `domain_added` | User adds a sending domain | user_id, session_id, timestamp, domain_count |
| `domain_verified` | Domain verification succeeds | user_id, session_id, timestamp |
| `api_key_created` | User creates first API key | user_id, session_id, timestamp |
| `first_send_attempted` | First email send API call | user_id, session_id, timestamp |
| `first_send_accepted` | First email accepted for delivery | user_id, session_id, timestamp |
| `first_send_delivered` | First email confirmed delivered | user_id, session_id, timestamp |
| `paid_plan_selected` | User selects paid plan | user_id, session_id, timestamp, plan, billing_period |
| `checkout_started` | User enters checkout flow | user_id, session_id, timestamp, plan, billing_period |
| `subscription_completed` | Payment processed successfully | user_id, session_id, timestamp, plan, billing_period, amount_eur |
| `enterprise_form_started` | User begins enterprise form | user_id, session_id, timestamp, page |
| `enterprise_form_submitted` | Enterprise form submission | user_id, session_id, timestamp, form_type |
| `private_cloud_form_submitted` | Private Cloud inquiry submitted | user_id, session_id, timestamp |

## CTA Click Events

| Event Name | Page | CTA |
|-----------|------|-----|
| `cta_start_free_click` | Homepage, Pricing | "Start free" |
| `cta_view_pricing_click` | Homepage | "View pricing" |
| `cta_read_docs_click` | Homepage, SDK pages | "Read documentation" |
| `cta_send_first_email_click` | Getting Started | "Send first email" |
| `cta_contact_sales_click` | Enterprise, Pricing | "Contact sales" |
| `cta_architecture_review_click` | Enterprise | "Request architecture review" |
| `cta_security_package_click` | Enterprise | "Request security package" |
| `cta_private_cloud_click` | Enterprise, Private Cloud | "Discuss Private Cloud" |
| `cta_start_migration_click` | Compare pages | "Start migration" |
| `cta_compare_plans_click` | Pricing | "Compare plans" |

## Event Field Definitions

| Field | Description |
|-------|-------------|
| `user_id` | Authenticated user ID or anonymous session ID |
| `session_id` | Unique session identifier |
| `timestamp` | ISO 8601 UTC timestamp |
| `page` | Current page URL path |
| `referrer` | Document referrer |
| `utm_source` | UTM campaign source |
| `utm_medium` | UTM campaign medium |
| `utm_campaign` | UTM campaign name |
| `plan` | Selected plan name |
| `volume_tier` | Email volume tier |
| `auth_method` | Authentication method (email, google, github) |
| `error_state` | Error message if action failed |
| `device_category` | mobile, tablet, or desktop |

## Privacy Compliance

- No personally identifiable information (PII) in event payloads beyond user_id
- user_id is pseudonymized where required
- Cookie consent required before analytics events fire
- Data retention per privacy policy
- Analytics subprocessor listed in subprocessor documentation
- Opt-out respected; no events fire after consent withdrawal
- Deleted account data handled per data deletion policy
