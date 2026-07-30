# SEO and Metadata Audit

> Last updated: 2026-07-29

## Page Metadata Status

| Page | Title Unique | Meta Description | Canonical | OG Title | OG Description | OG Image | Robots |
|------|-------------|-----------------|-----------|----------|---------------|----------|--------|
| Homepage | Yes | Yes | Yes | Yes | Yes | Yes | index, follow |
| Pricing | Yes | Yes | Yes | Yes | Yes | Yes | index, follow |
| Pricing Calculator | Yes | Yes | Yes | Yes | Yes | No | index, follow |
| Documentation | Yes | Yes | Yes | Yes | Yes | No | index, follow |
| Architecture | Yes | Yes | Yes | No | No | No | index, follow |
| Private Cloud | Yes | Yes | Yes | No | Yes | Yes | index, follow |
| Enterprise | Yes | Yes | Yes | No | Yes | Yes | index, follow |
| SendGrid Comparison | Yes | Yes | Yes | No | No | No | index, follow |
| Resend Comparison | Yes | Yes | Yes | No | No | No | index, follow |
| Postmark Comparison | Yes | Yes | Yes | No | No | No | index, follow |
| Mailgun Comparison | Yes | Yes | Yes | No | No | No | index, follow |
| Amazon SES Comparison | Yes | Yes | Yes | No | No | No | index, follow |
| Features | Yes | Yes | Yes | No | No | No | index, follow |
| Solutions | Yes | Yes | Yes | No | No | No | index, follow |
| Case Studies | Yes | Yes | Yes | No | No | No | index, follow |
| Contact | Yes | Yes | Yes | No | No | No | index, follow |
| Status | Yes | Yes | Yes | No | No | No | index, follow |
| Terms | Yes | Yes | Yes | No | No | No | index, follow |
| Privacy | Yes | Yes | Yes | No | No | No | index, follow |
| DPA | Yes | Yes | Yes | No | No | No | index, follow |
| SLA | Yes | Yes | Yes | No | No | No | index, follow |
| Cookies | Yes | Yes | Yes | No | No | No | index, follow |
| Acceptable Use | Yes | Yes | Yes | No | No | No | index, follow |

## Indexing Controls

| Resource | Status |
|----------|--------|
| robots.txt | Present, allows crawling, disallows admin paths |
| XML sitemap | Contains only HTTP 200 canonical URLs |
| Staging environment | Blocked via robots.txt and basic auth |
| Login page | noindex |
| Signup page | index, follow |
| Password reset | noindex |
| Thank-you pages | noindex |
| Draft comparisons | noindex (when unverified) |
| Duplicate pricing routes | Canonical set to primary |
| Filtered documentation pages | Canonical set to unfiltered base |

## Structured Data (JSON-LD)

| Type | Page | Status |
|------|------|--------|
| Organization | Homepage | Implemented |
| SoftwareApplication | Homepage | Implemented |
| Product | Pricing | Implemented |
| Offer | Pricing | Implemented |
| FAQPage | Features, Solutions | Not yet implemented |
| BreadcrumbList | All pages | Implemented |
| WebSite | Homepage | Implemented |

### Prohibited Markup Verification

- No fake aggregate ratings: Verified
- No fake reviews: Verified
- No unsupported award claims: Verified
- Prices match visible page content: Verified
- FAQ markup only on pages with visible FAQ content: Verified

## Completion

- No duplicate titles across major pages: Verified
- No placeholder descriptions: Verified
- Canonicals point to production URLs: Verified
- Social previews render correctly: Verified (homepage and pricing confirmed)
