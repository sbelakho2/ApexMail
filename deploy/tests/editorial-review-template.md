# ApexMail Editorial Review Template

**Purpose:** Structured review required for every published page.
**Status:** Complete — template defined
**Enforcement:** CMS publishing requires appropriate approvals.

## Page Metadata

| Field | Value |
|-------|-------|
| Page URL | |
| Page title | |
| Owner (name/team) | |
| Review date | |
| Next review date | |
| Version reviewed | |

## Review Checklist

### 1. Factual Accuracy
- [ ] All statements verifiable against product behavior
- [ ] Feature descriptions match implemented functionality
- [ ] Performance claims match measured results
- [ ] No planned features described as live

### 2. Claim-Register Approval
- [ ] Claims registered in claim register
- [ ] Evidence linked for each registered claim
- [ ] Claims within expiry date
- [ ] Legal entity identification consistent

### 3. Legal Identity
- [ ] Bel Consulting OÜ (reg 16588745, VAT EE102951727) correctly stated
- [ ] Legal entity references consistent
- [ ] No obsolete company identifiers

### 4. Pricing Accuracy
- [ ] Prices match billing configuration (`config.toml`)
- [ ] Overage rates match billing enforcement
- [ ] Plan limits match product enforcement
- [ ] Annual discount correctly stated (10%)
- [ ] VAT/tax handling disclosed

### 5. Technical Accuracy
- [ ] API behavior descriptions accurate
- [ ] Rate limits correctly stated
- [ ] SDK capabilities current
- [ ] Webhook events match published schema
- [ ] Delivery metrics taken from Message Events

### 6. Terminology
- [ ] Product names match `product-names-register.md`
- [ ] Technical terms used consistently
- [ ] No deprecated names or branding

### 7. Grammar
- [ ] Spelling checked
- [ ] Grammar reviewed
- [ ] No placeholder or lorem ipsum text

### 8. Accessibility
- [ ] WCAG 2.2 AA contrast checked
- [ ] Alt text on all images
- [ ] Heading hierarchy valid
- [ ] All interactive elements keyboard-accessible
- [ ] ARIA attributes valid
- [ ] Skip-to-content link present

### 9. Metadata
- [ ] Unique page title
- [ ] Unique meta description
- [ ] Canonical URL set
- [ ] Open Graph tags complete
- [ ] Twitter card tags complete
- [ ] Robots directives correct

### 10. Links
- [ ] Internal links valid (no broken)
- [ ] External links checked (accessible)
- [ ] Anchors valid (no broken hashes)
- [ ] No redirect chains exceeding max depth
- [ ] Canonical URLs resolve correctly

### 11. Mobile Layout
- [ ] Responsive at 320, 360, 375, 390, 414, 768px
- [ ] No horizontal scroll
- [ ] CTAs visible at all widths
- [ ] Touch targets >= 44x44px
- [ ] Forms fit without overflow
- [ ] No text overlap

### 12. CTA Tracking
- [ ] All CTAs have unique tracking events
- [ ] Event names identify page and CTA
- [ ] Device category distinguished (mobile/desktop)
- [ ] Events link to downstream conversion

### 13. Owner Assignment
- [ ] Page owner identified
- [ ] Contact information current

### 14. Review Date
- [ ] Review date recorded
- [ ] Next review date set
- [ ] Outdated flag mechanism in place

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Author | | | |
| Technical Reviewer | | | |
| Product Owner | | | |

## Outdated Page Handling
- Pages past their next review date are flagged for re-review.
- Review triggers are automated via CI (page crawled, stamp compared).

## Evidence
- Template stored at `deploy/tests/editorial-review-template.md`
- Automated enforcement via CI gates where feasible
