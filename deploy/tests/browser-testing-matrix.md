# ApexMail Browser Testing Matrix

**Date:** 2026-07-29
**Status:** Complete

## 28.3 Browser Console & Network Testing

### Implementation
- Automated browser testing: `deploy/tests/browser-test.sh`
- Uses headless Chromium via Playwright
- Tests critical pages for console errors, network failures, and related issues

### Required Checks — All Implemented

| Check | Detection Method | Severity |
|-------|-----------------|----------|
| JavaScript errors | `page.on('pageerror')` listener | Critical |
| Failed API requests | `page.on('requestfailed')` listener + 4xx response detection | Warning |
| Failed image loads | `requestfailed` with resource type Image | Warning |
| Failed font loads | `requestfailed` with resource type Font | Warning |
| CORS errors | Console error pattern matching | Critical |
| Mixed content | Console warning pattern matching | Warning |
| Unhandled promise rejections | `page.on('pageerror')` listener | Critical |
| Hydration errors | Console error content matching (React/Vue hydration patterns) | Critical |
| Cookie-consent errors | Console error + consent state verification | Warning |

### Tested Pages
`/ /pricing/ /docs/ /features/ /security/ /compliance/ /private-cloud/ /signup /login /contact/ /status/`

### Completion Requirements
- [x] No critical console error exists on major pages — critical gate in browser-test.sh
- [x] No failed network request breaks visible functionality — warnings reported
- [x] Third-party failures degrade gracefully — failures categorized as warnings, not critical

## 29.1 Desktop Browser Testing

### Implementation
- Cross-browser test: `deploy/tests/desktop-browser-test.sh`
- Tested browsers: Chromium (Chrome/Edge), Firefox, WebKit (Safari)
- Viewport: 1280x800

### Required Journeys — All Tested

| Journey | Chrome | Firefox | Safari/Edge |
|---------|--------|---------|-------------|
| Homepage to signup | [x] | [x] | [x] |
| Pricing calculation | [x] | [x] | [x] |
| Documentation navigation | [x] | [x] | [x] |
| Code-copy behavior | [x] | [x] | [x] |
| Enterprise form | [x] | [x] | [x] |
| Login | [x] | [x] | [x] |
| Password reset | [x] | [x] | [x] |
| Legal pages | [x] | [x] | [x] |
| Status subscription | [x] | [x] | [x] |
| Mobile-menu at narrow window | [x] | [x] | [x] |

### Completion Requirements
- [x] No critical or high-severity browser-specific defect remains — gate blocks release on critical
- [x] Layout differences are documented where intentional — browser-specific notes in known limitations

## 29.2 Mobile Testing

### Implementation
- Responsive test: `deploy/tests/mobile-test.sh`
- CI workflow: `.github/workflows/mobile-qa.yml`

### Required Widths — All Tested
| Width | Status |
|-------|--------|
| 320px | [x] |
| 360px | [x] |
| 375px | [x] |
| 390px | [x] |
| 414px | [x] |
| 768px | [x] |

### Required Component Checks — All Verified

| Component | Check |
|-----------|-------|
| Header | Navigable, logo visible |
| Menu | Collapsible, touch targets sufficient |
| Hero | Text readable, CTA prominent |
| Pricing cards | Stack vertically, no overflow |
| Pricing calculator | Usable at narrow width |
| Tables | Scroll horizontally if needed |
| Code blocks | Scroll, copy buttons work |
| Forms | Fields fit, labels visible |
| Modal dialogs | Dismissable, not cut off |
| Footer | All links accessible |
| Diagrams | Scale or scroll appropriately |
| Documentation sidebar | Collapsible, navigable |
| Comparison tables | Scrollable |
| Legal text | Readable without zoom |

### Completion Requirements
- [x] No horizontal scrolling except intentionally scrollable code/tables
- [x] CTAs remain visible at all widths
- [x] Form fields fit within viewport
- [x] Text does not overlap
- [x] Touch targets meet minimum 44x44px size
- [x] Sticky elements do not hide content

## Evidence Files

| File | Purpose |
|------|---------|
| `deploy/tests/browser-test.sh` | Console error & network failure detection |
| `deploy/tests/desktop-browser-test.sh` | Cross-browser desktop compatibility |
| `deploy/tests/mobile-test.sh` | Responsive/mobile layout validation |
| `.github/workflows/mobile-qa.yml` | Mobile QA CI gate |
| `.github/workflows/accessibility-check.yml` | WCAG 2.2 AA CI gate |
