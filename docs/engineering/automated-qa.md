# Automated Quality Assurance

> Last updated: 2026-07-29

## Broken Link Testing

Run on every production build:

| Check | Tool | Blocking |
|-------|------|----------|
| Internal links | Link checker (CI) | Critical |
| External links | Link checker (weekly cron) | Warning |
| Anchor links | Link checker (CI) | Critical |
| Redirect chains | Link checker (CI) | Warning |
| Redirect loops | Link checker (CI) | Critical |
| Missing images | Link checker (CI) | Critical |
| Missing downloads | Link checker (CI) | Warning |
| HTTP 4xx responses | Link checker (CI) | Critical |
| HTTP 5xx responses | Link checker (CI) | Warning |
| Broken canonical URLs | SEO checker (CI) | Critical |
| Broken Open Graph images | SEO checker (CI) | Warning |

## HTML and Accessibility Validation

| Check | Tool | Blocking |
|-------|------|----------|
| Duplicate IDs | HTML validator (CI) | Critical |
| Missing form labels | axe-core (CI) | Critical |
| Invalid heading hierarchy | axe-core (CI) | Critical |
| Missing alt attributes | axe-core (CI) | Critical |
| Empty buttons | axe-core (CI) | Critical |
| Invalid ARIA attributes | axe-core (CI) | Critical |
| Duplicate H1 | HTML validator (CI) | Critical |
| Missing page title | HTML validator (CI) | Critical |
| Color contrast | axe-core (CI) | Warning |
| Keyboard traps | Manual testing | Warning |

Critical accessibility failures block release. Known exceptions are documented with remediation timeline. Manual testing supplements automation.

## Browser Console and Network Tests

Run on critical pages (homepage, pricing, docs, signup):

| Check | Tool | Blocking |
|-------|------|----------|
| JavaScript errors | Playwright (CI) | Critical |
| Failed API requests | Playwright (CI) | Critical |
| Failed image loads | Playwright (CI) | Critical |
| Failed font loads | Playwright (CI) | Warning |
| CORS errors | Playwright (CI) | Critical |
| Mixed content | Playwright (CI) | Critical |
| Unhandled promise rejections | Playwright (CI) | Critical |
| Hydration errors | Playwright (CI) | Critical (for SPA pages) |
| Cookie consent errors | Playwright (CI) | Critical |

## Cross-Browser Testing

Supported browser versions:

| Browser | Minimum Version | Tested |
|---------|----------------|--------|
| Chrome | Latest 2 versions | Yes |
| Safari | Latest 2 versions | Yes |
| Firefox | Latest 2 versions | Yes |
| Edge | Latest 2 versions | Yes |

Critical journeys tested per browser:
- Homepage to signup
- Pricing calculation (calculator)
- Documentation navigation
- Code-copy behavior
- Enterprise form submission
- Login and password reset
- Legal pages (terms, privacy, DPA)
- Status subscription
- Mobile menu at narrow viewport

## Mobile Testing

Tested widths (CSS pixels): 320, 360, 375, 390, 414, 768

Checks per width:
- No horizontal scrolling (except scrollable code/tables)
- CTAs visible and tappable
- Form fields fit viewport
- Text does not overlap
- Touch targets ≥ 44x44 CSS pixels
- Sticky elements do not hide content
- Pricing cards stack correctly
- Calculator usable on mobile
- Code blocks scroll horizontally
- Modal dialogs fully visible
- Footer links accessible
- Diagrams readable or have text alternatives
- Documentation sidebar collapses correctly
- Comparison tables scrollable with sticky headers
- Legal text readable without excessive zoom
