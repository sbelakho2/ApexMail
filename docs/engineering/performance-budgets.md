# Performance Budgets

> Last updated: 2026-07-29
> Enforcement: CI build warns on threshold exceed; blocks release on critical failures.

## Homepage

| Metric | Budget | Severity |
|--------|--------|----------|
| Largest Contentful Paint (LCP) | < 2.5s | Critical |
| Interaction to Next Paint (INP) | < 200ms | Critical |
| Cumulative Layout Shift (CLS) | < 0.1 | Critical |
| Time to First Byte (TTFB) | < 800ms | Warning |
| Total JavaScript | < 300 KB | Warning |
| Total CSS | < 50 KB | Warning |
| Total image bytes | < 500 KB | Warning |
| Total font bytes | < 100 KB | Warning |
| Third-party request count | < 5 | Warning |
| Total page weight | < 1.5 MB | Warning |

## Pricing

| Metric | Budget | Severity |
|--------|--------|----------|
| LCP | < 2.5s | Critical |
| INP | < 200ms | Critical |
| CLS | < 0.1 | Critical |
| TTFB | < 800ms | Warning |
| Total JavaScript | < 400 KB | Warning |
| Total CSS | < 60 KB | Warning |
| Total image bytes | < 400 KB | Warning |
| Total page weight | < 1.2 MB | Warning |

## Documentation

| Metric | Budget | Severity |
|--------|--------|----------|
| LCP | < 3.0s | Warning |
| INP | < 200ms | Critical |
| CLS | < 0.1 | Critical |
| TTFB | < 1.0s | Warning |
| Total JavaScript | < 200 KB | Warning |
| Total CSS | < 80 KB | Warning |
| Total page weight | < 1.0 MB | Warning |

## Signup

| Metric | Budget | Severity |
|--------|--------|----------|
| LCP | < 2.5s | Critical |
| INP | < 200ms | Critical |
| CLS | < 0.1 | Critical |
| TTFB | < 600ms | Warning |
| Total JavaScript | < 250 KB | Warning |
| Total page weight | < 800 KB | Warning |

## Enterprise / Private Cloud

| Metric | Budget | Severity |
|--------|--------|----------|
| LCP | < 3.0s | Warning |
| INP | < 200ms | Critical |
| CLS | < 0.1 | Critical |
| TTFB | < 1.0s | Warning |
| Total JavaScript | < 300 KB | Warning |
| Total page weight | < 1.5 MB | Warning |

## Measurement

- Mobile: Simulated Moto G4, 3G Fast throttling (Lighthouse)
- Desktop: Simulated 10 Mbps down, 2 Mbps up (Lighthouse)
- Real User Monitoring (RUM): Enabled where possible via analytics
- CI: Lighthouse CI runs on every PR; budgets checked on main branch builds
