/**
 * Island Hydration Runtime
 *
 * Scans the DOM for `[data-island]` elements and lazy-loads the
 * corresponding island module. Uses IntersectionObserver for
 * below-the-fold islands (eager for above-the-fold).
 *
 * Usage in Tera templates:
 *   <div data-island="header" data-props='{"transparent": true}'></div>
 *
 * The island module must export a default function:
 *   export default function Header(props) { ... }
 */

import { h, render } from 'preact';

// Map of island name → lazy import function
const registry: Record<string, () => Promise<{ default: (props: any) => any }>> = {
  'header': () => import('./Header.tsx'),
  'api-console': () => import('./ApiConsole.tsx'),
  'pricing-calculator': () => import('./PricingCalculator.tsx'),
  'testimonials': () => import('./Testimonials.tsx'),
  'cookie-consent': () => import('./CookieConsent.tsx'),
  'status-overview': () => import('./StatusOverview.tsx'),
  'status-history': () => import('./StatusHistory.tsx'),
  'time-travel': () => import('./TimeTravel.tsx'),
  'render-history': () => import('./RenderHistory.tsx'),
  'debug-tools': () => import('./DebugTools.tsx'),
  'compliance-demo': () => import('./ComplianceDemo.tsx'),
  'pricing-faq': () => import('./PricingFaq.tsx'),
  'deployment-options': () => import('./DeploymentOptions.tsx'),
};

// Islands that must hydrate immediately (above the fold)
const EAGER_ISLANDS = new Set(['header', 'cookie-consent']);

async function hydrateIsland(el: HTMLElement) {
  const name = el.dataset.island;
  if (!name) return;

  const loader = registry[name];
  if (!loader) {
    console.warn(`[islands] Unknown island: "${name}"`);
    return;
  }

  try {
    const mod = await loader();
    const props = el.dataset.props ? JSON.parse(el.dataset.props) : {};
    render(h(mod.default, props), el);
  } catch (err) {
    console.error(`[islands] Failed to hydrate "${name}":`, err);
  }
}

function init() {
  const islands = document.querySelectorAll<HTMLElement>('[data-island]');

  if (!islands.length) return;

  // Separate eager vs lazy islands
  const eager: HTMLElement[] = [];
  const lazy: HTMLElement[] = [];

  islands.forEach((el) => {
    const name = el.dataset.island ?? '';
    if (EAGER_ISLANDS.has(name)) {
      eager.push(el);
    } else {
      lazy.push(el);
    }
  });

  // Hydrate eager islands immediately
  eager.forEach(hydrateIsland);

  // Hydrate lazy islands when they enter viewport
  if (lazy.length && 'IntersectionObserver' in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            observer.unobserve(entry.target);
            hydrateIsland(entry.target as HTMLElement);
          }
        });
      },
      { rootMargin: '200px' }
    );
    lazy.forEach((el) => observer.observe(el));
  } else {
    // Fallback: hydrate all
    lazy.forEach(hydrateIsland);
  }
}

// Run when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
