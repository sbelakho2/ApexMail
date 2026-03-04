/**
 * Header Island — mobile menu toggle, scroll-aware background, dropdown navigation
 * Ported from apps/marketing/src/components/layout/Header.tsx
 */
import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';

const navigation = [
  {
    name: 'Product',
    items: [
      { name: 'Features', href: '/features', description: 'Explore our complete feature set' },
      { name: 'Security', href: '/compliance', description: 'Enterprise-grade protection' },
      { name: 'Private Cloud', href: '/private-cloud', description: 'Single-tenant deployments' },
    ],
  },
  {
    name: 'Developers',
    items: [
      { name: 'Documentation', href: 'https://docs.apexmail.ee', description: 'API reference & guides' },
      { name: 'API Console', href: '/api-console', description: 'Try our API instantly' },
    ],
  },
  { name: 'Pricing', href: '/pricing' },
  { name: 'Compliance', href: '/compliance' },
  { name: 'Enterprise', href: '/private-cloud' },
];

export default function Header() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  useEffect(() => {
    let ticking = false;
    const handleScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        setIsScrolled(window.scrollY > 20);
        ticking = false;
      });
    };
    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header class={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${isScrolled ? 'bg-white/80 backdrop-blur-xl border-b border-surface-200/50 shadow-sm' : 'bg-transparent border-b border-transparent'}`}>
      <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16 lg:h-20">
          <a href="/" class="flex items-center gap-2 group">
            <div class="w-8 h-8 rounded-lg bg-primary-600 flex items-center justify-center transition-transform group-hover:scale-105 shadow-sm">
              <svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
            </div>
            <span class="text-xl font-bold text-surface-900 tracking-tight">ApexMail</span>
          </a>

          <div class="hidden lg:flex items-center gap-2">
            {navigation.map((item) =>
              'items' in item ? (
                <div
                  key={item.name}
                  class="relative"
                  onMouseEnter={() => setActiveDropdown(item.name)}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  <button
                    class="flex items-center gap-1.5 px-3 py-2.5 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-lg hover:bg-surface-50"
                    aria-haspopup="menu"
                    aria-expanded={activeDropdown === item.name}
                    onClick={() => setActiveDropdown(activeDropdown === item.name ? null : item.name)}
                  >
                    {item.name}
                    <svg class={`w-4 h-4 transition-transform duration-150 ${activeDropdown === item.name ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M19 9l-7 7-7-7" /></svg>
                  </button>
                  {activeDropdown === item.name && (
                    <div class="animate-in absolute top-full left-0 mt-2 w-80 p-2 bg-white rounded-xl border border-surface-200 shadow-xl shadow-surface-900/5">
                      {item.items!.map((subItem) => (
                        <a key={subItem.name} href={subItem.href} class="flex items-start gap-3 p-3 rounded-lg hover:bg-surface-50 transition-colors group">
                          <div><div class="font-semibold text-surface-900 text-sm mb-0.5">{subItem.name}</div><div class="text-xs text-surface-500 leading-snug">{subItem.description}</div></div>
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <a key={item.name} href={(item as any).href} class="px-3 py-2.5 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-lg hover:bg-surface-50">{item.name}</a>
              )
            )}
          </div>

          <div class="hidden lg:flex items-center gap-3">
            <a href="https://app.apexmail.ee/login" class="text-sm font-semibold text-surface-600 hover:text-surface-900 transition-colors px-3 py-2.5 hover:bg-surface-50 rounded-lg">Sign In</a>
            <a href="https://app.apexmail.ee/signup" class="btn-primary text-sm">Get Started Free</a>
          </div>

          <button
            class="lg:hidden p-2 text-surface-600 hover:text-surface-900 rounded-lg hover:bg-surface-50 transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen
              ? <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M6 18L18 6M6 6l12 12" /></svg>
              : <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h16" /></svg>
            }
          </button>
        </div>
      </nav>

      {mobileMenuOpen && (
        <div class="animate-in lg:hidden bg-white border-b border-surface-200 overflow-hidden">
          <div class="px-4 py-6 space-y-6">
            {navigation.map((item) =>
              'items' in item ? (
                <div key={item.name} class="space-y-3">
                  <div class="text-xs font-bold text-surface-900 px-3">{item.name}</div>
                  <div class="space-y-1">
                    {item.items!.map((subItem) => (
                      <a key={subItem.name} href={subItem.href} class="flex items-center gap-3 p-3.5 rounded-lg hover:bg-surface-50 transition-colors" onClick={() => setMobileMenuOpen(false)}>
                        <span class="text-surface-900 font-medium text-sm">{subItem.name}</span>
                      </a>
                    ))}
                  </div>
                </div>
              ) : (
                <a key={item.name} href={(item as any).href} class="block px-3 py-3 text-surface-900 font-medium hover:bg-surface-50 rounded-lg text-sm" onClick={() => setMobileMenuOpen(false)}>{item.name}</a>
              )
            )}
            <div class="pt-6 border-t border-surface-200 space-y-3 px-3">
              <a href="https://app.apexmail.ee/login" class="block w-full text-center py-2.5 text-surface-900 font-semibold border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors text-sm">Sign In</a>
              <a href="https://app.apexmail.ee/signup" class="block w-full btn-primary text-center py-2.5 text-sm">Get Started Free</a>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
