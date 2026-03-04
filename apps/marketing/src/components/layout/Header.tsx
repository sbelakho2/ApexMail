'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';
import { Menu, X, ChevronDown, Zap, Shield, Cloud, Code, BookOpen } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

const navigation = [
  {
    name: 'Product',
    items: [
      { name: 'Features', href: '/features', icon: Zap, description: 'Explore our complete feature set' },
      { name: 'Security', href: '/compliance', icon: Shield, description: 'Enterprise-grade protection' },
      { name: 'Private Cloud', href: '/private-cloud', icon: Cloud, description: 'Single-tenant deployments' },
    ],
  },
  {
    name: 'Developers',
    items: [
      { name: 'Documentation', href: 'https://docs.apexmail.ee', icon: BookOpen, description: 'API reference & guides' },
      { name: 'API Console', href: '#api-console', icon: Code, description: 'Try our API instantly' },
    ],
  },
  { name: 'Pricing', href: '/pricing' },
  { name: 'Compliance', href: '/compliance' },
  { name: 'Enterprise', href: '/private-cloud' },
];

export function Header() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  useEffect(() => {
    let ticking = false;

    const handleScroll = () => {
      if (ticking) return;

      ticking = true;
      window.requestAnimationFrame(() => {
        setIsScrolled(window.scrollY > 20);
        ticking = false;
      });
    };

    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
        isScrolled 
          ? 'bg-white/80 backdrop-blur-xl border-b border-surface-200/50 shadow-sm' 
          : 'bg-transparent border-b border-transparent'
      )}
    >
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 lg:h-20">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-lg bg-primary-600 flex items-center justify-center transition-transform group-hover:scale-105 shadow-sm">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-surface-900 tracking-tight">ApexMail</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden lg:flex items-center gap-2">
            {navigation.map((item) => (
              'items' in item ? (
                <div
                  key={item.name}
                  className="relative"
                  onMouseEnter={() => setActiveDropdown(item.name)}
                  onMouseLeave={() => setActiveDropdown(null)}
                  onFocus={() => setActiveDropdown(item.name)}
                  onBlur={(event) => {
                    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
                      setActiveDropdown(null);
                    }
                  }}
                >
                  <button
                    className="flex items-center gap-1.5 px-3 py-2.5 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-lg hover:bg-surface-50"
                    aria-haspopup="menu"
                    aria-expanded={activeDropdown === item.name}
                    onClick={() => setActiveDropdown(activeDropdown === item.name ? null : item.name)}
                    onKeyDown={(event) => {
                      if (event.key === 'Escape') {
                        setActiveDropdown(null);
                      }
                    }}
                  >
                    {item.name}
                    <ChevronDown className={cn('w-4 h-4 transition-transform duration-150', activeDropdown === item.name && 'rotate-180')} />
                  </button>
                  {activeDropdown === item.name && (
                      <div className="animate-in absolute top-full left-0 mt-2 w-80 p-2 bg-white rounded-xl border border-surface-200 shadow-xl shadow-surface-900/5">
                        {item.items?.map((subItem) => (
                          <Link
                            key={subItem.name}
                            href={subItem.href}
                            className="flex items-start gap-3 p-3 rounded-lg hover:bg-surface-50 transition-colors group"
                          >
                            <div className="w-9 h-9 rounded-lg bg-surface-50 flex items-center justify-center text-surface-500 group-hover:text-primary-600 transition-colors">
                              <subItem.icon className="w-5 h-5" />
                            </div>
                            <div>
                              <div className="font-semibold text-surface-900 text-sm mb-0.5">{subItem.name}</div>
                              <div className="text-xs text-surface-500 leading-snug">{subItem.description}</div>
                            </div>
                          </Link>
                        ))}
                      </div>
                    )}
                  
                </div>
              ) : (
                <Link key={item.name} href={item.href} className="px-3 py-2.5 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-lg hover:bg-surface-50">
                  {item.name}
                </Link>
              )
            ))}
          </div>

          {/* CTA Buttons */}
          <div className="hidden lg:flex items-center gap-3">
            <Link href="https://app.apexmail.ee/login" className="text-sm font-semibold text-surface-600 hover:text-surface-900 transition-colors px-3 py-2.5 hover:bg-surface-50 rounded-lg">
              Sign In
            </Link>
            <Link href="https://app.apexmail.ee/signup" className="btn-primary text-sm">
              Get Started Free
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <button
            className="lg:hidden p-2 text-surface-600 hover:text-surface-900 rounded-lg hover:bg-surface-50 transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
          <div className="animate-in lg:hidden bg-white border-b border-surface-200 overflow-hidden">
            <div className="px-4 py-6 space-y-6">
              {navigation.map((item) => (
                'items' in item ? (
                  <div key={item.name} className="space-y-3">
                    <div className="text-xs font-bold text-surface-900 px-3">{item.name}</div>
                    <div className="space-y-1">
                      {item.items?.map((subItem) => (
                        <Link
                          key={subItem.name}
                          href={subItem.href}
                          className="flex items-center gap-3 p-3.5 rounded-lg hover:bg-surface-50 transition-colors"
                          onClick={() => setMobileMenuOpen(false)}
                        >
                          <subItem.icon className="w-5 h-5 text-surface-500" />
                          <span className="text-surface-900 font-medium text-sm">{subItem.name}</span>
                        </Link>
                      ))}
                    </div>
                  </div>
                ) : (
                  <Link
                    key={item.name}
                    href={item.href}
                    className="block px-3 py-3 text-surface-900 font-medium hover:bg-surface-50 rounded-lg text-sm"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    {item.name}
                  </Link>
                )
              ))}
              <div className="pt-6 border-t border-surface-200 space-y-3 px-3">
                <Link href="https://app.apexmail.ee/login" className="block w-full text-center py-2.5 text-surface-900 font-semibold border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors text-sm">
                  Sign In
                </Link>
                <Link href="https://app.apexmail.ee/signup" className="block w-full btn-primary text-center py-2.5 text-sm">
                  Get Started Free
                </Link>
              </div>
            </div>
          </div>
        )}
      
    </header>
  );
}
