'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, ChevronDown, Zap, Shield, Cloud, Code, BookOpen, Users } from 'lucide-react';
import { cn } from '@/lib/utils';

const navigation = [
  {
    name: 'Product',
    items: [
      { name: 'Features', href: '/features', icon: Zap, description: 'Explore our complete feature set' },
      { name: 'Security', href: '/security', icon: Shield, description: 'Enterprise-grade protection' },
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
  { name: 'Enterprise', href: '/enterprise' },
];

export function Header() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
        isScrolled ? 'bg-surface-950/80 backdrop-blur-xl border-b border-surface-800/50' : 'bg-transparent'
      )}
    >
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 lg:h-20">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-white">ApexMail</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden lg:flex items-center gap-1">
            {navigation.map((item) => (
              'items' in item ? (
                <div
                  key={item.name}
                  className="relative"
                  onMouseEnter={() => setActiveDropdown(item.name)}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  <button className="flex items-center gap-1 px-4 py-2 text-surface-300 hover:text-white transition-colors">
                    {item.name}
                    <ChevronDown className={cn('w-4 h-4 transition-transform', activeDropdown === item.name && 'rotate-180')} />
                  </button>
                  <AnimatePresence>
                    {activeDropdown === item.name && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 10 }}
                        transition={{ duration: 0.15 }}
                        className="absolute top-full left-0 mt-2 w-72 glass-card p-2"
                      >
                        {item.items?.map((subItem) => (
                          <Link
                            key={subItem.name}
                            href={subItem.href}
                            className="flex items-start gap-3 p-3 rounded-lg hover:bg-surface-800/50 transition-colors group"
                          >
                            <div className="w-10 h-10 rounded-lg bg-surface-800 flex items-center justify-center group-hover:bg-primary-600/20 transition-colors">
                              <subItem.icon className="w-5 h-5 text-primary-400" />
                            </div>
                            <div>
                              <div className="font-medium text-white">{subItem.name}</div>
                              <div className="text-sm text-surface-400">{subItem.description}</div>
                            </div>
                          </Link>
                        ))}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <Link key={item.name} href={item.href} className="px-4 py-2 nav-link">
                  {item.name}
                </Link>
              )
            ))}
          </div>

          {/* CTA Buttons */}
          <div className="hidden lg:flex items-center gap-4">
            <Link href="https://app.apexmail.ee/login" className="text-surface-300 hover:text-white transition-colors">
              Sign In
            </Link>
            <Link href="https://app.apexmail.ee/signup" className="btn-primary">
              Get Started Free
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <button
            className="lg:hidden p-2 text-surface-300 hover:text-white"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {/* Mobile Menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="lg:hidden bg-surface-950/95 backdrop-blur-xl border-b border-surface-800"
          >
            <div className="px-4 py-6 space-y-4">
              {navigation.map((item) => (
                'items' in item ? (
                  <div key={item.name} className="space-y-2">
                    <div className="text-sm font-medium text-surface-400 uppercase tracking-wider">{item.name}</div>
                    {item.items?.map((subItem) => (
                      <Link
                        key={subItem.name}
                        href={subItem.href}
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-surface-800/50"
                        onClick={() => setMobileMenuOpen(false)}
                      >
                        <subItem.icon className="w-5 h-5 text-primary-400" />
                        <span className="text-white">{subItem.name}</span>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <Link
                    key={item.name}
                    href={item.href}
                    className="block p-3 text-white hover:bg-surface-800/50 rounded-lg"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    {item.name}
                  </Link>
                )
              ))}
              <div className="pt-4 border-t border-surface-800 space-y-3">
                <Link href="https://app.apexmail.ee/login" className="block w-full btn-secondary text-center">
                  Sign In
                </Link>
                <Link href="https://app.apexmail.ee/signup" className="block w-full btn-primary text-center">
                  Get Started Free
                </Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
