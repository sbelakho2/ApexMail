'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, ChevronDown, Zap, Shield, Cloud, Code, BookOpen } from 'lucide-react';
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
        isScrolled 
          ? 'bg-white/80 backdrop-blur-xl border-b border-surface-200/50 shadow-sm' 
          : 'bg-transparent border-b border-transparent'
      )}
    >
      <nav className="max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 lg:h-20">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-md bg-primary-600 flex items-center justify-center transition-transform group-hover:scale-105">
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
                >
                  <button className="flex items-center gap-1 px-4 py-2 text-[14px] font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-md hover:bg-surface-100/50">
                    {item.name}
                    <ChevronDown className={cn('w-3.5 h-3.5 transition-transform duration-200', activeDropdown === item.name && 'rotate-180')} />
                  </button>
                  <AnimatePresence>
                    {activeDropdown === item.name && (
                      <motion.div
                        initial={{ opacity: 0, y: 8, scale: 0.98 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 8, scale: 0.98 }}
                        transition={{ duration: 0.2, ease: "easeOut" }}
                        className="absolute top-full left-0 mt-2 w-80 premium-card p-2 bg-white/95 backdrop-blur-sm shadow-xl border-surface-200/60"
                      >
                        {item.items?.map((subItem) => (
                          <Link
                            key={subItem.name}
                            href={subItem.href}
                            className="flex items-start gap-3 p-3 rounded-lg hover:bg-surface-50 transition-all group"
                          >
                            <div className="w-10 h-10 rounded-md bg-surface-100 flex items-center justify-center group-hover:bg-primary-50 group-hover:text-primary-600 transition-colors">
                              <subItem.icon className="w-5 h-5 text-surface-500 group-hover:text-primary-600 transition-colors" />
                            </div>
                            <div>
                              <div className="font-bold text-surface-900 text-sm">{subItem.name}</div>
                              <div className="text-xs text-surface-500 mt-0.5">{subItem.description}</div>
                            </div>
                          </Link>
                        ))}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <Link key={item.name} href={item.href} className="px-4 py-2 text-[14px] font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-md hover:bg-surface-100/50">
                  {item.name}
                </Link>
              )
            ))}
          </div>

 {/* CTA Buttons */}
 <div className="hidden lg:flex items-center gap-4">
 <Link href="https://app.apexmail.ee/login" className="text-surface-600 hover:text-surface-900 font-medium transition-colors">
 Sign In
 </Link>
 <Link href="https://app.apexmail.ee/signup" className="btn-primary">
 Get Started Free
 </Link>
 </div>

 {/* Mobile Menu Button */}
 <button
 className="lg:hidden p-2 text-surface-600 hover:text-surface-900"
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
 className="lg:hidden bg-white border-b border-surface-200"
 >
 <div className="px-4 py-6 space-y-4">
 {navigation.map((item) => (
 'items' in item ? (
 <div key={item.name} className="space-y-2">
 <div className="text-xs font-bold text-surface-600 uppercase tracking-widest">{item.name}</div>
 {item.items?.map((subItem) => (
 <Link
 key={subItem.name}
 href={subItem.href}
 className="flex items-center gap-3 p-3 rounded-md hover:bg-surface-50"
 onClick={() => setMobileMenuOpen(false)}
 >
 <subItem.icon className="w-5 h-5 text-primary-600" />
 <span className="text-surface-900 font-medium">{subItem.name}</span>
 </Link>
 ))}
 </div>
 ) : (
 <Link
 key={item.name}
 href={item.href}
 className="block p-3 text-surface-900 font-medium hover:bg-surface-50 rounded-md"
 onClick={() => setMobileMenuOpen(false)}
 >
 {item.name}
 </Link>
 )
 ))}
 <div className="pt-4 border-t border-surface-200 space-y-3">
 <Link href="https://app.apexmail.ee/login" className="block w-full text-center py-3 text-surface-900 font-medium border border-surface-200 rounded-md">
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
