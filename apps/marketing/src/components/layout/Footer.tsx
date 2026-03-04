import Link from 'next/link';
import { Zap, Github, Twitter, Linkedin, Mail } from '@/components/ui/icons';

const footerLinks = {
  product: [
    { name: 'Features', href: '/features' },
    { name: 'Pricing', href: '/pricing' },
    { name: 'Security', href: '/compliance' },
    { name: 'Enterprise', href: '/private-cloud' },
    { name: 'Private Cloud', href: '/private-cloud' },
    { name: 'Compliance', href: '/compliance' },
  ],
  developers: [
    { name: 'Documentation', href: 'https://docs.apexmail.ee' },
    { name: 'API Reference', href: 'https://docs.apexmail.ee/api' },
    { name: 'SDKs', href: 'https://docs.apexmail.ee/sdks' },
    { name: 'Webhooks', href: 'https://docs.apexmail.ee/webhooks' },
    { name: 'API Console', href: '/api-console' },
    { name: 'Status', href: '/status' },
  ],
  resources: [
    { name: 'API Console', href: '/api-console' },
    { name: 'Case Studies', href: '/case-studies' },
    { name: 'Compare Providers', href: '/compare' },
    { name: 'Forensic Tools', href: '/forensic' },
    { name: 'Status', href: '/status' },
    { name: 'Compliance', href: '/compliance' },
  ],
  company: [
    { name: 'Private Cloud', href: '/private-cloud' },
    { name: 'Case Studies', href: '/case-studies' },
    { name: 'Compare', href: '/compare' },
    { name: 'Status', href: '/status' },
    { name: 'Features', href: '/features' },
  ],
  legal: [
    { name: 'Privacy Policy', href: '/privacy' },
    { name: 'Terms of Service', href: '/terms' },
    { name: 'Cookie Policy', href: '/cookies' },
    { name: 'DPA', href: '/dpa' },
    { name: 'SLA', href: '/sla' },
    { name: 'Acceptable Use', href: '/acceptable-use' },
  ],
};

const socialLinks = [
  { name: 'GitHub', href: 'https://github.com/Bel-Consulting-OU/ApexMail', icon: Github },
  { name: 'Twitter', href: 'https://twitter.com/apexmail', icon: Twitter },
  { name: 'LinkedIn', href: 'https://linkedin.com/company/apexmail', icon: Linkedin },
  { name: 'Email', href: 'mailto:hello@apexmail.ee', icon: Mail },
];

export function Footer() {
  return (
    <footer className="border-t border-surface-200 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-16">
        {/* Top Section */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-8 lg:gap-12">
          {/* Brand Column */}
          <div className="col-span-2 md:col-span-3 lg:col-span-1">
            <Link href="/" className="flex items-center gap-2 mb-6">
              <div className="w-8 h-8 rounded bg-primary-600 flex items-center justify-center">
                <Zap className="w-4 h-4 text-white" fill="currentColor" />
              </div>
              <span className="text-lg font-bold text-surface-900 tracking-tight">ApexMail</span>
            </Link>
            <p className="text-surface-500 text-sm mb-6 max-w-xs leading-relaxed">
              Enterprise email infrastructure that keeps you compliant and your emails delivered.
            </p>
            <div className="flex items-center gap-3">
              {socialLinks.map((link) => (
                <a
                  key={link.name}
                  href={link.href}
                  target={link.href.startsWith('mailto:') ? undefined : '_blank'}
                  rel={link.href.startsWith('mailto:') ? undefined : 'noopener noreferrer'}
                  className="w-11 h-11 rounded-lg bg-surface-50 border border-surface-200 flex items-center justify-center text-surface-500 hover:text-surface-900 hover:border-surface-300 transition-colors"
                  aria-label={link.name}
                >
                  <link.icon className="w-4 h-4" />
                </a>
              ))}
            </div>
          </div>

          {/* Product */}
          <div>
            <h3 className="text-xs font-bold text-surface-900 mb-4 uppercase tracking-widest">Product</h3>
            <ul className="space-y-1">
              {footerLinks.product.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm font-medium text-surface-600 hover:text-primary-600 transition-colors py-2.5 inline-block">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Developers */}
          <div>
            <h3 className="text-xs font-bold text-surface-900 mb-4 uppercase tracking-widest">Developers</h3>
            <ul className="space-y-1">
              {footerLinks.developers.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm font-medium text-surface-600 hover:text-primary-600 transition-colors py-2.5 inline-block">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="text-xs font-bold text-surface-900 mb-4 uppercase tracking-widest">Resources</h3>
            <ul className="space-y-1">
              {footerLinks.resources.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm font-medium text-surface-600 hover:text-primary-600 transition-colors py-2.5 inline-block">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Company */}
          <div>
            <h3 className="text-xs font-bold text-surface-900 mb-4 uppercase tracking-widest">Company</h3>
            <ul className="space-y-1">
              {footerLinks.company.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm font-medium text-surface-600 hover:text-primary-600 transition-colors py-2.5 inline-block">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal */}
          <div>
            <h3 className="text-xs font-bold text-surface-900 mb-4 uppercase tracking-widest">Legal</h3>
            <ul className="space-y-1">
              {footerLinks.legal.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm font-medium text-surface-600 hover:text-primary-600 transition-colors py-2.5 inline-block">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="mt-12 pt-8 border-t border-surface-200">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="text-sm text-surface-500 font-medium">
              <p>© 2026 Bel Consulting OÜ. All rights reserved.</p>
              <p className="mt-1">ApexMail is a brand of Bel Consulting OÜ.</p>
            </div>
            <div className="text-sm text-surface-500 font-medium text-right">
              <p>Bel Consulting OÜ · Sakala 7-2 · 10141 Tallinn · Estonia</p>
              <p>Reg. 16192499 · VAT EE102951727</p>
            </div>
          </div>
          <div className="mt-4 flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="flex items-center gap-6 text-sm text-surface-500 font-medium">
              <span>Made with ❤️ in Estonia 🇪🇪</span>
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]"></span>
                All systems operational
              </span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
