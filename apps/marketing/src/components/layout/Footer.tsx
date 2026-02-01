import Link from 'next/link';
import { Zap, Github, Twitter, Linkedin, Mail } from 'lucide-react';

const footerLinks = {
  product: [
    { name: 'Features', href: '/features' },
    { name: 'Pricing', href: '/pricing' },
    { name: 'Security', href: '/security' },
    { name: 'Enterprise', href: '/enterprise' },
    { name: 'Private Cloud', href: '/private-cloud' },
    { name: 'Compliance', href: '/compliance' },
  ],
  developers: [
    { name: 'Documentation', href: 'https://docs.apexmail.ee' },
    { name: 'API Reference', href: 'https://docs.apexmail.ee/api' },
    { name: 'SDKs', href: 'https://docs.apexmail.ee/sdks' },
    { name: 'Webhooks', href: 'https://docs.apexmail.ee/webhooks' },
    { name: 'Changelog', href: '/changelog' },
    { name: 'Status', href: 'https://status.apexmail.ee' },
  ],
  resources: [
    { name: 'Blog', href: '/blog' },
    { name: 'Case Studies', href: '/case-studies' },
    { name: 'Guides', href: '/guides' },
    { name: 'Email Best Practices', href: '/guides/best-practices' },
    { name: 'Deliverability', href: '/guides/deliverability' },
    { name: 'GDPR Guide', href: '/guides/gdpr' },
  ],
  company: [
    { name: 'About', href: '/about' },
    { name: 'Careers', href: '/careers' },
    { name: 'Contact', href: '/contact' },
    { name: 'Partners', href: '/partners' },
    { name: 'Press Kit', href: '/press' },
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
  { name: 'GitHub', href: 'https://github.com/apexmail', icon: Github },
  { name: 'Twitter', href: 'https://twitter.com/apexmail', icon: Twitter },
  { name: 'LinkedIn', href: 'https://linkedin.com/company/apexmail', icon: Linkedin },
  { name: 'Email', href: 'mailto:hello@apexmail.ee', icon: Mail },
];

export function Footer() {
  return (
    <footer className="border-t border-surface-800 bg-surface-950/50 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-16">
        {/* Top Section */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-8 lg:gap-12">
          {/* Brand Column */}
          <div className="col-span-2 md:col-span-3 lg:col-span-1">
            <Link href="/" className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center">
                <Zap className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold text-white">ApexMail</span>
            </Link>
            <p className="text-surface-400 text-sm mb-4 max-w-xs">
              Enterprise email infrastructure that keeps you compliant and your emails delivered.
            </p>
            <div className="flex items-center gap-3">
              {socialLinks.map((link) => (
                <a
                  key={link.name}
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-9 h-9 rounded-lg bg-surface-800 flex items-center justify-center text-surface-400 hover:text-white hover:bg-surface-700 transition-colors"
                  aria-label={link.name}
                >
                  <link.icon className="w-4 h-4" />
                </a>
              ))}
            </div>
          </div>

          {/* Product */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Product</h3>
            <ul className="space-y-3">
              {footerLinks.product.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm text-surface-400 hover:text-white transition-colors">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Developers */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Developers</h3>
            <ul className="space-y-3">
              {footerLinks.developers.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm text-surface-400 hover:text-white transition-colors">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Resources</h3>
            <ul className="space-y-3">
              {footerLinks.resources.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm text-surface-400 hover:text-white transition-colors">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Company */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Company</h3>
            <ul className="space-y-3">
              {footerLinks.company.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm text-surface-400 hover:text-white transition-colors">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Legal</h3>
            <ul className="space-y-3">
              {footerLinks.legal.map((link) => (
                <li key={link.name}>
                  <Link href={link.href} className="text-sm text-surface-400 hover:text-white transition-colors">
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="mt-12 pt-8 border-t border-surface-800">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="text-sm text-surface-400">
              © {new Date().getFullYear()} Bel Consulting OÜ. All rights reserved.
            </div>
            <div className="flex items-center gap-6 text-sm text-surface-400">
              <span>Made with ❤️ in Estonia 🇪🇪</span>
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-accent-500 animate-pulse"></span>
                All systems operational
              </span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
