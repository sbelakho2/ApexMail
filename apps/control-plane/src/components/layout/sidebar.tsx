'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '../../lib/utils';

interface NavItem {
    href: string;
    label: string;
    icon: string;
}

interface NavSection {
    title: string;
    items: NavItem[];
}

const navSections: NavSection[] = [
    {
        title: 'Sales Automation',
        items: [
            { href: '/crm', label: 'CRM Pipeline', icon: '📊' },
            { href: '/leads', label: 'Lead Discovery', icon: '🎯' },
            { href: '/campaigns', label: 'Drip Campaigns', icon: '📧' },
            { href: '/inbox', label: 'Inbox Sentinel', icon: '📥' },
            { href: '/calendar', label: 'Demo Scheduling', icon: '📅' },
        ],
    },
    {
        title: 'Platform Governance',
        items: [
            { href: '/compliance', label: 'Compliance Admin', icon: '🛡️' },
            { href: '/risk', label: 'Risk Monitoring', icon: '⚠️' },
            { href: '/audit', label: 'Audit Logs', icon: '📜' },
            { href: '/gdpr', label: 'GDPR Requests', icon: '🇪🇺' },
            { href: '/secrets', label: 'Secrets Vault', icon: '🔐' },
        ],
    },
    {
        title: 'Business Operations',
        items: [
            { href: '/tenants', label: 'Tenant Overview', icon: '🏢' },
            { href: '/revenue', label: 'Revenue Metrics', icon: '💰' },
            { href: '/promos', label: 'Ad Injection', icon: '📢' },
            { href: '/settings', label: 'Platform Settings', icon: '⚙️' },
        ],
    },
];

export function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="w-64 border-r border-surface-200 bg-surface-50/80 backdrop-blur-xl min-h-screen fixed left-0 top-0 overflow-y-auto">
            <div className="p-6">
                {/* Logo */}
                <Link href="/" className="flex items-center gap-2 mb-8">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-white font-bold">
                        A
                    </div>
                    <span className="text-lg font-bold">Control Plane</span>
                </Link>

                {/* Navigation */}
                <nav className="space-y-6">
                    {navSections.map((section) => (
                        <div key={section.title}>
                            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-3">
                                {section.title}
                            </h3>
                            <ul className="space-y-1">
                                {section.items.map((item) => (
                                    <li key={item.href}>
                                        <Link
                                            href={item.href}
                                            className={cn(
                                                'flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors',
                                                pathname === item.href
                                                    ? 'bg-indigo-100 text-indigo-900 font-medium'
                                                    : 'hover:bg-gray-100 text-gray-700'
                                            )}
                                        >
                                            <span>{item.icon}</span>
                                            {item.label}
                                        </Link>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </nav>

                {/* Security Notice */}
                <div className="mt-8 p-4 bg-indigo-50 rounded-lg border border-indigo-100">
                    <div className="flex items-center gap-2 text-sm text-indigo-800 font-medium mb-1">
                        🔒 Secure Environment
                    </div>
                    <div className="text-xs text-indigo-600">
                        Control Plane is isolated from customer console.
                        IP-restricted access only.
                    </div>
                </div>
            </div>
        </aside>
    );
}
