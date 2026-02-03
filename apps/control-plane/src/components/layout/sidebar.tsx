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
        title: 'Customer Success',
        items: [
            { href: '/support', label: 'Support Tickets', icon: '🎫' },
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
        title: 'Infrastructure',
        items: [
            { href: '/system', label: 'System Health', icon: '💓' },
            { href: '/ip-warmer', label: 'IP Warmer', icon: '🔥' },
            { href: '/features', label: 'Feature Flags', icon: '🚩' },
        ],
    },
    {
        title: 'Business Operations',
        items: [
            { href: '/tenants', label: 'Tenant Overview', icon: '🏢' },
            { href: '/revenue', label: 'Revenue Metrics', icon: '💰' },
            { href: '/analytics', label: 'Analytics & Insights', icon: '📈' },
            { href: '/content', label: 'Content & CMS', icon: '✍️' },
            { href: '/settings', label: 'Platform Settings', icon: '⚙️' },
        ],
    },
];

interface SidebarProps {
    onNavigate?: () => void;
    className?: string;
}

export function Sidebar({ onNavigate, className }: SidebarProps) {
    const pathname = usePathname();

    const handleLinkClick = () => {
        if (onNavigate) {
            onNavigate();
        }
    };

    return (
        <aside className={cn("w-64 border-r border-surface-200 bg-surface-0 min-h-screen overflow-y-auto print:hidden", className)}>
            {/* Control Plane Header */}
            <div className="bg-gradient-to-r from-amber-500 to-orange-500 text-white text-xs font-medium py-1.5 px-4 text-center">
                🔐 Control Plane
            </div>
            
            <div className="p-4 md:p-6">
                {/* Logo */}
                <Link href="/" className="flex items-center gap-3 mb-6 md:mb-8" onClick={handleLinkClick}>
                    <div className="flex h-9 w-9 md:h-10 md:w-10 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold text-base md:text-lg shadow-md">
                        A
                    </div>
                    <div>
                        <span className="text-base md:text-lg font-bold text-surface-900">ApexMail</span>
                        <div className="text-xs text-surface-500">Platform Admin</div>
                    </div>
                </Link>

                {/* Navigation */}
                <nav className="space-y-4 md:space-y-6">
                    {navSections.map((section) => (
                        <div key={section.title}>
                            <h3 className="text-xs font-semibold uppercase tracking-wider text-surface-600 mb-2 md:mb-3 px-3">
                                {section.title}
                            </h3>
                            <ul className="space-y-1">
                                {section.items.map((item) => (
                                    <li key={item.href}>
                                        <Link
                                            href={item.href}
                                            onClick={handleLinkClick}
                                            className={cn(
                                                'flex items-center gap-3 px-3 py-2 md:py-2.5 rounded-lg text-sm transition-all',
                                                pathname === item.href
                                                    ? 'bg-blue-50 text-blue-700 font-medium border border-blue-100'
                                                    : 'hover:bg-surface-50 text-surface-600 hover:text-surface-900'
                                            )}
                                        >
                                            <span className="text-base">{item.icon}</span>
                                            {item.label}
                                        </Link>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </nav>

                {/* Security Notice - Hidden on mobile for space */}
                <div className="hidden md:block mt-8 p-4 bg-surface-50 rounded-xl border border-surface-200">
                    <div className="flex items-center gap-2 text-sm text-surface-700 font-medium mb-1">
                        🔒 Secure Environment
                    </div>
                    <div className="text-xs text-surface-500">
                        Control Plane is isolated from customer console.
                        IP-restricted access only.
                    </div>
                </div>

                {/* Version */}
                <div className="mt-6 text-center">
                    <span className="text-xs text-surface-400">v1.0.0</span>
                </div>
            </div>
        </aside>
    );
}
