'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useRouter } from 'next/navigation';
import { 
    Target, 
    Mail, 
    Bot, 
    Inbox, 
    Calendar, 
    Ticket, 
    ShieldCheck, 
    AlertTriangle, 
    History, 
    Euro, 
    Key, 
    Activity, 
    Flame, 
    Flag, 
    Building2, 
    BarChart3, 
    FileText, 
    Settings,
    Lock,
    LogOut,
    Zap
} from '../ui/icons';
import { cn } from '../../lib/utils';

interface NavItem {
    href: string;
    label: string;
    icon: React.ReactNode;
    minRole?: 'viewer' | 'operator' | 'admin' | 'owner';
}

interface NavSection {
    title: string;
    items: NavItem[];
}

const navSections: NavSection[] = [
    {
        title: 'Sales Automation',
        items: [
            { href: '/sales', label: 'Sales System', icon: <Zap className="w-4 h-4" /> },
            { href: '/crm', label: 'CRM Pipeline', icon: <BarChart3 className="w-4 h-4" /> },
            { href: '/leads', label: 'Lead Discovery', icon: <Target className="w-4 h-4" /> },
            { href: '/campaigns', label: 'Drip Campaigns', icon: <Mail className="w-4 h-4" /> },
            { href: '/autopilot', label: 'Autopilot Console', icon: <Bot className="w-4 h-4" /> },
            { href: '/inbox', label: 'Inbox Sentinel', icon: <Inbox className="w-4 h-4" /> },
            { href: '/calendar', label: 'Demo Scheduling', icon: <Calendar className="w-4 h-4" /> },
        ],
    },
    {
        title: 'Customer Success',
        items: [
            { href: '/support', label: 'Support Tickets', icon: <Ticket className="w-4 h-4" /> },
        ],
    },
    {
        title: 'Platform Governance',
        items: [
            { href: '/compliance', label: 'Compliance Admin', icon: <ShieldCheck className="w-4 h-4" />, minRole: 'admin' },
            { href: '/risk', label: 'Risk Monitoring', icon: <AlertTriangle className="w-4 h-4" /> },
            { href: '/audit', label: 'Audit Logs', icon: <History className="w-4 h-4" /> },
            { href: '/gdpr', label: 'GDPR Requests', icon: <Euro className="w-4 h-4" />, minRole: 'admin' },
            { href: '/secrets', label: 'Secrets Vault', icon: <Key className="w-4 h-4" />, minRole: 'admin' },
        ],
    },
    {
        title: 'Infrastructure',
        items: [
            { href: '/system', label: 'System Health', icon: <Activity className="w-4 h-4" /> },
            { href: '/ip-warmer', label: 'IP Warmer', icon: <Flame className="w-4 h-4" /> },
            { href: '/features', label: 'Feature Flags', icon: <Flag className="w-4 h-4" />, minRole: 'admin' },
        ],
    },
    {
        title: 'Business Operations',
        items: [
            { href: '/tenants', label: 'Tenant Overview', icon: <Building2 className="w-4 h-4" /> },
            { href: '/revenue', label: 'Revenue Metrics', icon: <Euro className="w-4 h-4" /> },
            { href: '/analytics', label: 'Analytics & Insights', icon: <BarChart3 className="w-4 h-4" /> },
            { href: '/content', label: 'Content & CMS', icon: <FileText className="w-4 h-4" /> },
            { href: '/settings', label: 'Platform Settings', icon: <Settings className="w-4 h-4" />, minRole: 'admin' },
        ],
    },
];

interface SidebarProps {
    onNavigate?: () => void;
    className?: string;
    userRole?: 'viewer' | 'operator' | 'admin' | 'owner';
}

const ROLE_RANK: Record<string, number> = { viewer: 0, operator: 1, admin: 2, owner: 3 };

export function Sidebar({ onNavigate, className, userRole = 'viewer' }: SidebarProps) {
    const pathname = usePathname();
    const router = useRouter();

    const handleLinkClick = () => {
        if (onNavigate) {
            onNavigate();
        }
    };

    const handleLogout = async () => {
        try {
            const { getCsrfToken } = await import('../../lib/client-csrf');
            const csrfToken = await getCsrfToken();
            await fetch('/api/auth/logout', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
            });
        } catch {
            // proceed to login even if the request fails
        }
        router.push('/login');
    };

    return (
        <aside className={cn("w-64 border-r border-border bg-card min-h-screen overflow-y-auto print:hidden", className)}>
            {/* Sidebar header — echoes the top bar accent inside the nav */}
            <div className="bg-control-plane text-control-plane-foreground text-[13px] font-medium py-1.5 px-4 text-center flex items-center justify-center gap-2">
                <Lock className="w-3 h-3" />
                Control Plane
            </div>

            <div className="p-4 md:p-6">
                {/* Logo */}
                <Link href="/" className="flex items-center gap-3 mb-6 md:mb-8" onClick={handleLinkClick}>
                    <div className="flex h-9 w-9 md:h-10 md:w-10 items-center justify-center rounded-md bg-primary text-primary-foreground font-bold text-base md:text-lg shadow-md">
                        A
                    </div>
                    <div>
                        <span className="text-base md:text-lg font-bold text-foreground">ApexMail</span>
                        <div className="text-[14px] text-muted-foreground">Platform Admin</div>
                    </div>
                </Link>

                {/* Navigation */}
                <nav className="space-y-4 md:space-y-6">
                    {navSections.map((section) => (
                        <div key={section.title}>
                            <h3 className="text-[14px] font-semibold uppercase tracking-wider text-surface-600 mb-2 md:mb-3 px-3">
                                {section.title}
                            </h3>
                            <ul className="space-y-1">
                                {section.items
                                    .filter((item) => !item.minRole || (ROLE_RANK[userRole] ?? 0) >= (ROLE_RANK[item.minRole] ?? 0))
                                    .map((item) => (
                                    <li key={item.href}>
                                        <Link
                                            href={item.href}
                                            onClick={handleLinkClick}
                                            className={cn(
                                                'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all',
                                                pathname === item.href
                                                    ? 'bg-brand-50 text-brand-700 font-medium border border-brand-100 shadow-[inset_0_0_0_1px_rgba(37,99,235,0.05)]'
                                                    : 'hover:bg-surface-50 text-surface-600 hover:text-surface-900'
                                            )}
                                            aria-current={pathname === item.href ? 'page' : undefined}
                                        >
                                            <span className={cn(
                                                "transition-colors",
                                                pathname === item.href ? "text-brand-600" : "text-surface-400 group-hover:text-surface-600"
                                            )}>
                                                {item.icon}
                                            </span>
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
                        <Lock className="w-4 h-4 text-surface-500" />
                        Secure Environment
                    </div>
                    <div className="text-[14px] text-surface-500">
                        Control Plane is isolated from customer console.
                        IP-restricted access only.
                    </div>
                </div>

                {/* Version */}
                <div className="mt-6 text-center">
                    <span className="text-[14px] text-surface-400">v1.0.0</span>
                </div>

                {/* Logout */}
                <button
                    onClick={handleLogout}
                    className="mt-4 w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm text-surface-600 hover:bg-destructive/10 hover:text-destructive transition-colors"
                >
                    <LogOut className="w-4 h-4" />
                    Log out
                </button>
            </div>
        </aside>
    );
}
