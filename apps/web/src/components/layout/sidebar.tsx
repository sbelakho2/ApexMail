'use client';

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cva, type VariantProps } from 'class-variance-authority';
import {
    Home,
    Mail,
    Users,
    BarChart3,
    Settings,
    Send,
    ListFilter,
    Shield,
    Bot,
    Building2,
    CreditCard,
    HelpCircle,
    ChevronLeft,
    ChevronRight,
    LogOut,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { SimpleTooltip } from '@/components/ui/tooltip';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';

interface NavItem {
    title: string;
    href: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string | number;
    disabled?: boolean;
}

interface NavSection {
    title?: string;
    items: NavItem[];
}

const mainNav: NavSection[] = [
    {
        items: [
            { title: 'Dashboard', href: '/dashboard', icon: Home },
            { title: 'Campaigns', href: '/campaigns', icon: Send },
            { title: 'Contacts', href: '/contacts', icon: Users },
            { title: 'Lists', href: '/lists', icon: ListFilter },
            { title: 'Templates', href: '/templates', icon: Mail },
        ],
    },
    {
        title: 'Analytics',
        items: [
            { title: 'Reports', href: '/reports', icon: BarChart3 },
            { title: 'AI Insights', href: '/ai-insights', icon: Bot },
        ],
    },
    {
        title: 'Sales',
        items: [
            { title: 'CRM Pipeline', href: '/crm', icon: Building2 },
            { title: 'Lead Scoring', href: '/leads', icon: Users },
        ],
    },
    {
        title: 'Settings',
        items: [
            { title: 'Account', href: '/settings', icon: Settings },
            { title: 'Compliance', href: '/compliance', icon: Shield },
            { title: 'Billing', href: '/billing', icon: CreditCard },
        ],
    },
];

const sidebarVariants = cva(
    'flex flex-col border-r bg-background transition-all duration-300 ease-in-out',
    {
        variants: {
            collapsed: {
                true: 'w-16',
                false: 'w-64',
            },
        },
        defaultVariants: {
            collapsed: false,
        },
    }
);

interface SidebarProps extends VariantProps<typeof sidebarVariants> {
    className?: string;
}

export function Sidebar({ className }: SidebarProps) {
    const [collapsed, setCollapsed] = React.useState(false);
    const pathname = usePathname();

    return (
        <aside className={cn(sidebarVariants({ collapsed }), className)}>
            {/* Logo */}
            <div className="flex h-16 items-center justify-between px-4 border-b">
                {!collapsed && (
                    <Link href="/dashboard" className="flex items-center gap-2">
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold">
                            A
                        </div>
                        <span className="text-lg font-semibold">ApexMail</span>
                    </Link>
                )}
                {collapsed && (
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold mx-auto">
                        A
                    </div>
                )}
            </div>

            {/* Navigation */}
            <ScrollArea className="flex-1 py-4">
                <nav className="space-y-6 px-2">
                    {mainNav.map((section, sectionIndex) => (
                        <div key={sectionIndex}>
                            {section.title && !collapsed && (
                                <h4 className="mb-2 px-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                                    {section.title}
                                </h4>
                            )}
                            {section.title && collapsed && (
                                <Separator className="my-2" />
                            )}
                            <div className="space-y-1">
                                {section.items.map((item) => {
                                    const isActive = pathname === item.href || pathname?.startsWith(item.href + '/');
                                    const Icon = item.icon;

                                    const linkContent = (
                                        <Link
                                            href={item.disabled ? '#' : item.href}
                                            className={cn(
                                                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                                                isActive
                                                    ? 'bg-primary/10 text-primary'
                                                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                                                item.disabled && 'cursor-not-allowed opacity-50',
                                                collapsed && 'justify-center px-2'
                                            )}
                                        >
                                            <Icon className="h-5 w-5 shrink-0" />
                                            {!collapsed && (
                                                <>
                                                    <span className="flex-1">{item.title}</span>
                                                    {item.badge && (
                                                        <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-semibold text-primary">
                                                            {item.badge}
                                                        </span>
                                                    )}
                                                </>
                                            )}
                                        </Link>
                                    );

                                    return collapsed ? (
                                        <SimpleTooltip
                                            key={item.href}
                                            content={item.title}
                                            side="right"
                                        >
                                            {linkContent}
                                        </SimpleTooltip>
                                    ) : (
                                        <React.Fragment key={item.href}>
                                            {linkContent}
                                        </React.Fragment>
                                    );
                                })}
                            </div>
                        </div>
                    ))}
                </nav>
            </ScrollArea>

            {/* Footer */}
            <div className="border-t p-4">
                {!collapsed && (
                    <div className="mb-4">
                        <Link
                            href="/help"
                            className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                        >
                            <HelpCircle className="h-5 w-5" />
                            <span>Help & Support</span>
                        </Link>
                    </div>
                )}
                <div className="flex items-center justify-between">
                    {!collapsed && (
                        <Button variant="ghost" size="sm" className="text-muted-foreground">
                            <LogOut className="h-4 w-4 mr-2" />
                            Sign Out
                        </Button>
                    )}
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setCollapsed(!collapsed)}
                        className={cn(collapsed && 'mx-auto')}
                    >
                        {collapsed ? (
                            <ChevronRight className="h-4 w-4" />
                        ) : (
                            <ChevronLeft className="h-4 w-4" />
                        )}
                    </Button>
                </div>
            </div>
        </aside>
    );
}

export { mainNav, type NavItem, type NavSection };
