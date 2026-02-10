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
 CreditCard,
 HelpCircle,
 ChevronLeft,
 ChevronRight,
 LogOut,
 X,
 type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { SimpleTooltip } from '@/components/ui/tooltip';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';

interface NavItem {
 title: string;
 href: string;
 icon: LucideIcon;
 badge?: string | number;
 disabled?: boolean;
}

interface NavSection {
 title?: string;
 items: NavItem[];
}

/**
 * Customer Console Navigation
 * 
 * NOTE: Sales/CRM features are INTENTIONALLY EXCLUDED from customer console.
 * CRM Pipeline, Lead Scoring, and Sales Automation are CONTROL PLANE features
 * available only at the internal Sales Autopilot service (port 3010).
 * 
 * This separation ensures:
 * 1. Customer data isolation - customers never see owner's lead data
 * 2. Process isolation - control plane runs in separate process
 * 3. Security boundary - different auth/authorization rules
 */
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
 title: 'Settings',
 items: [
 { title: 'Account', href: '/settings', icon: Settings },
 { title: 'Compliance', href: '/compliance', icon: Shield },
 { title: 'Billing', href: '/billing', icon: CreditCard },
 ],
 },
];

const sidebarVariants = cva(
  'flex flex-col border-r border-surface-200 bg-surface-50/80 backdrop-blur-xl transition-all duration-300 ease-in-out',
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
  onClose?: () => void;
}

export function Sidebar({ className, onClose }: SidebarProps) {
  const [collapsed, setCollapsed] = React.useState(false);
  const pathname = usePathname();

  return (
    <aside className={cn(sidebarVariants({ collapsed }), className)}>
      {/* Logo */}
      <div className="flex h-16 items-center justify-between px-4">
        {!collapsed && (
          <Link href="/dashboard" className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground font-bold shadow-sm">
              A
            </div>
            <span className="text-xl font-bold tracking-tight text-foreground">ApexMail</span>
          </Link>
        )}
        {onClose && (
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            onClick={onClose}
            aria-label="Close menu"
          >
            <X className="h-5 w-5" />
          </Button>
        )}
        {collapsed && (
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground font-bold mx-auto shadow-sm">
            A
          </div>
        )}
      </div>

      <Separator className="bg-border/50" />

      {/* Navigation */}
      <ScrollArea className="flex-1 px-3">
        <nav className="flex flex-col gap-6 py-6">
          {mainNav.map((section, sectionIndex) => (
            <div key={sectionIndex} className="flex flex-col gap-1">
              {section.title && !collapsed && (
                <h4 className="px-3 mb-2 text-[14px] font-semibold uppercase tracking-widest text-muted-foreground/60">
                  {section.title}
                </h4>
              )}
              {section.title && collapsed && (
                <Separator className="my-2 bg-border/30" />
              )}
              <div className="flex flex-col gap-1">
                {section.items.map((item) => {
                  const isActive = pathname === item.href || pathname?.startsWith(item.href + '/');
                  const Icon = item.icon;

                  const linkContent = (
                    <Link
                      href={item.disabled ? '#' : item.href}
                      className={cn(
                        'flex items-center gap-3 rounded-md px-3 py-3 text-[14px] font-medium transition-all duration-200',
                        isActive
                          ? 'bg-primary/5 text-primary shadow-[inset_0_0_0_1px_rgba(37,99,235,0.1)]'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                        item.disabled && 'cursor-not-allowed opacity-50',
                        collapsed && 'justify-center px-2.5'
                      )}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      <Icon className={cn('h-[18px] w-[18px]', isActive ? 'text-primary' : 'text-muted-foreground/70')} />
                      {!collapsed && (
                        <>
                          <span className="flex-1 truncate">{item.title}</span>
                          {item.badge && (
                            <span className="rounded-sm bg-primary/10 px-1.5 py-0.5 text-[12px] font-bold text-primary">
                              {item.badge}
                            </span>
                          )}
                        </>
                      )}
                    </Link>
                  );

                  return collapsed ? (
                    <SimpleTooltip key={item.href} content={item.title} side="right">
                      {linkContent}
                    </SimpleTooltip>
                  ) : (
                    <React.Fragment key={item.href}>{linkContent}</React.Fragment>
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
                className="flex items-center gap-3 rounded-md px-3 py-3 text-[14px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
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
 aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
 aria-expanded={!collapsed}
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
