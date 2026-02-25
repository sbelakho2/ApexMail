'use client';

import * as React from 'react';
import { ChevronRight, Home } from '@/components/ui/icons';
import Link from 'next/link';
import { cn } from '@/lib/utils';

interface BreadcrumbItem {
 label: string;
 href?: string;
}

interface PageHeaderProps {
 title: string;
 description?: string;
 breadcrumbs?: BreadcrumbItem[];
 actions?: React.ReactNode;
 className?: string;
 children?: React.ReactNode;
}

export function PageHeader({
  title,
  description,
  breadcrumbs,
  actions,
  className,
  children,
}: PageHeaderProps) {
  const mobileBreadcrumbs = React.useMemo(() => {
    if (!breadcrumbs || breadcrumbs.length === 0) return [] as Array<BreadcrumbItem | { label: '…' }>;
    if (breadcrumbs.length <= 2) return breadcrumbs;
    return [breadcrumbs[0], { label: '…' as const }, breadcrumbs[breadcrumbs.length - 1]];
  }, [breadcrumbs]);

  return (
    <div className={cn('relative pb-6 mb-8 border-b border-surface-200/70', className)}>
      <div className="flex flex-col gap-4">
        {/* Breadcrumbs */}
        {breadcrumbs && breadcrumbs.length > 0 && (
          <>
          <nav className="flex sm:hidden items-center gap-x-1.5 gap-y-1 text-[13px] text-surface-500 min-w-0 overflow-hidden">
            <Link
              href="/dashboard"
              className="flex items-center shrink-0 hover:text-surface-900 transition-all duration-200"
            >
              <Home className="h-3.5 w-3.5" />
            </Link>
            {mobileBreadcrumbs.map((item, index) => (
              <React.Fragment key={index}>
                <ChevronRight className="h-3 w-3 opacity-40 shrink-0" />
                {'href' in item && item.href ? (
                  <Link
                    href={item.href}
                    className="max-w-[120px] truncate hover:text-surface-900 transition-all duration-200"
                  >
                    {item.label}
                  </Link>
                ) : (
                  <span className="max-w-[120px] truncate font-medium text-surface-900">{item.label}</span>
                )}
              </React.Fragment>
            ))}
          </nav>

          <nav className="hidden sm:flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[13px] text-surface-500 min-w-0">
            <Link
              href="/dashboard"
              className="flex items-center shrink-0 hover:text-surface-900 transition-all duration-200"
            >
              <Home className="h-3.5 w-3.5" />
            </Link>
            {breadcrumbs.map((item, index) => (
              <React.Fragment key={index}>
                <ChevronRight className="h-3 w-3 opacity-40 shrink-0" />
                {item.href ? (
                  <Link
                    href={item.href}
                    className="max-w-[240px] truncate hover:text-surface-900 transition-all duration-200"
                  >
                    {item.label}
                  </Link>
                ) : (
                  <span className="max-w-[240px] truncate font-medium text-surface-900">
                    {item.label}
                  </span>
                )}
              </React.Fragment>
            ))}
          </nav>
          </>
        )}

        {/* Header content */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1.5 min-w-0">
            <h1 className="text-2xl font-bold tracking-tight md:text-3xl text-surface-900 break-words">
              {title}
            </h1>
            {description && (
              <p className="text-[15px] text-surface-600 max-w-[720px] leading-relaxed break-words">
                {description}
              </p>
            )}
          </div>
          {actions && (
            <div className="flex flex-wrap items-center gap-3 shrink-0">{actions}</div>
          )}
        </div>

        {/* Optional children content */}
        {children && <div className="mt-2">{children}</div>}
      </div>
    </div>
  );
}
