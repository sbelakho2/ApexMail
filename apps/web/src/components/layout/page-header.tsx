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
  return (
    <div className={cn('relative pb-6 mb-8 border-b border-surface-200/70', className)}>
      <div className="flex flex-col gap-4">
        {/* Breadcrumbs */}
        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav className="flex items-center space-x-1.5 text-[13px] text-surface-500">
            <Link
              href="/dashboard"
              className="flex items-center hover:text-surface-900 transition-all duration-200"
            >
              <Home className="h-3.5 w-3.5" />
            </Link>
            {breadcrumbs.map((item, index) => (
              <React.Fragment key={index}>
                <ChevronRight className="h-3 w-3 opacity-40" />
                {item.href ? (
                  <Link
                    href={item.href}
                    className="hover:text-surface-900 transition-all duration-200"
                  >
                    {item.label}
                  </Link>
                ) : (
                  <span className="font-medium text-surface-900">
                    {item.label}
                  </span>
                )}
              </React.Fragment>
            ))}
          </nav>
        )}

        {/* Header content */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1.5">
            <h1 className="text-2xl font-bold tracking-tight md:text-3xl text-surface-900">
              {title}
            </h1>
            {description && (
              <p className="text-[15px] text-surface-600 max-w-[720px] leading-relaxed">
                {description}
              </p>
            )}
          </div>
          {actions && (
            <div className="flex flex-wrap items-center gap-3">{actions}</div>
          )}
        </div>

        {/* Optional children content */}
        {children && <div className="mt-2">{children}</div>}
      </div>
    </div>
  );
}
