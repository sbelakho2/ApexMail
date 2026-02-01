'use client';

import * as React from 'react';
import { ChevronRight, Home } from 'lucide-react';
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
        <div className={cn('space-y-4', className)}>
            {/* Breadcrumbs */}
            {breadcrumbs && breadcrumbs.length > 0 && (
                <nav className="flex items-center space-x-1 text-sm text-muted-foreground">
                    <Link
                        href="/dashboard"
                        className="flex items-center hover:text-foreground transition-colors"
                    >
                        <Home className="h-4 w-4" />
                    </Link>
                    {breadcrumbs.map((item, index) => (
                        <React.Fragment key={index}>
                            <ChevronRight className="h-4 w-4" />
                            {item.href ? (
                                <Link
                                    href={item.href}
                                    className="hover:text-foreground transition-colors"
                                >
                                    {item.label}
                                </Link>
                            ) : (
                                <span className="font-medium text-foreground">
                                    {item.label}
                                </span>
                            )}
                        </React.Fragment>
                    ))}
                </nav>
            )}

            {/* Header content */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
                        {title}
                    </h1>
                    {description && (
                        <p className="mt-1 text-muted-foreground">{description}</p>
                    )}
                </div>
                {actions && (
                    <div className="flex flex-wrap items-center gap-2">{actions}</div>
                )}
            </div>

            {/* Optional children content */}
            {children}
        </div>
    );
}
