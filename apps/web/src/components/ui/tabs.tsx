'use client';

import * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const Tabs = TabsPrimitive.Root;

const tabsListVariants = cva(
    'inline-flex items-center justify-center',
    {
        variants: {
            variant: {
                default: 'rounded-md bg-muted p-1 text-muted-foreground',
                underline: 'border-b border-border bg-transparent',
                pills: 'gap-2 bg-transparent',
            },
        },
        defaultVariants: {
            variant: 'default',
        },
    }
);

export interface TabsListProps
    extends React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>,
        VariantProps<typeof tabsListVariants> {}

const TabsList = React.forwardRef<
    React.ElementRef<typeof TabsPrimitive.List>,
    TabsListProps
>(({ className, variant, ...props }, ref) => (
    <TabsPrimitive.List
        ref={ref}
        className={cn(tabsListVariants({ variant, className }))}
        {...props}
    />
));
TabsList.displayName = TabsPrimitive.List.displayName;

const tabsTriggerVariants = cva(
    'inline-flex items-center justify-center whitespace-nowrap px-3 py-1.5 text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
    {
        variants: {
            variant: {
                default:
                    'rounded-sm data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm',
                underline:
                    'relative border-b-2 border-transparent pb-3 pt-2 text-muted-foreground data-[state=active]:border-primary data-[state=active]:text-foreground',
                pills:
                    'rounded-full bg-transparent data-[state=active]:bg-primary data-[state=active]:text-primary-foreground',
            },
        },
        defaultVariants: {
            variant: 'default',
        },
    }
);

export interface TabsTriggerProps
    extends React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>,
        VariantProps<typeof tabsTriggerVariants> {
    icon?: React.ReactNode;
}

const TabsTrigger = React.forwardRef<
    React.ElementRef<typeof TabsPrimitive.Trigger>,
    TabsTriggerProps
>(({ className, variant, icon, children, ...props }, ref) => (
    <TabsPrimitive.Trigger
        ref={ref}
        className={cn(tabsTriggerVariants({ variant, className }))}
        {...props}
    >
        {icon && <span className="mr-2">{icon}</span>}
        {children}
    </TabsPrimitive.Trigger>
));
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName;

const TabsContent = React.forwardRef<
    React.ElementRef<typeof TabsPrimitive.Content>,
    React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
    <TabsPrimitive.Content
        ref={ref}
        className={cn(
            'mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
            className
        )}
        {...props}
    />
));
TabsContent.displayName = TabsPrimitive.Content.displayName;

export { Tabs, TabsList, TabsTrigger, TabsContent, tabsListVariants, tabsTriggerVariants };
