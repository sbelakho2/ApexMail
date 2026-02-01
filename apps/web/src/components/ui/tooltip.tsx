'use client';

import * as React from 'react';
import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const TooltipProvider = TooltipPrimitive.Provider;

const Tooltip = TooltipPrimitive.Root;

const TooltipTrigger = TooltipPrimitive.Trigger;

const tooltipContentVariants = cva(
    'z-50 overflow-hidden rounded-md px-3 py-1.5 text-xs animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2',
    {
        variants: {
            variant: {
                default: 'border bg-popover text-popover-foreground shadow-md',
                dark: 'bg-primary text-primary-foreground',
                glass: 'glass border-white/10 text-foreground',
            },
        },
        defaultVariants: {
            variant: 'default',
        },
    }
);

export interface TooltipContentProps
    extends React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>,
        VariantProps<typeof tooltipContentVariants> {}

const TooltipContent = React.forwardRef<
    React.ElementRef<typeof TooltipPrimitive.Content>,
    TooltipContentProps
>(({ className, sideOffset = 4, variant, ...props }, ref) => (
    <TooltipPrimitive.Content
        ref={ref}
        sideOffset={sideOffset}
        className={cn(tooltipContentVariants({ variant, className }))}
        {...props}
    />
));
TooltipContent.displayName = TooltipPrimitive.Content.displayName;

// Convenience wrapper component
interface SimpleTooltipProps {
    content: React.ReactNode;
    children: React.ReactNode;
    side?: 'top' | 'right' | 'bottom' | 'left';
    align?: 'start' | 'center' | 'end';
    delayDuration?: number;
    variant?: TooltipContentProps['variant'];
}

const SimpleTooltip = ({
    content,
    children,
    side = 'top',
    align = 'center',
    delayDuration = 200,
    variant,
}: SimpleTooltipProps) => (
    <TooltipProvider>
        <Tooltip delayDuration={delayDuration}>
            <TooltipTrigger asChild>{children}</TooltipTrigger>
            <TooltipContent side={side} align={align} variant={variant}>
                {content}
            </TooltipContent>
        </Tooltip>
    </TooltipProvider>
);

export {
    Tooltip,
    TooltipTrigger,
    TooltipContent,
    TooltipProvider,
    SimpleTooltip,
    tooltipContentVariants,
};
