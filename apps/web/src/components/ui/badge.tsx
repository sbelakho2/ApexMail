import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
    'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
    {
        variants: {
            variant: {
                default: 'border-transparent bg-primary text-primary-foreground',
                secondary: 'border-transparent bg-secondary text-secondary-foreground',
                destructive: 'border-transparent bg-destructive text-destructive-foreground',
                outline: 'text-foreground',
                success: 'border-transparent bg-success/10 text-success',
                warning: 'border-transparent bg-warning/10 text-warning',
                error: 'border-transparent bg-error/10 text-error',
                info: 'border-transparent bg-primary/10 text-primary',
                ghost: 'border-transparent bg-muted text-muted-foreground',
            },
            size: {
                default: 'px-2.5 py-0.5 text-xs',
                sm: 'px-2 py-0.5 text-2xs',
                lg: 'px-3 py-1 text-sm',
            },
        },
        defaultVariants: {
            variant: 'default',
            size: 'default',
        },
    }
);

export interface BadgeProps
    extends React.HTMLAttributes<HTMLDivElement>,
        VariantProps<typeof badgeVariants> {
    icon?: React.ReactNode;
}

function Badge({ className, variant, size, icon, children, ...props }: BadgeProps) {
    return (
        <div className={cn(badgeVariants({ variant, size }), className)} {...props}>
            {icon && <span className="mr-1">{icon}</span>}
            {children}
        </div>
    );
}

export { Badge, badgeVariants };
