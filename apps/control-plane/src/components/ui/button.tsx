import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
    'inline-flex items-center justify-center rounded-lg font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/30 disabled:opacity-50 disabled:cursor-not-allowed',
    {
        variants: {
            variant: {
                default: 'bg-primary text-primary-foreground hover:bg-primary/90',
                outline: 'bg-card border border-border text-foreground hover:bg-muted',
                ghost: 'text-muted-foreground hover:text-foreground hover:bg-muted',
                destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
            },
            size: {
                sm: 'min-h-[44px] px-3 py-2 text-sm',
                md: 'min-h-[44px] px-4 py-2 text-sm',
                lg: 'min-h-[44px] px-6 py-2.5 text-sm',
            },
        },
        defaultVariants: {
            variant: 'default',
            size: 'md',
        },
    }
);

export interface ButtonProps
    extends React.ButtonHTMLAttributes<HTMLButtonElement>,
        VariantProps<typeof buttonVariants> {}

export function Button({ className, variant, size, ...props }: ButtonProps) {
    return <button className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}
