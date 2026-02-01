'use client';

import * as React from 'react';
import * as CheckboxPrimitive from '@radix-ui/react-checkbox';
import { Check, Minus } from 'lucide-react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const checkboxVariants = cva(
    'peer shrink-0 rounded-sm border ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
    {
        variants: {
            variant: {
                default:
                    'border-primary data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground',
                secondary:
                    'border-secondary data-[state=checked]:bg-secondary data-[state=checked]:text-secondary-foreground',
                destructive:
                    'border-destructive data-[state=checked]:bg-destructive data-[state=checked]:text-destructive-foreground',
                success:
                    'border-success data-[state=checked]:bg-success data-[state=checked]:text-white',
            },
            size: {
                sm: 'h-3.5 w-3.5',
                default: 'h-4 w-4',
                lg: 'h-5 w-5',
            },
        },
        defaultVariants: {
            variant: 'default',
            size: 'default',
        },
    }
);

export interface CheckboxProps
    extends React.ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>,
        VariantProps<typeof checkboxVariants> {
    indeterminate?: boolean;
}

const Checkbox = React.forwardRef<
    React.ElementRef<typeof CheckboxPrimitive.Root>,
    CheckboxProps
>(({ className, variant, size, indeterminate, ...props }, ref) => (
    <CheckboxPrimitive.Root
        ref={ref}
        className={cn(checkboxVariants({ variant, size, className }))}
        {...props}
    >
        <CheckboxPrimitive.Indicator
            className={cn('flex items-center justify-center text-current')}
        >
            {indeterminate ? (
                <Minus className="h-3 w-3" />
            ) : (
                <Check className="h-3 w-3" />
            )}
        </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
));
Checkbox.displayName = CheckboxPrimitive.Root.displayName;

export { Checkbox, checkboxVariants };
