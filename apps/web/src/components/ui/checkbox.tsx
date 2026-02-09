'use client';

import * as React from 'react';
import * as CheckboxPrimitive from '@radix-ui/react-checkbox';
import { Check, Minus } from 'lucide-react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const checkboxVariants = cva(
  'peer shrink-0 border ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-all duration-200 relative after:absolute after:left-1/2 after:top-1/2 after:h-[44px] after:w-[44px] after:-translate-x-1/2 after:-translate-y-1/2 after:content-[""]',
  {
    variants: {
      variant: {
        default:
          'border-input data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground data-[state=checked]:border-primary shadow-sm hover:border-primary/50',
        secondary:
          'border-input data-[state=checked]:bg-secondary data-[state=checked]:text-secondary-foreground',
        destructive:
          'border-destructive data-[state=checked]:bg-destructive data-[state=checked]:text-destructive-foreground',
        success:
          'border-success data-[state=checked]:bg-success data-[state=checked]:text-white',
      },
      size: {
        sm: 'h-3.5 w-3.5 rounded-sm',
        default: 'h-4 w-4 rounded-md',
        lg: 'h-5 w-5 rounded-md',
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
        <Minus className={cn("w-full h-full p-0.5")} strokeWidth={3} />
      ) : (
        <Check className={cn("w-full h-full p-0.5")} strokeWidth={3} />
      )}
    </CheckboxPrimitive.Indicator>
  </CheckboxPrimitive.Root>
));
Checkbox.displayName = CheckboxPrimitive.Root.displayName;

export { Checkbox, checkboxVariants };
