'use client';

import * as React from 'react';
import * as ProgressPrimitive from '@radix-ui/react-progress';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const progressVariants = cva(
  'relative w-full overflow-hidden rounded-full',
  {
    variants: {
      variant: {
        default: 'bg-surface-100',
        success: 'bg-success/20',
        warning: 'bg-warning/20',
        error: 'bg-destructive/20',
      },
      size: {
        sm: 'h-1',
        default: 'h-2',
        lg: 'h-3',
        xl: 'h-4',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

const progressIndicatorVariants = cva(
 'h-full w-full flex-1 transition-all duration-300 ease-in-out',
 {
 variants: {
 variant: {
 default: 'bg-primary',
 success: 'bg-success',
 warning: 'bg-warning',
 error: 'bg-destructive',
 },
 animated: {
 true: 'animate-progress',
 false: '',
 },
 },
 defaultVariants: {
 variant: 'default',
 animated: false,
 },
 }
);

export interface ProgressProps
 extends React.ComponentPropsWithoutRef<typeof ProgressPrimitive.Root>,
 VariantProps<typeof progressVariants> {
 indicatorVariant?: VariantProps<typeof progressIndicatorVariants>['variant'];
 animated?: boolean;
 showValue?: boolean;
}

const Progress = React.forwardRef<
 React.ElementRef<typeof ProgressPrimitive.Root>,
 ProgressProps
>(({ className, value, variant, size, indicatorVariant, animated, showValue, ...props }, ref) => (
 <div className="flex items-center gap-2">
 <ProgressPrimitive.Root
 ref={ref}
 className={cn(progressVariants({ variant, size, className }))}
 {...props}
 >
 <ProgressPrimitive.Indicator
 className={cn(progressIndicatorVariants({ 
 variant: indicatorVariant || variant, 
 animated 
 }))}
 style={{ transform: `translateX(-${100 - (value || 0)}%)` }}
 />
 </ProgressPrimitive.Root>
 {showValue && (
 <span className="text-sm text-muted-foreground apex-metric-number">
 {value}%
 </span>
 )}
 </div>
));
Progress.displayName = ProgressPrimitive.Root.displayName;

export { Progress, progressVariants };
