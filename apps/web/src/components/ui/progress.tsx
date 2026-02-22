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
>(({ className, value, variant, size, indicatorVariant, animated, showValue, ...props }, ref) => {
 const clampedValue = Math.max(0, Math.min(100, value ?? 0));

 return (
 <div className="flex items-center gap-2">
 <ProgressPrimitive.Root
 ref={ref}
 className={cn(progressVariants({ variant, size, className }))}
 {...props}
 >
 <ProgressPrimitive.Indicator
 className={cn(progressIndicatorVariants({
 variant: indicatorVariant || variant,
 animated,
 }))}
 >
 <svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
 <rect x="0" y="0" width={clampedValue} height="100" fill="currentColor" rx="999" ry="999" />
 </svg>
 </ProgressPrimitive.Indicator>
 </ProgressPrimitive.Root>
 {showValue && (
 <span className="text-sm text-muted-foreground apex-metric-number">
 {clampedValue}%
 </span>
 )}
 </div>
 );
});
Progress.displayName = ProgressPrimitive.Root.displayName;

export { Progress, progressVariants };
