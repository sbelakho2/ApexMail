'use client';

import * as React from 'react';
import * as LabelPrimitive from '@radix-ui/react-label';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const labelVariants = cva(
 'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
 {
 variants: {
 variant: {
 default: 'text-foreground',
 muted: 'text-muted-foreground',
 error: 'text-destructive',
 success: 'text-success',
 },
 size: {
 sm: 'text-xs',
 default: 'text-sm',
 lg: 'text-base',
 },
 },
 defaultVariants: {
 variant: 'default',
 size: 'default',
 },
 }
);

export interface LabelProps
 extends React.ComponentPropsWithoutRef<typeof LabelPrimitive.Root>,
 VariantProps<typeof labelVariants> {
 required?: boolean;
 optional?: boolean;
}

const Label = React.forwardRef<
 React.ElementRef<typeof LabelPrimitive.Root>,
 LabelProps
>(({ className, variant, size, required, optional, children, ...props }, ref) => (
 <LabelPrimitive.Root
 ref={ref}
 className={cn(labelVariants({ variant, size, className }))}
 {...props}
 >
 {children}
 {required && <span className="ml-1 text-destructive">*</span>}
 {optional && <span className="ml-1 text-muted-foreground">(optional)</span>}
 </LabelPrimitive.Root>
));
Label.displayName = LabelPrimitive.Root.displayName;

export { Label, labelVariants };
