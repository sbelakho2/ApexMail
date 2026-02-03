import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const inputVariants = cva(
  'flex w-full rounded-md border bg-background text-[14px] ring-offset-background transition-all duration-300 file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:border-primary disabled:cursor-not-allowed disabled:opacity-50 hover:border-border/80 shadow-sm',
  {
    variants: {
      variant: {
        default: 'border-input',
        error: 'border-destructive focus-visible:ring-destructive/20 focus-visible:border-destructive',
        success: 'border-success focus-visible:ring-success/20 focus-visible:border-success',
        ghost: 'border-transparent bg-transparent shadow-none hover:bg-muted/50',
      },
      inputSize: {
        default: 'h-10 px-3 py-2',
        sm: 'h-8 px-2.5 py-1 text-xs rounded-sm',
        lg: 'h-11 px-4 py-3 text-[17px] rounded-lg',
      },
    },
 defaultVariants: {
 variant: 'default',
 inputSize: 'default',
 },
 }
);

export interface InputProps
 extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'>,
 VariantProps<typeof inputVariants> {
 leftIcon?: React.ReactNode;
 rightIcon?: React.ReactNode;
 error?: string;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
 ({ className, type, variant, inputSize, leftIcon, rightIcon, error, ...props }, ref) => {
 const errorVariant = error ? 'error' : variant;

 if (leftIcon || rightIcon) {
 return (
 <div className="relative">
 {leftIcon && (
 <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
 {leftIcon}
 </div>
 )}
 <input
 type={type}
 className={cn(
 inputVariants({ variant: errorVariant, inputSize }),
 leftIcon && 'pl-10',
 rightIcon && 'pr-10',
 className
 )}
 ref={ref}
 {...props}
 />
 {rightIcon && (
 <div className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground">
 {rightIcon}
 </div>
 )}
 </div>
 );
 }

 return (
 <input
 type={type}
 className={cn(inputVariants({ variant: errorVariant, inputSize, className }))}
 ref={ref}
 {...props}
 />
 );
 }
);
Input.displayName = 'Input';

export { Input, inputVariants };
