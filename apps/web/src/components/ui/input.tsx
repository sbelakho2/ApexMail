import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const inputVariants = cva(
    'flex w-full rounded-lg border bg-background text-sm ring-offset-background transition-all duration-200 file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
    {
        variants: {
            variant: {
                default: 'border-input',
                error: 'border-destructive focus-visible:ring-destructive',
                success: 'border-success focus-visible:ring-success',
                glass: 'glass-morphism border-white/20',
            },
            inputSize: {
                default: 'h-10 px-3 py-2',
                sm: 'h-9 px-2 py-1 text-sm',
                lg: 'h-11 px-4 py-3',
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
