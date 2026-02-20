import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-lg text-[14px] font-display font-semibold tracking-[0.01em] ring-offset-background transition-all duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]',
  {
    variants: {
      variant: {
        apex: 'font-display bg-gradient-to-b from-brand-500 to-brand-700 text-white border border-brand-500/60 shadow-[0_12px_34px_rgba(52,78,165,0.38),inset_0_1px_0_rgba(255,255,255,0.25)] hover:from-brand-500 hover:to-brand-600 hover:shadow-[0_16px_40px_rgba(52,78,165,0.45)] dark:from-brand-400 dark:to-brand-600 dark:border-brand-300/60 dark:text-surface-900 dark:shadow-[0_14px_36px_rgba(91,120,210,0.48),inset_0_1px_0_rgba(255,255,255,0.18)] dark:hover:from-brand-400 dark:hover:to-brand-500',
        default: 'font-display bg-gradient-to-b from-brand-500 to-brand-700 text-white border border-brand-500/60 shadow-[0_12px_34px_rgba(52,78,165,0.38),inset_0_1px_0_rgba(255,255,255,0.25)] hover:from-brand-500 hover:to-brand-600 hover:shadow-[0_16px_40px_rgba(52,78,165,0.45)] dark:from-brand-400 dark:to-brand-600 dark:border-brand-300/60 dark:text-surface-900 dark:shadow-[0_14px_36px_rgba(91,120,210,0.48),inset_0_1px_0_rgba(255,255,255,0.18)] dark:hover:from-brand-400 dark:hover:to-brand-500',
        destructive:
          'bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-sm',
        outline:
          'border border-input bg-background text-foreground shadow-sm hover:bg-accent hover:text-accent-foreground hover:shadow-md dark:border-surface-300/70 dark:bg-surface-100/90 dark:hover:bg-surface-200/80',
        secondary:
          'bg-secondary text-secondary-foreground hover:bg-secondary/80 shadow-sm',
        ghost: 'hover:bg-accent hover:text-accent-foreground',
        link: 'text-primary underline-offset-4 hover:underline',
        premium: 'premium-card hover:bg-muted text-foreground',
        success: 'bg-success text-success-foreground hover:bg-success/90 shadow-sm',
        warning: 'bg-warning text-warning-foreground hover:bg-warning/90 shadow-sm',
        glass: 'backdrop-blur-md bg-white/10 border border-white/20 text-foreground hover:bg-white/20 shadow-lg',
      },
      size: {
        default: 'h-11 px-4 py-2',
        sm: 'h-9 rounded-sm px-3 text-sm min-h-[44px]',
        lg: 'h-11 rounded-lg px-6 text-[17px]',
        xl: 'h-12 rounded-lg px-8 text-[17px]',
        icon: 'h-11 w-11',
        'icon-sm': 'h-9 w-9 min-h-[44px] min-w-[44px] rounded-sm',
        'icon-lg': 'h-12 w-12 rounded-lg',
      },
    },
 defaultVariants: {
 variant: 'apex',
 size: 'default',
 },
 }
);

export interface ButtonProps
 extends React.ButtonHTMLAttributes<HTMLButtonElement>,
 VariantProps<typeof buttonVariants> {
 asChild?: boolean;
 loading?: boolean;
 leftIcon?: React.ReactNode;
 rightIcon?: React.ReactNode;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
 (
 {
 className,
 variant,
 size,
 asChild = false,
 loading = false,
 leftIcon,
 rightIcon,
 children,
 disabled,
 ...props
 },
 ref
 ) => {
 const Comp = asChild ? Slot : 'button';

 // When asChild is true, Slot expects exactly one child element
 // So we don't render loading indicators or icons - those should be in the child
 if (asChild) {
 return (
 <Comp
 className={cn(buttonVariants({ variant, size, className }))}
 ref={ref}
 {...props}
 >
 {children}
 </Comp>
 );
 }

 return (
 <Comp
 className={cn(buttonVariants({ variant, size, className }))}
 ref={ref}
 disabled={disabled || loading}
 {...props}
 >
 {loading && (
 <svg
 className="mr-2 h-4 w-4 animate-spin"
 xmlns="http://www.w3.org/2000/svg"
 fill="none"
 viewBox="0 0 24 24"
 >
 <circle
 className="opacity-25"
 cx="12"
 cy="12"
 r="10"
 stroke="currentColor"
 strokeWidth="4"
 />
 <path
 className="opacity-75"
 fill="currentColor"
 d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
 />
 </svg>
 )}
 {!loading && leftIcon && <span className="mr-2">{leftIcon}</span>}
 {children}
 {!loading && rightIcon && <span className="ml-2">{rightIcon}</span>}
 </Comp>
 );
 }
);
Button.displayName = 'Button';

export { Button, buttonVariants };
