import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const cardVariants = cva('rounded-[var(--radius-lg)] border border-border bg-card text-card-foreground transition-premium font-display dark:border-surface-300/60 dark:bg-surface-100/95', {
  variants: {
    variant: {
      default: 'shadow-premium hover:border-primary/30 hover:bg-muted/40 hover:shadow-premium-hover',
      ghost: 'border-transparent shadow-none',
      premium: 'premium-card',
      outline: 'border-border bg-transparent',
      elevated: 'shadow-premium-hover hover:border-primary/30',
      inset: 'border-border bg-muted/30 shadow-inner',
    },
    padding: {
      none: '',
      xs: 'p-2', // var(--space-2)
      sm: 'p-3', // var(--space-3)
      default: 'p-4', // var(--space-4)
      lg: 'p-6', // var(--space-6)
      xl: 'p-8', // var(--space-8)
    },
    interactive: {
      true: 'cursor-pointer hover:border-primary/30 hover:bg-muted/50 active:scale-[0.99] shadow-premium hover:shadow-premium-hover',
      false: '',
    },
  },
  defaultVariants: {
    variant: 'default',
    padding: 'default',
    interactive: false,
  },
});

export interface CardProps
 extends React.HTMLAttributes<HTMLDivElement>,
 VariantProps<typeof cardVariants> {}

const Card = React.forwardRef<HTMLDivElement, CardProps>(
  ({ className, variant, padding, interactive, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(cardVariants({ variant, padding, interactive, className }))}
      {...props}
    />
  )
);
Card.displayName = 'Card';

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex flex-col space-y-1.5 font-display min-w-0', className)}
      {...props}
    />
  )
);
CardHeader.displayName = 'CardHeader';

const CardTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h3
      ref={ref}
      className={cn('font-display font-bold leading-tight tracking-tight break-words', className)}
      {...props}
    />
  )
);
CardTitle.displayName = 'CardTitle';

const CardDescription = React.forwardRef<
 HTMLParagraphElement,
 React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn('font-display text-sm text-muted-foreground break-words', className)}
    {...props}
  />
));
CardDescription.displayName = 'CardDescription';

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('font-display min-w-0', className)} {...props} />
  )
);
CardContent.displayName = 'CardContent';

const CardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex items-center pt-4 font-display min-w-0', className)}
      {...props}
    />
  )
);
CardFooter.displayName = 'CardFooter';

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent, cardVariants };
