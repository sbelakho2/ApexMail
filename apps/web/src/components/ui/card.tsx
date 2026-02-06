import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const cardVariants = cva('rounded-lg border bg-card text-card-foreground transition-all duration-150 ease-out', {
  variants: {
    variant: {
      default: 'border-border shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)]',
      ghost: 'border-transparent shadow-none',
      premium: 'premium-card border-border',
      outline: 'border-border bg-transparent',
      elevated: 'border-border shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)] hover:shadow-[0_14px_40px_rgba(15,23,42,0.08)]',
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
      true: 'cursor-pointer hover:border-primary/30 hover:bg-muted/50 active:scale-[0.99] shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)] hover:shadow-[0_14px_40px_rgba(15,23,42,0.08)]',
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
 <div ref={ref} className={cn('flex flex-col space-y-1.5', className)} {...props} />
 )
);
CardHeader.displayName = 'CardHeader';

const CardTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(
 ({ className, ...props }, ref) => (
 <h3
 ref={ref}
 className={cn('font-bold leading-tight tracking-tight', className)}
 {...props}
 />
 )
);
CardTitle.displayName = 'CardTitle';

const CardDescription = React.forwardRef<
 HTMLParagraphElement,
 React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
 <p ref={ref} className={cn('text-sm text-muted-foreground', className)} {...props} />
));
CardDescription.displayName = 'CardDescription';

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
 ({ className, ...props }, ref) => <div ref={ref} className={cn('', className)} {...props} />
);
CardContent.displayName = 'CardContent';

const CardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
 ({ className, ...props }, ref) => (
 <div ref={ref} className={cn('flex items-center pt-4', className)} {...props} />
 )
);
CardFooter.displayName = 'CardFooter';

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent, cardVariants };
