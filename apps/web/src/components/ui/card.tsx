import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const cardVariants = cva('rounded-xl border bg-card text-card-foreground transition-all duration-200', {
    variants: {
        variant: {
            default: 'border-border shadow-sm',
            ghost: 'border-transparent shadow-none',
            glass: 'glass-morphism border-white/20',
            outline: 'border-border bg-transparent',
            elevated: 'border-border shadow-lg',
        },
        padding: {
            none: '',
            sm: 'p-4',
            default: 'p-6',
            lg: 'p-8',
        },
        interactive: {
            true: 'cursor-pointer hover:shadow-md hover:border-primary/20 active:scale-[0.99]',
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
            className={cn('text-lg font-semibold leading-none tracking-tight', className)}
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
