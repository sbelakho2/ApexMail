import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm',
        secondary: 'border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80',
        destructive: 'border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/90',
        outline: 'text-foreground hover:bg-accent hover:text-accent-foreground',
        success: 'border-transparent bg-success text-success-foreground hover:bg-success/90 shadow-sm',
        warning: 'border-transparent bg-warning text-warning-foreground hover:bg-warning/90 shadow-sm',
        error: 'border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-sm',
        info: 'border-transparent bg-info text-info-foreground hover:bg-info/90 shadow-sm',
        ghost: 'border-transparent bg-muted text-muted-foreground hover:bg-muted/80',
        'outline-success': 'text-success border-success/30 bg-success/5',
        'outline-warning': 'text-warning border-warning/30 bg-warning/5',
        'outline-error': 'text-destructive border-destructive/30 bg-destructive/5',
      },
      size: {
        default: 'px-2.5 py-0.5 text-xs',
        sm: 'px-2.5 py-0.5 text-[10px] uppercase tracking-wider font-bold',
        lg: 'px-3 py-1 text-sm',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface BadgeProps
 extends React.HTMLAttributes<HTMLDivElement>,
 VariantProps<typeof badgeVariants> {
 icon?: React.ReactNode;
}

function Badge({ className, variant, size, icon, children, ...props }: BadgeProps) {
 return (
 <div className={cn(badgeVariants({ variant, size }), className)} {...props}>
 {icon && <span className="mr-1">{icon}</span>}
 {children}
 </div>
 );
}

export { Badge, badgeVariants };
