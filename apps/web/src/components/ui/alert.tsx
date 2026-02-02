'use client';

import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import {
 AlertCircle,
 CheckCircle,
 Info,
 AlertTriangle,
 X,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const alertVariants = cva(
  'relative w-full rounded-xl border p-4 [&>svg~*]:pl-7 [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground shadow-sm',
  {
    variants: {
      variant: {
        default: 'bg-surface-50 text-surface-900 border-surface-200',
        destructive:
          'border-destructive/20 bg-destructive/5 text-destructive dark:border-destructive [&>svg]:text-destructive',
        success:
          'border-success/20 bg-success/5 text-success-700 dark:border-success [&>svg]:text-success',
        warning:
          'border-warning/20 bg-warning/5 text-warning-700 dark:border-warning [&>svg]:text-warning',
        info:
          'border-primary/20 bg-primary/5 text-primary-700 dark:border-primary [&>svg]:text-primary',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

interface AlertProps
 extends React.HTMLAttributes<HTMLDivElement>,
 VariantProps<typeof alertVariants> {
 onClose?: () => void;
 icon?: React.ReactNode;
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
 ({ className, variant, children, onClose, icon, ...props }, ref) => {
 const defaultIcons = {
 default: <Info className="h-4 w-4" />,
 destructive: <AlertCircle className="h-4 w-4" />,
 success: <CheckCircle className="h-4 w-4" />,
 warning: <AlertTriangle className="h-4 w-4" />,
 info: <Info className="h-4 w-4" />,
 };

 return (
 <div
 ref={ref}
 role="alert"
 className={cn(alertVariants({ variant }), className)}
 {...props}
 >
 {icon || defaultIcons[variant || 'default']}
 {children}
 {onClose && (
 <button
 onClick={onClose}
 className="absolute right-2 top-2 rounded-md p-1 opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
 >
 <X className="h-4 w-4" />
 <span className="sr-only">Dismiss</span>
 </button>
 )}
 </div>
 );
 }
);
Alert.displayName = 'Alert';

const AlertTitle = React.forwardRef<
 HTMLParagraphElement,
 React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
 <h5
 ref={ref}
 className={cn('mb-1 font-medium leading-none tracking-tight', className)}
 {...props}
 />
));
AlertTitle.displayName = 'AlertTitle';

const AlertDescription = React.forwardRef<
 HTMLParagraphElement,
 React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
 <div
 ref={ref}
 className={cn('text-sm [&_p]:leading-relaxed', className)}
 {...props}
 />
));
AlertDescription.displayName = 'AlertDescription';

export { Alert, AlertTitle, AlertDescription, alertVariants };
