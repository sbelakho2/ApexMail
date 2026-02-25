import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center rounded-md font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/30 disabled:opacity-60 disabled:cursor-not-allowed',
  {
    variants: {
      variant: {
        default: 'bg-brand-500 border border-brand-500 text-white hover:bg-brand-600',
        outline: 'bg-white border border-surface-200 text-surface-900 hover:bg-surface-50',
        ghost: 'text-surface-700 hover:text-surface-900 hover:bg-surface-50',
      },
      size: {
        sm: 'min-h-[44px] px-3 py-2 text-sm',
        md: 'min-h-[44px] px-4 py-2.5 text-sm',
        lg: 'min-h-[44px] px-6 py-3 text-sm',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'md',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export function Button({ className, variant, size, ...props }: ButtonProps) {
  return <button className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}
