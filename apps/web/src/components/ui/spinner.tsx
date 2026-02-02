'use client';

import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const spinnerVariants = cva(
 'animate-spin',
 {
 variants: {
 size: {
 xs: 'h-3 w-3',
 sm: 'h-4 w-4',
 default: 'h-6 w-6',
 lg: 'h-8 w-8',
 xl: 'h-12 w-12',
 },
 variant: {
 default: 'text-primary',
 muted: 'text-muted-foreground',
 white: 'text-white',
 },
 },
 defaultVariants: {
 size: 'default',
 variant: 'default',
 },
 }
);

export interface SpinnerProps
 extends Omit<React.ComponentPropsWithoutRef<'svg'>, 'ref'>,
 VariantProps<typeof spinnerVariants> {}

const Spinner = React.forwardRef<SVGSVGElement, SpinnerProps>(
 ({ className, size, variant, ...props }, ref) => (
 <svg
 ref={ref}
 className={cn(spinnerVariants({ size, variant, className }))}
 xmlns="http://www.w3.org/2000/svg"
 fill="none"
 viewBox="0 0 24 24"
 {...props}
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
 )
);
Spinner.displayName = 'Spinner';

// Skeleton component for loading states
const skeletonVariants = cva(
  'animate-pulse rounded-md bg-surface-100',
  {
    variants: {
      variant: {
        default: 'bg-surface-100',
        card: 'bg-surface-200/50 rounded-xl',
        text: 'h-4 w-full rounded-md',
        circle: 'rounded-full',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export interface SkeletonProps
 extends React.HTMLAttributes<HTMLDivElement>,
 VariantProps<typeof skeletonVariants> {}

function Skeleton({ className, variant, ...props }: SkeletonProps) {
 return (
 <div
 className={cn(skeletonVariants({ variant, className }))}
 {...props}
 />
 );
}

// Full page loading overlay
interface LoadingOverlayProps {
 isLoading?: boolean;
 text?: string;
 children?: React.ReactNode;
}

function LoadingOverlay({ isLoading = true, text, children }: LoadingOverlayProps) {
  if (!isLoading) return <>{children}</>;

  return (
    <div className="relative">
      {children && <div className="opacity-50 pointer-events-none blur-sm transition-all duration-300">{children}</div>}
      <div className="absolute inset-0 flex flex-col items-center justify-center bg-white/50 backdrop-blur-sm z-50 rounded-xl transition-all duration-300">
        <div className="premium-card p-4 rounded-full shadow-lg bg-white">
            <Spinner size="lg" />
        </div>
        {text && <p className="mt-4 text-[13px] font-bold uppercase tracking-widest text-surface-500">{text}</p>}
      </div>
    </div>
  );
}

export { Spinner, Skeleton, LoadingOverlay, spinnerVariants, skeletonVariants };
