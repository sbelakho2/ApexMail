'use client';

import * as React from 'react';
import * as SwitchPrimitive from '@radix-ui/react-switch';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const switchVariants = cva(
  'peer inline-flex shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 hover:opacity-90 active:scale-95 duration-200',
  {
    variants: {
      variant: {
        default:
          'data-[state=checked]:bg-primary data-[state=unchecked]:bg-muted shadow-inner',
        success:
          'data-[state=checked]:bg-success data-[state=unchecked]:bg-muted shadow-inner',
        destructive:
          'data-[state=checked]:bg-destructive data-[state=unchecked]:bg-muted shadow-inner',
      },
      size: {
        sm: 'h-4 w-7',
        default: 'h-6 w-11',
        lg: 'h-7 w-14',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

const switchThumbVariants = cva(
  'pointer-events-none block rounded-full bg-background ring-0 transition-transform shadow-md',
  {
    variants: {
      size: {
        sm: 'h-3 w-3 data-[state=checked]:translate-x-3 data-[state=unchecked]:translate-x-0',
        default: 'h-5 w-5 data-[state=checked]:translate-x-5 data-[state=unchecked]:translate-x-0',
        lg: 'h-6 w-6 data-[state=checked]:translate-x-7 data-[state=unchecked]:translate-x-0',
      },
    },
    defaultVariants: {
      size: 'default',
    },
  }
);

export interface SwitchProps
 extends React.ComponentPropsWithoutRef<typeof SwitchPrimitive.Root>,
 VariantProps<typeof switchVariants> {}

const Switch = React.forwardRef<
 React.ElementRef<typeof SwitchPrimitive.Root>,
 SwitchProps
>(({ className, variant, size, ...props }, ref) => (
 <SwitchPrimitive.Root
 className={cn(switchVariants({ variant, size, className }))}
 {...props}
 ref={ref}
 >
 <SwitchPrimitive.Thumb className={cn(switchThumbVariants({ size }))} />
 </SwitchPrimitive.Root>
));
Switch.displayName = SwitchPrimitive.Root.displayName;

export { Switch, switchVariants };
