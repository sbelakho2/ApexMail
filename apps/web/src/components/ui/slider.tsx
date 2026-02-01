'use client';

import * as React from 'react';
import * as SliderPrimitive from '@radix-ui/react-slider';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const sliderVariants = cva(
    'relative flex w-full touch-none select-none items-center',
    {
        variants: {
            size: {
                sm: '',
                default: '',
                lg: '',
            },
        },
        defaultVariants: {
            size: 'default',
        },
    }
);

const sliderTrackVariants = cva(
    'relative w-full grow overflow-hidden rounded-full bg-secondary',
    {
        variants: {
            size: {
                sm: 'h-1',
                default: 'h-2',
                lg: 'h-3',
            },
        },
        defaultVariants: {
            size: 'default',
        },
    }
);

const sliderRangeVariants = cva(
    'absolute h-full',
    {
        variants: {
            variant: {
                default: 'bg-primary',
                success: 'bg-success',
                warning: 'bg-warning',
                error: 'bg-destructive',
            },
        },
        defaultVariants: {
            variant: 'default',
        },
    }
);

const sliderThumbVariants = cva(
    'block rounded-full border-2 border-primary bg-background ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
    {
        variants: {
            size: {
                sm: 'h-3 w-3',
                default: 'h-5 w-5',
                lg: 'h-6 w-6',
            },
        },
        defaultVariants: {
            size: 'default',
        },
    }
);

export interface SliderProps
    extends React.ComponentPropsWithoutRef<typeof SliderPrimitive.Root>,
        VariantProps<typeof sliderVariants>,
        VariantProps<typeof sliderRangeVariants> {
    showTooltip?: boolean;
}

const Slider = React.forwardRef<
    React.ElementRef<typeof SliderPrimitive.Root>,
    SliderProps
>(({ className, size, variant, showTooltip, ...props }, ref) => {
    const [showValue, setShowValue] = React.useState(false);
    
    return (
        <SliderPrimitive.Root
            ref={ref}
            className={cn(sliderVariants({ size, className }))}
            onPointerDown={() => setShowValue(true)}
            onPointerUp={() => setShowValue(false)}
            {...props}
        >
            <SliderPrimitive.Track className={cn(sliderTrackVariants({ size }))}>
                <SliderPrimitive.Range className={cn(sliderRangeVariants({ variant }))} />
            </SliderPrimitive.Track>
            {(props.value || props.defaultValue || [0]).map((_, index) => (
                <SliderPrimitive.Thumb
                    key={index}
                    className={cn(sliderThumbVariants({ size }), 'relative')}
                >
                    {showTooltip && showValue && (
                        <span className="absolute -top-8 left-1/2 -translate-x-1/2 rounded bg-primary px-2 py-1 text-xs text-primary-foreground">
                            {(props.value || props.defaultValue)?.[index]}
                        </span>
                    )}
                </SliderPrimitive.Thumb>
            ))}
        </SliderPrimitive.Root>
    );
});
Slider.displayName = SliderPrimitive.Root.displayName;

export { Slider, sliderVariants };
