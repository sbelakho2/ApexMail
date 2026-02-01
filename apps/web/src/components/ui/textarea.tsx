import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const textareaVariants = cva(
    'flex min-h-[80px] w-full rounded-md border bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
    {
        variants: {
            variant: {
                default: 'border-input',
                error: 'border-destructive focus-visible:ring-destructive',
                success: 'border-success focus-visible:ring-success',
            },
            resize: {
                none: 'resize-none',
                vertical: 'resize-y',
                horizontal: 'resize-x',
                both: 'resize',
            },
        },
        defaultVariants: {
            variant: 'default',
            resize: 'vertical',
        },
    }
);

export interface TextareaProps
    extends React.TextareaHTMLAttributes<HTMLTextAreaElement>,
        VariantProps<typeof textareaVariants> {
    maxLength?: number;
    showCount?: boolean;
}

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
    ({ className, variant, resize, maxLength, showCount, value, ...props }, ref) => {
        const [charCount, setCharCount] = React.useState(
            typeof value === 'string' ? value.length : 0
        );

        const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
            setCharCount(e.target.value.length);
            props.onChange?.(e);
        };

        return (
            <div className="relative">
                <textarea
                    className={cn(textareaVariants({ variant, resize, className }))}
                    ref={ref}
                    maxLength={maxLength}
                    value={value}
                    onChange={handleChange}
                    {...props}
                />
                {showCount && maxLength && (
                    <span className="absolute bottom-2 right-2 text-xs text-muted-foreground">
                        {charCount}/{maxLength}
                    </span>
                )}
            </div>
        );
    }
);
Textarea.displayName = 'Textarea';

export { Textarea, textareaVariants };
