'use client';

import * as React from 'react';
import * as AvatarPrimitive from '@radix-ui/react-avatar';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const avatarVariants = cva(
  'relative flex shrink-0 overflow-hidden rounded-lg border border-surface-200 shadow-sm',
  {
    variants: {
      size: {
        xs: 'h-6 w-6 rounded-md',
        sm: 'h-8 w-8 rounded-md',
        default: 'h-10 w-10 rounded-lg',
        lg: 'h-12 w-12 rounded-lg',
        xl: 'h-16 w-16 rounded-xl',
        '2xl': 'h-20 w-20 rounded-2xl',
      },
      status: {
        none: '',
        online: 'ring-2 ring-success ring-offset-2 ring-offset-background',
        offline: 'ring-2 ring-muted ring-offset-2 ring-offset-background',
        busy: 'ring-2 ring-error ring-offset-2 ring-offset-background',
        away: 'ring-2 ring-warning ring-offset-2 ring-offset-background',
      },
    },
    defaultVariants: {
      size: 'default',
      status: 'none',
    },
  }
);

export interface AvatarProps
 extends React.ComponentPropsWithoutRef<typeof AvatarPrimitive.Root>,
 VariantProps<typeof avatarVariants> {}

const Avatar = React.forwardRef<
 React.ElementRef<typeof AvatarPrimitive.Root>,
 AvatarProps
>(({ className, size, status, ...props }, ref) => (
 <AvatarPrimitive.Root
 ref={ref}
 className={cn(avatarVariants({ size, status, className }))}
 {...props}
 />
));
Avatar.displayName = AvatarPrimitive.Root.displayName;

const AvatarImage = React.forwardRef<
 React.ElementRef<typeof AvatarPrimitive.Image>,
 React.ComponentPropsWithoutRef<typeof AvatarPrimitive.Image>
>(({ className, ...props }, ref) => (
 <AvatarPrimitive.Image
 ref={ref}
 className={cn('aspect-square h-full w-full object-cover', className)}
 {...props}
 />
));
AvatarImage.displayName = AvatarPrimitive.Image.displayName;

const AvatarFallback = React.forwardRef<
  React.ElementRef<typeof AvatarPrimitive.Fallback>,
  React.ComponentPropsWithoutRef<typeof AvatarPrimitive.Fallback>
>(({ className, ...props }, ref) => (
  <AvatarPrimitive.Fallback
    ref={ref}
    className={cn(
      'flex h-full w-full items-center justify-center bg-surface-100 text-surface-600 font-bold text-xs uppercase tracking-wide',
      className
    )}
    {...props}
  />
));
AvatarFallback.displayName = AvatarPrimitive.Fallback.displayName;

interface AvatarGroupProps extends React.HTMLAttributes<HTMLDivElement> {
 max?: number;
 size?: AvatarProps['size'];
}

const AvatarGroup = React.forwardRef<HTMLDivElement, AvatarGroupProps>(
 ({ className, children, max = 4, size = 'default', ...props }, ref) => {
 const childrenArray = React.Children.toArray(children);
 const visibleChildren = max ? childrenArray.slice(0, max) : childrenArray;
 const remainingCount = max ? Math.max(childrenArray.length - max, 0) : 0;

 return (
 <div
 ref={ref}
 className={cn('flex -space-x-2', className)}
 {...props}
 >
 {visibleChildren.map((child, index) => {
 if (React.isValidElement<AvatarProps>(child)) {
 return React.cloneElement(child, {
 key: index,
 size,
 className: cn(
 'ring-2 ring-background',
 child.props.className
 ),
 });
 }
 return child;
 })}
 {remainingCount > 0 && (
 <Avatar size={size} className="ring-2 ring-background">
 <AvatarFallback className="bg-muted text-muted-foreground">
 +{remainingCount}
 </AvatarFallback>
 </Avatar>
 )}
 </div>
 );
 }
);
AvatarGroup.displayName = 'AvatarGroup';

export { Avatar, AvatarImage, AvatarFallback, AvatarGroup, avatarVariants };
