import * as React from 'react';
import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center py-12 px-6 text-center animate-in fade-in zoom-in-95 duration-500',
        className
      )}
    >
      {Icon && (
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted/50 border border-border/50">
          <Icon className="h-8 w-8 text-muted-foreground/60" strokeWidth={1.5} />
        </div>
      )}
      <h3 className="text-[17px] font-bold text-foreground mb-2">{title}</h3>
      {description && (
        <p className="mx-auto max-w-[320px] text-sm text-muted-foreground leading-relaxed">
          {description}
        </p>
      )}
      {action && (
        <Button
          onClick={action.onClick}
          variant="outline"
          size="sm"
          className="mt-6 font-semibold"
        >
          {action.label}
        </Button>
      )}
    </div>
  );
}
