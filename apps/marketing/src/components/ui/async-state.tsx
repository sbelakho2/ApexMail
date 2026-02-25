import * as React from 'react';
import { AlertCircle, Inbox, Loader2 } from '@/components/ui/icons';
import { Button } from '@/components/ui/button';

interface PageLoadingStateProps {
  label?: string;
}

interface PageErrorStateProps {
  title?: string;
  description?: string;
  retryLabel?: string;
  onRetry?: () => void;
}

interface PageEmptyStateProps {
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export function PageLoadingState({ label = 'Loading...' }: PageLoadingStateProps) {
  return (
    <div className="min-h-[320px] flex items-center justify-center">
      <div className="flex flex-col items-center gap-3 text-center">
        <Loader2 className="w-8 h-8 animate-spin text-surface-500" aria-hidden="true" />
        <p className="text-sm font-semibold text-surface-600">{label}</p>
      </div>
    </div>
  );
}

export function PageErrorState({
  title = 'Something went wrong',
  description,
  retryLabel = 'Retry',
  onRetry,
}: PageErrorStateProps) {
  return (
    <div className="min-h-[320px] flex items-center justify-center">
      <div className="max-w-md px-6 text-center space-y-3">
        <div className="mx-auto w-12 h-12 rounded-full bg-red-50 border border-red-100 flex items-center justify-center">
          <AlertCircle className="w-6 h-6 text-red-500" />
        </div>
        <h3 className="text-lg font-bold text-surface-900">{title}</h3>
        {description ? <p className="text-sm text-surface-600">{description}</p> : null}
        {onRetry ? (
          <Button
            onClick={onRetry}
            variant="outline"
            size="md"
          >
            {retryLabel}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

export function PageEmptyState({ title, description, action }: PageEmptyStateProps) {
  return (
    <div className="min-h-[220px] flex items-center justify-center">
      <div className="max-w-md px-6 text-center space-y-3">
        <div className="mx-auto w-12 h-12 rounded-full bg-surface-50 border border-surface-200 flex items-center justify-center">
          <Inbox className="w-6 h-6 text-surface-500" />
        </div>
        <h3 className="text-lg font-bold text-surface-900">{title}</h3>
        {description ? <p className="text-sm text-surface-600">{description}</p> : null}
        {action ? (
          <Button
            onClick={action.onClick}
            variant="outline"
            size="md"
          >
            {action.label}
          </Button>
        ) : null}
      </div>
    </div>
  );
}
