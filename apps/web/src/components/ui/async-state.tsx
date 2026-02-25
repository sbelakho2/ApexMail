import * as React from 'react';
import { AlertCircle, Inbox } from '@/components/ui/icons';
import { EmptyState } from '@/components/ui/empty-state';
import { Spinner } from '@/components/ui/spinner';

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
    <div className="flex items-center justify-center min-h-[320px]">
      <div className="flex flex-col items-center gap-3">
        <Spinner size="lg" variant="muted" aria-hidden="true" />
        <p className="text-sm text-muted-foreground font-medium">{label}</p>
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
    <EmptyState
      icon={AlertCircle}
      title={title}
      description={description}
      action={onRetry ? { label: retryLabel, onClick: onRetry } : undefined}
      className="min-h-[320px]"
    />
  );
}

export function PageEmptyState({ title, description, action }: PageEmptyStateProps) {
  return (
    <EmptyState
      icon={Inbox}
      title={title}
      description={description}
      action={action}
      className="min-h-[220px]"
    />
  );
}
