import * as React from 'react';
import { AlertTriangle, Inbox, Loader2 } from './icons';
import { Button } from './button';

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
            <div className="flex flex-col items-center gap-3 text-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
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
        <div className="min-h-[320px] flex items-center justify-center">
            <div className="max-w-md text-center space-y-3 px-6">
                <div className="mx-auto w-12 h-12 rounded-full bg-destructive/10 border border-destructive/20 flex items-center justify-center">
                    <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <h3 className="text-lg font-semibold text-foreground">{title}</h3>
                {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
                {onRetry ? (
                    <Button
                        onClick={onRetry}
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
            <div className="max-w-md text-center space-y-3 px-6">
                <div className="mx-auto w-12 h-12 rounded-full bg-muted border border-border flex items-center justify-center">
                    <Inbox className="h-6 w-6 text-muted-foreground" />
                </div>
                <h3 className="text-lg font-semibold text-foreground">{title}</h3>
                {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
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
