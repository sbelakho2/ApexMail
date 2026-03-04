'use client';

import { useEffect } from 'react';

function reportClientError(error: Error & { digest?: string }) {
    const payload = {
        message: error.message,
        digest: error.digest,
        stack: error.stack,
        timestamp: new Date().toISOString(),
        path: typeof window !== 'undefined' ? window.location.pathname : undefined,
    };

    if (process.env.NODE_ENV !== 'production') {
        console.error('[ApexMail Error]', payload);
        return;
    }

    try {
        const serialized = JSON.stringify(payload);
        if (navigator.sendBeacon) {
            navigator.sendBeacon('/v1/client-errors', serialized);
            return;
        }
        void fetch('/v1/client-errors', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: serialized,
            keepalive: true,
        });
    } catch {
        // swallow reporting failures
    }
}

export default function GlobalError({
    error,
    reset,
}: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    useEffect(() => {
        reportClientError(error);
    }, [error]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <div className="max-w-md w-full bg-card border border-border rounded-xl p-8 text-center">
                <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg
                        className="w-8 h-8 text-destructive"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                    >
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                        />
                    </svg>
                </div>
                <h2 className="text-xl font-semibold text-foreground mb-2">
                    Something went wrong
                </h2>
                <p className="text-sm text-muted-foreground mb-6">
                    An unexpected error occurred. Please try again or contact support if the problem persists.
                </p>
                {error.digest && (
                    <p className="text-xs text-muted-foreground mb-4 font-mono">
                        Error ID: {error.digest}
                    </p>
                )}
                <div className="flex gap-3 justify-center">
                    <button
                        onClick={reset}
                        className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
                    >
                        Try Again
                    </button>
                    <button
                        onClick={() => window.location.href = '/'}
                        className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg text-sm font-medium hover:bg-secondary/80 transition-colors"
                    >
                        Go Home
                    </button>
                </div>
            </div>
        </div>
    );
}
