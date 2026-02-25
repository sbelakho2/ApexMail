'use client';

import React from 'react';

interface Props {
  fallback?: React.ReactNode;
  demoName?: string;
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

/**
 * Error boundary for interactive marketing demos.
 * When a demo component throws (e.g. DOMPurify not available, framer-motion
 * SSR issues, or a third-party script failure), we fall back to a minimal
 * static description instead of crashing the whole page.
 */
export class DemoErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Log to console in dev; in production this would go to an observability sink
    if (process.env.NODE_ENV !== 'production') {
      console.warn(`[DemoErrorBoundary] Demo "${this.props.demoName ?? 'unknown'}" crashed:`, error, info);
    }
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div
          role="status"
          aria-label="Interactive demo unavailable"
          className="flex flex-col items-center justify-center py-16 px-6 bg-surface-50 border border-surface-200 rounded-lg text-center"
        >
          <div className="w-10 h-10 rounded-full bg-surface-100 border border-surface-200 flex items-center justify-center mb-4">
            <span className="text-surface-400 text-lg" aria-hidden="true">⚐</span>
          </div>
          <h3 className="text-sm font-semibold text-surface-700 mb-1">
            {this.props.demoName ? `${this.props.demoName} demo` : 'Interactive demo'} unavailable
          </h3>
          <p className="text-xs text-surface-500 max-w-xs">
            This interactive feature could not load.{' '}
            <a href="/docs" className="text-primary-600 underline hover:text-primary-700">
              Browse our documentation
            </a>{' '}
            or{' '}
            <a href="/signup" className="text-primary-600 underline hover:text-primary-700">
              sign up to try the real API
            </a>.
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}
