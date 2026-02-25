'use client';

import { useEffect } from 'react';
import { PageErrorState } from '@/components/ui/async-state';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('[Marketing Error]', error);
  }, [error]);

  return (
    <PageErrorState
      title="Something went wrong"
      description="We couldn't load this page right now. Please retry."
      onRetry={reset}
    />
  );
}
