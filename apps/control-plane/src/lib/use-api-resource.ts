'use client';

import { useCallback, useEffect, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';

interface UseApiResourceOptions<T> {
    initialData: T;
    credentials?: RequestCredentials;
    errorMessage?: string;
}

interface UseApiResourceResult<T> {
    data: T;
    setData: Dispatch<SetStateAction<T>>;
    loading: boolean;
    error: string | null;
    setError: Dispatch<SetStateAction<string | null>>;
    refetch: () => Promise<void>;
}

export function useApiResource<T>(url: string, options: UseApiResourceOptions<T>): UseApiResourceResult<T> {
    const {
        initialData,
        credentials = 'include',
        errorMessage = 'Failed to load data.',
    } = options;

    const [data, setData] = useState<T>(initialData);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const refetch = useCallback(async () => {
        try {
            setError(null);
            const response = await fetch(url, { credentials });
            if (!response.ok) {
                throw new Error(`Request failed: ${response.status}`);
            }
            const payload = await response.json() as T;
            setData(payload);
        } catch {
            setError(errorMessage);
        } finally {
            setLoading(false);
        }
    }, [credentials, errorMessage, url]);

    useEffect(() => {
        void refetch();
    }, [refetch]);

    return { data, setData, loading, error, setError, refetch };
}
