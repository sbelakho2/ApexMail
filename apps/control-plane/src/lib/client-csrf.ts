let cachedCsrfToken: string | null = null;
let csrfTokenPromise: Promise<string | null> | null = null;
let csrfTokenFetchedAt = 0;

const CSRF_TTL_MS = 90 * 60 * 1000; // 90 minutes

export function clearCsrfToken() {
    cachedCsrfToken = null;
    csrfTokenPromise = null;
    csrfTokenFetchedAt = 0;
}

export async function getCsrfToken(): Promise<string | null> {
    if (cachedCsrfToken && (Date.now() - csrfTokenFetchedAt) < CSRF_TTL_MS) {
        return cachedCsrfToken;
    }

    // Token expired or missing — refetch
    cachedCsrfToken = null;

    if (!csrfTokenPromise) {
        csrfTokenPromise = fetch('/api/csrf', { credentials: 'include' })
            .then(async (response) => {
                if (!response.ok) return null;
                const payload = await response.json() as { token?: string };
                cachedCsrfToken = payload.token ?? null;
                csrfTokenFetchedAt = Date.now();
                return cachedCsrfToken;
            })
            .catch(() => null)
            .finally(() => {
                csrfTokenPromise = null;
            });
    }

    return csrfTokenPromise;
}
