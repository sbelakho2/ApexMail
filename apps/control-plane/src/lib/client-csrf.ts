let cachedCsrfToken: string | null = null;
let csrfTokenPromise: Promise<string | null> | null = null;

export async function getCsrfToken(): Promise<string | null> {
    if (cachedCsrfToken) {
        return cachedCsrfToken;
    }

    if (!csrfTokenPromise) {
        csrfTokenPromise = fetch('/api/csrf', { credentials: 'include' })
            .then(async (response) => {
                if (!response.ok) return null;
                const payload = await response.json() as { token?: string };
                cachedCsrfToken = payload.token ?? null;
                return cachedCsrfToken;
            })
            .catch(() => null)
            .finally(() => {
                csrfTokenPromise = null;
            });
    }

    return csrfTokenPromise;
}
