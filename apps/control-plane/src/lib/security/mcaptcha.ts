const DEFAULT_MCAPTCHA_VERIFY_URL = 'https://demo.mcaptcha.org/api/v1/pow/siteverify';

type VerifyResult =
  | { ok: true; skipped: boolean }
  | { ok: false; reason: 'missing' | 'invalid' | 'provider' | 'misconfigured' };

function isEnabled(): boolean {
    return process.env.MCAPTCHA_ENABLED === 'true';
}

function getConfig() {
    const siteKey = process.env.MCAPTCHA_SITE_KEY?.trim();
    const secret = process.env.MCAPTCHA_SECRET?.trim();
    const verifyUrl = process.env.MCAPTCHA_VERIFY_URL?.trim() || DEFAULT_MCAPTCHA_VERIFY_URL;

    return {
        siteKey,
        secret,
        verifyUrl,
    };
}

export async function verifyMCaptchaToken(token: string | undefined): Promise<VerifyResult> {
    if (!isEnabled()) {
        return { ok: true, skipped: true };
    }

    const { siteKey, secret, verifyUrl } = getConfig();
    if (!siteKey || !secret) {
        return { ok: false, reason: 'misconfigured' };
    }

    const normalizedToken = token?.trim();
    if (!normalizedToken) {
        return { ok: false, reason: 'missing' };
    }

    try {
        const response = await fetch(verifyUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                token: normalizedToken,
                key: siteKey,
                secret,
            }),
            signal: AbortSignal.timeout(5000),
        });

        if (!response.ok) {
            return { ok: false, reason: 'provider' };
        }

        const data = (await response.json()) as { valid?: unknown };
        if (data.valid === true) {
            return { ok: true, skipped: false };
        }

        return { ok: false, reason: 'invalid' };
    } catch {
        return { ok: false, reason: 'provider' };
    }
}