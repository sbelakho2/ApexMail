'use client';

import { useEffect, useMemo } from 'react';
import Script from 'next/script';

type MCaptchaWidgetProps = {
    token: string;
    onTokenChange: (token: string) => void;
    error?: string;
};

const glueScriptSrc = process.env.NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL
    || 'https://unpkg.com/@mcaptcha/vanilla-glue@0.1.0-rc2/dist/index.js';

export function MCaptchaWidget({ token, onTokenChange, error }: MCaptchaWidgetProps) {
    const widgetUrl = process.env.NEXT_PUBLIC_MCAPTCHA_WIDGET_URL?.trim() || '';
    const enabled = process.env.NEXT_PUBLIC_MCAPTCHA_ENABLED === 'true' && widgetUrl.length > 0;

    const tokenInputId = useMemo(() => 'mcaptcha__token', []);
    const tokenLabelId = useMemo(() => 'mcaptcha__token-label', []);
    const widgetContainerId = useMemo(() => 'mcaptcha__widget-container', []);

    useEffect(() => {
        if (!enabled) {
            return;
        }

        const input = document.getElementById(tokenInputId) as HTMLInputElement | null;
        if (!input) {
            return;
        }

        const syncToken = () => {
            const nextToken = input.value?.trim() || '';
            if (nextToken !== token) {
                onTokenChange(nextToken);
            }
        };

        syncToken();
        input.addEventListener('input', syncToken);
        const poll = window.setInterval(syncToken, 250);

        return () => {
            input.removeEventListener('input', syncToken);
            window.clearInterval(poll);
        };
    }, [enabled, token, onTokenChange, tokenInputId]);

    if (!enabled) {
        return null;
    }

    return (
        <div className="space-y-2">
            <label
                data-mcaptcha_url={widgetUrl}
                htmlFor={tokenInputId}
                id={tokenLabelId}
                className="sr-only"
            >
                mCaptcha authorization token.
            </label>
            <input
                type="text"
                name="mcaptcha__token"
                id={tokenInputId}
                value={token}
                onChange={(event) => onTokenChange(event.target.value)}
                className="sr-only"
                aria-hidden="true"
                tabIndex={-1}
            />
            <div
                id={widgetContainerId}
                className="min-h-[84px] rounded-xl border border-input bg-card p-2"
            />
            {error ? <p className="text-xs text-destructive" role="alert">{error}</p> : null}
            <Script id="mcaptcha-vanilla-glue" src={glueScriptSrc} strategy="afterInteractive" />
        </div>
    );
}