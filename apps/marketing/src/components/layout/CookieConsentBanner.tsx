'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

const CONSENT_KEY = 'apexmail_cookie_consent';

export function CookieConsentBanner() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const saved = window.localStorage.getItem(CONSENT_KEY);
    setVisible(saved !== 'accepted');
  }, []);

  if (!visible) return null;

  return (
    <div className="fixed inset-x-0 bottom-0 z-50 border-t border-surface-200 bg-surface-50/95 backdrop-blur px-4 py-3">
      <div className="mx-auto flex max-w-6xl flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-surface-600">
          We use essential cookies and privacy-friendly analytics to improve ApexMail.
          See our{' '}
          <Link href="/cookies" className="font-semibold text-surface-900 underline">
            Cookie Policy
          </Link>
          .
        </p>
        <button
          type="button"
          onClick={() => {
            window.localStorage.setItem(CONSENT_KEY, 'accepted');
            setVisible(false);
          }}
          className="btn-primary px-4 py-2 text-sm"
        >
          Accept
        </button>
      </div>
    </div>
  );
}
