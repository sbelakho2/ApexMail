'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

interface AuthErrorShape {
  error?: string;
  errorCode?: string;
}

export function useLoginController() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [authErrorKey, setAuthErrorKey] = useState('');
  const [csrfError, setCsrfError] = useState('');
  const [online, setOnline] = useState(true);
  const [retryAfterSeconds, setRetryAfterSeconds] = useState(0);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [lockoutMessage, setLockoutMessage] = useState('');
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [capsLockOn, setCapsLockOn] = useState(false);
  const [ssoLoading, setSsoLoading] = useState<'google' | 'github' | null>(null);
  const [failedAttempts, setFailedAttempts] = useState(0);

  const returnTo = (() => {
    const next = searchParams.get('next');
    if (!next || !next.startsWith('/')) return '/dashboard';
    return next;
  })();

  const validateEmail = (value: string) => {
    if (!value.trim()) return 'Email is required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Enter a valid email address';
    return '';
  };

  const validatePassword = (value: string) => {
    if (!value.trim()) return 'Password is required';
    if (value.length < 8) return 'Password must be at least 8 characters';
    return '';
  };

  const getNetworkClass = () => {
    if (typeof navigator === 'undefined') return 'unknown';
    const nav = navigator as Navigator & { connection?: unknown };
    if (!nav.connection || typeof nav.connection !== 'object') return 'unknown';
    const effectiveType = (nav.connection as { effectiveType?: unknown }).effectiveType;
    return typeof effectiveType === 'string' ? effectiveType : 'unknown';
  };

  const reportAuthTelemetry = async (reason: string, status?: number) => {
    try {
      await fetch('/api/auth/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason,
          status,
          networkClass: typeof navigator === 'undefined' ? 'unknown' : getNetworkClass(),
          at: Date.now(),
        }),
        keepalive: true,
      });
    } catch {
      // non-blocking telemetry
    }
  };

  const mapAuthError = (status: number, data: AuthErrorShape) => {
    if (status === 429) {
      return { key: 'auth.error.rate_limited', message: 'Too many sign-in attempts. Please wait and try again.' };
    }

    if (status === 423 || data.errorCode === 'ACCOUNT_LOCKED') {
      return { key: 'auth.error.locked', message: 'Your account is temporarily locked. Reset your password or contact support to regain access.' };
    }

    if (data.errorCode === 'MFA_REQUIRED') {
      return { key: 'auth.error.mfa_required', message: 'Additional verification required. Enter your MFA code.' };
    }

    if (status === 401 || status === 400 || data.errorCode === 'INVALID_CREDENTIALS') {
      return { key: 'auth.error.invalid_credentials', message: 'Incorrect email, password, or verification code.' };
    }

    return { key: 'auth.error.generic', message: 'We could not sign you in. Please try again.' };
  };

  const loadCsrfToken = async () => {
    setCsrfError('');
    try {
      const res = await fetch('/api/csrf');
      const data = await res.json();
      setCsrfToken(data.token || null);
    } catch {
      setCsrfError('Unable to initialize security token.');
    }
  };

  useEffect(() => {
    setOnline(typeof navigator === 'undefined' ? true : navigator.onLine);
    loadCsrfToken();

    const checkSession = async () => {
      try {
        const res = await fetch('/api/auth/session', { cache: 'no-store' });
        if (!res.ok) return;
        const data = await res.json();
        if (data?.authenticated) {
          router.replace(returnTo);
        }
      } catch {
        // ignore redirect guard failures
      }
    };

    checkSession();

    const onOnline = () => setOnline(true);
    const onOffline = () => setOnline(false);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);

    const csrfRefreshInterval = window.setInterval(() => {
      loadCsrfToken();
    }, 10 * 60 * 1000);

    return () => {
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
      window.clearInterval(csrfRefreshInterval);
    };
  }, [router, returnTo]);

  useEffect(() => {
    if (retryAfterSeconds <= 0) return;
    const timer = window.setInterval(() => {
      setRetryAfterSeconds((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [retryAfterSeconds]);

  useEffect(() => {
    const reason = searchParams.get('reason');
    if (reason === 'session_expired') {
      setError('Your session expired. Please sign in again.');
      setAuthErrorKey('auth.error.session_expired');
    }
  }, [searchParams]);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setAuthErrorKey('');
    setLockoutMessage('');

    if (!online) {
      setError('You appear to be offline. Reconnect and try again.');
      setAuthErrorKey('auth.error.offline');
      reportAuthTelemetry('offline');
      setIsLoading(false);
      return;
    }

    if (retryAfterSeconds > 0) {
      setError(`Too many attempts. Try again in ${retryAfterSeconds}s.`);
      setAuthErrorKey('auth.error.rate_limited');
      reportAuthTelemetry('rate_limited_active');
      setIsLoading(false);
      return;
    }

    if (!csrfToken) {
      setCsrfError('Security token missing. Retry initialization below.');
      setAuthErrorKey('auth.error.csrf_missing');
      reportAuthTelemetry('csrf_missing');
      setIsLoading(false);
      return;
    }

    const nextEmailError = validateEmail(email);
    const nextPasswordError = validatePassword(password);
    setEmailError(nextEmailError);
    setPasswordError(nextPasswordError);
    if (nextEmailError || nextPasswordError) {
      setAuthErrorKey('auth.error.validation');
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ email, password, mfaCode: mfaCode || undefined, rememberMe }),
        credentials: 'include',
      });

      const data = await response.json();

      if (response.status === 429) {
        const retryAfter = Number.parseInt(response.headers.get('Retry-After') || '30', 10);
        setRetryAfterSeconds(Number.isNaN(retryAfter) ? 30 : retryAfter);
        const mapped = mapAuthError(response.status, data || {});
        setError(mapped.message);
        setAuthErrorKey(mapped.key);
        setFailedAttempts((prev) => prev + 1);
        reportAuthTelemetry('rate_limited_response', response.status);
        setIsLoading(false);
        return;
      }

      if (data?.requiresMfa || data?.errorCode === 'MFA_REQUIRED') {
        setMfaRequired(true);
        const mapped = mapAuthError(response.status, data || {});
        setError(mapped.message);
        setAuthErrorKey(mapped.key);
        reportAuthTelemetry('mfa_required', response.status);
        setIsLoading(false);
        return;
      }

      if (!response.ok) {
        const mapped = mapAuthError(response.status, data || {});

        if (mapped.key === 'auth.error.locked') {
          setLockoutMessage(mapped.message);
        }

        setError(mapped.message);
        setAuthErrorKey(mapped.key);
        setFailedAttempts((prev) => prev + 1);
        reportAuthTelemetry(mapped.key, response.status);
        setIsLoading(false);
        return;
      }

      setFailedAttempts(0);
      router.push(returnTo);
    } catch {
      setError('Network error. Please try again.');
      setAuthErrorKey('auth.error.network');
      setFailedAttempts((prev) => prev + 1);
      reportAuthTelemetry('network_error');
      setIsLoading(false);
    }
  };

  return {
    isLoading,
    error,
    authErrorKey,
    csrfError,
    online,
    retryAfterSeconds,
    mfaRequired,
    mfaCode,
    setMfaCode,
    rememberMe,
    setRememberMe,
    lockoutMessage,
    csrfToken,
    email,
    setEmail,
    password,
    setPassword,
    emailError,
    setEmailError,
    passwordError,
    setPasswordError,
    showPassword,
    setShowPassword,
    capsLockOn,
    setCapsLockOn,
    ssoLoading,
    setSsoLoading,
    failedAttempts,
    returnTo,
    loadCsrfToken,
    handleSubmit,
    validateEmail,
    validatePassword,
  };
}
