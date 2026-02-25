'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ArrowRight, CheckCircle2 } from '@/components/ui/icons';

/**
 * Customer Console Login Page
 * 
 * Main authentication page for ApexMail customers.
 * Uses global design tokens for Theme Lock compliance (6.5.3).
 * 
 * Features:
 * - Email/password authentication
 * - Social login placeholders (Google, GitHub)
 * - Password reset flow
 */
export default function LoginPage() {
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
    const connection = (navigator as Navigator & { connection?: { effectiveType?: string } }).connection;
    return connection?.effectiveType || 'unknown';
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

  const mapAuthError = (status: number, data: { error?: string; errorCode?: string }) => {
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
        const safeMessage = /exception|stack|trace|sql|internal|panic/i.test(data?.error || '')
          ? mapped.message
          : mapped.message;

        if (mapped.key === 'auth.error.locked') {
          setLockoutMessage(mapped.message);
        }

        setError(safeMessage);
        setAuthErrorKey(mapped.key);
        setFailedAttempts((prev) => prev + 1);
        reportAuthTelemetry(mapped.key, response.status);
        setIsLoading(false);
        return;
      }
      
      // Authentication successful - redirect to dashboard
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

  return (
    <div className="min-h-screen bg-surface-50 relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-32 left-1/2 h-72 w-[520px] -translate-x-1/2 rounded-full bg-brand-200/40 blur-3xl" />
        <div className="absolute -bottom-24 right-[-120px] h-72 w-72 rounded-full bg-brand-100/60 blur-3xl" />
      </div>
      <div className="relative mx-auto flex min-h-screen w-full max-w-6xl items-center px-6 py-12">
        <div className="grid w-full items-center gap-10 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="hidden lg:block">
            <div className="inline-flex items-center gap-2 rounded-full border border-brand-200/60 bg-white/80 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-brand-700">
              Console Access
            </div>
            <h1 className="mt-6 text-4xl font-semibold text-surface-900 tracking-tight">
              Your premium command center for delivery, trust, and analytics.
            </h1>
            <p className="mt-4 max-w-[520px] text-[16px] text-surface-600 leading-relaxed">
              Monitor every campaign, verify your domains, and spot deliverability risks before they impact your reputation.
            </p>
            <div className="mt-8 space-y-3 text-sm text-surface-600">
              {[
                'Real-time delivery intelligence across regions',
                'Enterprise-grade compliance workflows',
                'Executive-ready performance reporting',
              ].map((item) => (
                <div key={item} className="flex items-center gap-3">
                  <span className="flex h-7 w-7 items-center justify-center rounded-full bg-brand-100 text-brand-700">
                    <CheckCircle2 className="h-4 w-4" />
                  </span>
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="w-full">
            {/* Header */}
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/20 mb-6">
                <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                  <path d="M22 17a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9.5C2 7 4 5 5.5 5H18.5C20 5 22 7 22 9.5V17Z" />
                  <path d="M6 8L12 12L18 8" />
                </svg>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Welcome back
              </h1>
              <p className="text-sm text-muted-foreground mt-2 font-medium">
                Enter your credentials to access the console
              </p>
            </div>

            {/* Login Card */}
            <div className="bg-card rounded-3xl shadow-[0_24px_60px_rgba(15,23,42,0.15)] border border-surface-200/70 overflow-hidden">
          <form
            onSubmit={handleSubmit}
            aria-describedby={error || emailError || passwordError ? 'login-form-errors' : undefined}
            className="p-8 space-y-5"
          >
            {error || emailError || passwordError ? (
              <div id="login-form-errors" className="sr-only" role="alert" aria-live="assertive">
                {error ? `Form error: ${error}. ` : ''}
                {emailError ? `Email error: ${emailError}. ` : ''}
                {passwordError ? `Password error: ${passwordError}.` : ''}
              </div>
            ) : null}
            {error && (
              <div className="bg-destructive/10 border border-destructive/20 text-destructive text-sm rounded-lg p-3" data-state="error" data-error-key={authErrorKey || undefined}>
                {error}
                {authErrorKey ? <span className="sr-only">Error key: {authErrorKey}</span> : null}
              </div>
            )}
            {lockoutMessage ? (
              <div className="bg-warning/10 border border-warning/30 text-foreground text-sm rounded-lg p-3">
                {lockoutMessage}
              </div>
            ) : null}
            {!online ? (
              <div className="bg-warning/10 border border-warning/30 text-foreground text-sm rounded-lg p-3" role="status" aria-live="polite">
                You are offline. Login actions are paused until connection is restored.
              </div>
            ) : null}
            {csrfError ? (
              <div className="bg-warning/10 border border-warning/30 text-foreground text-sm rounded-lg p-3 flex items-center justify-between gap-3" role="alert">
                <span>{csrfError}</span>
                <button type="button" onClick={loadCsrfToken} className="text-primary font-semibold hover:underline">Retry</button>
              </div>
            ) : null}
            <div className="space-y-2">
              <label className="text-sm font-semibold text-foreground" htmlFor="email">
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                autoComplete="username"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => {
                  const value = e.target.value;
                  setEmail(value);
                  if (emailError) setEmailError(validateEmail(value));
                }}
                onBlur={() => setEmailError(validateEmail(email))}
                className="w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all placeholder:text-muted-foreground bg-white/90 text-sm font-medium text-foreground"
              />
              {emailError ? <p className="text-xs text-destructive" role="alert">{emailError}</p> : null}
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-semibold text-foreground" htmlFor="password">
                  Password
                </label>
                <Link 
                  href="/forgot-password" 
                  className="text-xs font-semibold text-primary hover:text-primary/80 hover:underline"
                >
                  Forgot password?
                </Link>
              </div>
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => {
                  const value = e.target.value;
                  setPassword(value);
                  if (passwordError) setPasswordError(validatePassword(value));
                }}
                onBlur={() => setPasswordError(validatePassword(password))}
                onKeyUp={(e) => setCapsLockOn(e.getModifierState('CapsLock'))}
                onKeyDown={(e) => setCapsLockOn(e.getModifierState('CapsLock'))}
                className="w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white/90 text-foreground"
              />
              <div className="flex items-center justify-between gap-3">
                {passwordError ? <p className="text-xs text-destructive" role="alert">{passwordError}</p> : <span />}
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="text-xs font-semibold text-primary hover:text-primary/80 hover:underline"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              {capsLockOn ? (
                <p className="text-xs text-warning" role="status" aria-live="polite">
                  Caps Lock is on
                </p>
              ) : null}
            </div>

            {mfaRequired ? (
              <div className="space-y-2">
                <label className="text-sm font-semibold text-foreground" htmlFor="mfaCode">MFA Code</label>
                <input
                  id="mfaCode"
                  name="mfaCode"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
                  className="w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white/90 text-foreground"
                />
              </div>
            ) : null}

            <div className="flex items-start gap-2">
              <input
                id="rememberMe"
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-surface-300 text-primary focus:ring-primary"
              />
              <label htmlFor="rememberMe" className="text-xs text-muted-foreground">
                Keep me signed in on this device for up to 30 days.
              </label>
            </div>

            <button
              type="submit"
              disabled={isLoading || !online || retryAfterSeconds > 0}
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 mt-2 transition-all"
            >
              {isLoading ? (
                <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>

            <div className="text-xs text-muted-foreground flex items-center justify-center gap-2" role="status" aria-live="polite">
              <span className={`inline-block h-2 w-2 rounded-full ${csrfToken ? 'bg-success' : 'bg-warning'}`} aria-hidden="true" />
              <span>{csrfToken ? 'Security check complete' : 'Security check pending'}</span>
            </div>

            {failedAttempts >= 3 ? (
              <p className="text-xs text-muted-foreground text-center">
                Need help signing in? <a href="mailto:support@apexmail.com" className="text-primary font-semibold hover:underline">Contact support</a>.
              </p>
            ) : null}
          </form>

          {/* Social / SSO */}
          <div className="px-8 pb-8">
            <div className="relative mb-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-border"></div>
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-3 text-muted-foreground font-semibold tracking-wider">
                  Or continue with
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => {
                  setSsoLoading('google');
                  window.location.href = `/api/auth/sso/google?next=${encodeURIComponent(returnTo)}`;
                }}
                disabled={isLoading || ssoLoading !== null}
                aria-label="Continue with Google"
                className="flex flex-wrap items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border hover:bg-accent hover:border-accent-foreground/10 transition-all"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                  <path d="M5.84 14.17c-.22-.66-.35-1.36-.35-2.17s.13-1.51.35-2.17V7.69H2.18C.79 10.45 0 13.63 0 17c0 3.37.79 6.55 2.18 9.31l3.66-2.84z" fill="#FBBC05"/>
                  <path d="M12 4.6c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.09 14.97 0 12 0 7.7 0 3.99 2.47 2.18 5.69l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                <span className="text-sm font-semibold text-foreground">
                  {ssoLoading === 'google' ? 'Redirecting…' : 'Google'}
                </span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setSsoLoading('github');
                  window.location.href = `/api/auth/sso/github?next=${encodeURIComponent(returnTo)}`;
                }}
                disabled={isLoading || ssoLoading !== null}
                aria-label="Continue with GitHub"
                className="flex flex-wrap items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border hover:bg-accent hover:border-accent-foreground/10 transition-all"
              >
                <svg className="w-5 h-5 text-foreground" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.03.555-3.885-1.425-3.885-1.425-.546-1.38-1.335-1.755-1.335-1.755-1.005-.69.075-.675.075-.675 1.11.075 1.695 1.14 1.695 1.14 1.005 1.725 2.64 1.23 3.285.945.105-.72.39-1.215.705-1.485-2.565-.285-5.265-1.29-5.265-5.73 0-1.26.45-2.295 1.185-3.09-.12-.285-.525-1.455.105-3.045 0 0 .96-.3 3.15 1.2A10.965 10.965 0 0 1 12 5.805c.9.015 1.785.12 2.64.24 2.19-1.5 3.15-1.2 3.15-1.2.63 1.59.225 2.76.105 3.045.735.795 1.185 1.83 1.185 3.09 0 4.455-2.715 5.43-5.295 5.715.39.345.735 1.02.735 2.055 0 1.485-.015 2.685-.015 3.045 0 .315.225.69.84.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12" />
                </svg>
                <span className="text-sm font-semibold text-foreground">
                  {ssoLoading === 'github' ? 'Redirecting…' : 'GitHub'}
                </span>
              </button>
            </div>

            <p className="mt-6 text-center text-xs text-muted-foreground">
              By signing in, you agree to our{' '}
              <Link href="/legal/terms" className="text-primary hover:underline">Terms</Link>{' '}
              and{' '}
              <Link href="/legal/privacy" className="text-primary hover:underline">Privacy Policy</Link>.
            </p>
          </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
