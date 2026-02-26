'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, ArrowRight, AlertTriangle, Lock } from '../../components/ui/icons';

/**
 * Control Plane Login Page
 * 
 * This is a SEPARATE authentication system from the customer login.
 * Only platform owners can access this.
 * 
 * Security Features:
 * - Rate limited login attempts
 * - MFA required for production
 * - Audit logging of all login attempts
 * - Session timeout after inactivity
 * 
 * Design: Uses global design tokens for Theme Lock compliance (6.5.3)
 */
export default function ControlPlaneLogin() {
    const router = useRouter();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState('');
    const [showMfa, setShowMfa] = useState(false);
    const [error, setError] = useState('');
    const [emailError, setEmailError] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [mfaError, setMfaError] = useState('');
    const [loading, setLoading] = useState(false);
    const [csrfToken, setCsrfToken] = useState<string | null>(null);

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

    const validateMfa = (value: string) => {
        if (!showMfa) return '';
        if (!value.trim()) return 'MFA code is required';
        if (!/^\d{6}$/.test(value)) return 'MFA code must be 6 digits';
        return '';
    };

    useEffect(() => {
        const controller = new AbortController();
        fetch('/api/csrf', { signal: controller.signal })
            .then((res) => res.json())
            .then((data) => {
                setCsrfToken(data.token || null);
            })
            .catch((err) => {
                if (err instanceof DOMException && err.name === 'AbortError') return;
                setError('Unable to initialize security token. Please refresh.');
            });

        return () => {
            controller.abort();
        };
    }, []);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        const nextEmailError = validateEmail(email);
        const nextPasswordError = validatePassword(password);
        const nextMfaError = validateMfa(mfaCode);
        setEmailError(nextEmailError);
        setPasswordError(nextPasswordError);
        setMfaError(nextMfaError);
        if (nextEmailError || nextPasswordError || nextMfaError) {
            setLoading(false);
            return;
        }

        if (!csrfToken) {
            setError('Security token missing. Please refresh and try again.');
            setLoading(false);
            return;
        }

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({ 
                    email, 
                    password,
                    mfaCode: showMfa ? mfaCode : undefined,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                if (data.requireMfa) {
                    setShowMfa(true);
                    setError('');
                } else {
                    setError(data.error || 'Login failed');
                }
                return;
            }

            // Success - redirect to dashboard
            router.push('/');
        } catch {
            setError('Network error. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex flex-col bg-background">
            {/* Control Plane Banner - Uses semantic control-plane-accent token */}
            <div className="bg-control-plane text-control-plane-foreground text-xs font-semibold py-1.5 px-4 text-center shadow-sm">
                <div className="flex items-center justify-center gap-2">
                    <Lock className="w-3.5 h-3.5" />
                    <span>ApexMail Control Plane — Restricted access</span>
                </div>
            </div>

            <div className="flex-1 flex items-center justify-center p-4">
                <div className="w-full max-w-[400px] space-y-6">
                    {/* Security Notice - Uses semantic warning/control-plane tokens */}
                    <div className="bg-warning/10 border border-warning/20 rounded-xl p-4 shadow-sm">
                        <div className="flex items-start gap-3">
                            <AlertTriangle className="w-5 h-5 text-warning mt-0.5 flex-shrink-0" />
                            <div>
                                <h3 className="font-semibold text-foreground text-sm">Restricted Access Area</h3>
                                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                                    Access is restricted to authorized platform administrators only. 
                                    All IP addresses and login attempts are logged and continuously monitored.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Header - Matches web app login */}
                    <div className="text-center">
                        <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/20 mb-6">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                                <path d="M22 17a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9.5C2 7 4 5 5.5 5H18.5C20 5 22 7 22 9.5V17Z" />
                                <path d="M6 8L12 12L18 8" />
                            </svg>
                        </div>
                        <h1 className="text-2xl font-bold tracking-tight text-foreground">
                            Control Plane
                        </h1>
                        <p className="text-sm text-muted-foreground mt-2 font-medium">
                            Platform Administration Console
                        </p>
                    </div>

                    {/* Login Card - Uses semantic design tokens */}
                    <div className="bg-card rounded-lg shadow-xl border border-border overflow-hidden">
                        {/* Form */}
                        <form
                            onSubmit={handleLogin}
                            aria-describedby={error || emailError || passwordError || mfaError ? 'control-login-form-errors' : undefined}
                            className="p-8 space-y-5"
                        >
                            {error || emailError || passwordError || mfaError ? (
                                <div id="control-login-form-errors" className="sr-only" role="alert" aria-live="assertive">
                                    {error ? `Form error: ${error}. ` : ''}
                                    {emailError ? `Email error: ${emailError}. ` : ''}
                                    {passwordError ? `Password error: ${passwordError}. ` : ''}
                                    {mfaError ? `MFA error: ${mfaError}.` : ''}
                                </div>
                            ) : null}
                            {error && (
                                <div className="bg-destructive/10 border border-destructive/20 text-destructive text-sm rounded-lg p-3 flex items-center gap-2">
                                    <AlertTriangle className="w-4 h-4" />
                                    {error}
                                </div>
                            )}

                            <div className="space-y-2">
                                <label htmlFor="login-email" className="text-sm font-semibold text-foreground">
                                    Email Address
                                </label>
                                <input
                                    id="login-email"
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    onBlur={() => setEmailError(validateEmail(email))}
                                    className="w-full px-4 py-3 min-h-[44px] rounded-sm border border-input focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all placeholder:text-muted-foreground bg-muted/30 text-sm font-medium text-foreground"
                                    placeholder="you@example.com"
                                    required
                                    disabled={loading}
                                />
                                {emailError ? <p className="text-xs text-destructive" role="alert">{emailError}</p> : null}
                            </div>

                            <div className="space-y-2">
                                <label htmlFor="login-password" className="text-sm font-semibold text-foreground">
                                    Password
                                </label>
                                <input
                                    id="login-password"
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    onBlur={() => setPasswordError(validatePassword(password))}
                                    className="w-full px-4 py-3 min-h-[44px] rounded-sm border border-input focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all bg-muted/30 text-foreground"
                                    placeholder="••••••••••••"
                                    required
                                    disabled={loading}
                                />
                                {passwordError ? <p className="text-xs text-destructive" role="alert">{passwordError}</p> : null}
                            </div>

                            {showMfa && (
                                <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 space-y-3">
                                    <label htmlFor="login-mfa" className="flex items-center gap-2 text-sm font-semibold text-foreground">
                                        <Lock className="w-4 h-4 text-primary" />
                                        MFA Verification
                                    </label>
                                    <input
                                        id="login-mfa"
                                        type="text"
                                        value={mfaCode}
                                        onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                        onBlur={() => setMfaError(validateMfa(mfaCode))}
                                        className="w-full px-4 py-3 min-h-[44px] font-mono text-center text-lg tracking-[0.5em] rounded-sm border border-primary/30 focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none bg-card text-foreground"
                                        placeholder="000000"
                                        maxLength={6}
                                        required
                                        disabled={loading}
                                        autoFocus
                                    />
                                    {mfaError ? <p className="text-xs text-destructive text-center" role="alert">{mfaError}</p> : null}
                                    <p className="text-xs text-muted-foreground text-center font-medium">
                                        Enter the 6-digit code from your authenticator app
                                    </p>
                                </div>
                            )}

                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 mt-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {loading ? (
                                    <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                ) : (
                                    <>
                                        <span>{showMfa ? 'Verify & Sign In' : 'Sign In to Control Plane'}</span>
                                        <ArrowRight className="w-4 h-4" />
                                    </>
                                )}
                            </button>
                        </form>

                        {/* Footer - Security badges */}
                        <div className="bg-muted/30 px-8 py-4 border-t border-border flex items-center justify-center gap-4">
                            <div className="flex items-center gap-2 text-xs font-semibold text-muted-foreground">
                                <Shield className="w-4 h-4" />
                                <span>TLS 1.3</span>
                            </div>
                            <span className="w-1 h-1 rounded-full bg-border"></span>
                            <span className="text-xs font-semibold text-muted-foreground">Audit Logged</span>
                            <span className="w-1 h-1 rounded-full bg-border"></span>
                            <span className="text-xs font-semibold text-muted-foreground">SOC2</span>
                        </div>
                    </div>

                    {/* Footer Warning */}
                    <div className="space-y-4">
                        <p className="text-center text-xs leading-relaxed text-muted-foreground max-w-xs mx-auto">
                            Unauthorized access attempts are a federal offense. 
                            Your IP address has been logged.
                        </p>

                        {/* Environment indicator */}
                        <div className="flex justify-center">
                            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-card border border-border text-muted-foreground shadow-sm">
                                <span className="relative flex h-2 w-2">
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-success-500"></span>
                                </span>
                                System Operational
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
