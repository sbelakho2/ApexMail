'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

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
 */
export default function ControlPlaneLogin() {
    const router = useRouter();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState('');
    const [showMfa, setShowMfa] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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
        <div className="min-h-screen flex flex-col bg-slate-50">
            {/* Control Plane Banner */}
            <div className="bg-gradient-to-r from-amber-500 to-orange-500 text-white text-xs font-medium py-1.5 px-4 text-center">
                🔐 ApexMail Control Plane — Restricted Access
            </div>

            <div className="flex-1 flex items-center justify-center p-4">
                <div className="w-full max-w-md">
                    {/* Security Notice */}
                    <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-6">
                        <div className="flex items-start gap-3">
                            <span className="text-amber-600 text-xl">⚠️</span>
                            <div>
                                <h3 className="font-semibold text-amber-800">Restricted Access</h3>
                                <p className="text-sm text-amber-700 mt-1">
                                    This is the ApexMail Control Plane. Access is restricted to 
                                    authorized platform administrators only. All login attempts 
                                    are logged and monitored.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Login Card */}
                    <div className="bg-white rounded-xl border border-slate-200 shadow-lg overflow-hidden">
                        {/* Card Header */}
                        <div className="bg-gradient-to-br from-slate-900 to-slate-800 px-8 py-8 text-center">
                            <div className="inline-flex h-14 w-14 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold text-2xl mb-4 shadow-lg">
                                A
                            </div>
                            <h1 className="text-2xl font-bold text-white">Control Plane</h1>
                            <p className="text-sm text-slate-400 mt-1">
                                Platform Administration
                            </p>
                        </div>

                        {/* Form */}
                        <div className="p-8">
                            <form onSubmit={handleLogin} className="space-y-5">
                                {error && (
                                    <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3 flex items-center gap-2">
                                        <span>❌</span>
                                        {error}
                                    </div>
                                )}

                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-2">
                                        Email Address
                                    </label>
                                    <input
                                        type="email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        className="input"
                                        placeholder="admin@apexmail.ee"
                                        required
                                        disabled={loading}
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-2">
                                        Password
                                    </label>
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="input"
                                        placeholder="••••••••••••"
                                        required
                                        disabled={loading}
                                    />
                                </div>

                                {showMfa && (
                                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                                        <label className="block text-sm font-medium text-blue-800 mb-2">
                                            🔐 MFA Verification Required
                                        </label>
                                        <input
                                            type="text"
                                            value={mfaCode}
                                            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                            className="input font-mono text-center text-lg tracking-[0.5em]"
                                            placeholder="000000"
                                            maxLength={6}
                                            required
                                            disabled={loading}
                                            autoFocus
                                        />
                                        <p className="text-xs text-blue-600 mt-2">
                                            Enter the 6-digit code from your authenticator app
                                        </p>
                                    </div>
                                )}

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full py-3 px-4 bg-control-plane text-control-plane-foreground rounded-lg font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
                        >
                            {loading ? 'Signing in...' : showMfa ? 'Verify & Sign In' : 'Sign In'}
                        </button>
                    </form>

                    <div className="mt-6 pt-6 border-t border-surface-200 text-center">
                        <p className="text-xs text-muted-foreground">
                            🔒 Secured connection • All activity logged
                        </p>
                    </div>
                </div>

                {/* Footer Warning */}
                <p className="text-center text-xs text-muted-foreground mt-4">
                    Unauthorized access attempts will be reported.
                </p>
            </div>
        </div>
    );
}
