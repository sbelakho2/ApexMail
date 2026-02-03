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
        <div className="min-h-screen flex flex-col bg-surface-50">
            {/* Control Plane Banner */}
            <div className="bg-gradient-to-r from-amber-500 to-amber-600 text-white text-xs font-semibold py-2 px-4 text-center tracking-wide shadow-sm">
                🔐 APEXMAIL CONTROL PLANE — RESTRICTED ACCESS
            </div>

            <div className="flex-1 flex items-center justify-center p-4">
                <div className="w-full max-w-md space-y-6">
                    {/* Security Notice */}
                    <div className="bg-amber-50/50 border border-amber-200/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
                        <div className="flex items-start gap-3">
                            <span className="text-amber-600 text-lg mt-0.5">⚠️</span>
                            <div>
                                <h3 className="font-semibold text-amber-900 text-sm">Restricted Access Area</h3>
                                <p className="text-xs text-amber-800/80 mt-1 leading-relaxed">
                                    Access is restricted to authorized platform administrators only. 
                                    All IP addresses and login attempts are logged and continuously monitored.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Login Card */}
                    <div className="bg-surface-0 rounded-2xl border border-surface-200 shadow-xl shadow-surface-200/40 overflow-hidden">
                        {/* Card Header */}
                        <div className="bg-surface-900 px-8 py-10 text-center relative overflow-hidden">
                            {/* Detailed Pattern Background */}
                            <div className="absolute inset-0 opacity-10 bg-[radial-gradient(#fff_1px,transparent_1px)] [background-size:16px_16px]"></div>
                            
                            <div className="relative z-10">
                                <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold text-xl mb-4 shadow-lg shadow-blue-900/50 border border-blue-400/20">
                                    A
                                </div>
                                <h1 className="text-xl font-bold text-white tracking-tight">Control Plane</h1>
                                <p className="text-xs text-surface-600 mt-2 font-medium uppercase tracking-wider">
                                    Platform Administration
                                </p>
                            </div>
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

                                <div className="space-y-1.5">
                                    <label className="block text-xs font-semibold text-surface-700 uppercase tracking-wide">
                                        Email Address
                                    </label>
                                    <input
                                        type="email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        className="w-full px-4 py-2.5 rounded-lg border border-surface-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 outline-none transition-all placeholder:text-surface-400 bg-surface-50/50 text-sm"
                                        placeholder="admin@apexmail.ee"
                                        required
                                        disabled={loading}
                                    />
                                </div>

                                <div className="space-y-1.5">
                                    <label className="block text-xs font-semibold text-surface-700 uppercase tracking-wide">
                                        Password
                                    </label>
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="w-full px-4 py-2.5 rounded-lg border border-surface-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 outline-none transition-all bg-surface-50/50 text-sm"
                                        placeholder="••••••••••••"
                                        required
                                        disabled={loading}
                                    />
                                </div>

                                {showMfa && (
                                    <div className="bg-blue-50/50 border border-blue-100 rounded-xl p-4 space-y-3 animate-in fade-in slide-in-from-top-2">
                                        <label className="flex items-center gap-2 text-sm font-semibold text-blue-900">
                                            <span>🔐</span> MFA Verification
                                        </label>
                                        <input
                                            type="text"
                                            value={mfaCode}
                                            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                            className="w-full px-4 py-3 font-mono text-center text-lg tracking-[0.5em] rounded-lg border border-blue-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 outline-none bg-surface-0"
                                            placeholder="000000"
                                            maxLength={6}
                                            required
                                            disabled={loading}
                                            autoFocus
                                        />
                                        <p className="text-[10px] text-blue-600 text-center font-medium">
                                            Enter the 6-digit code from your authenticator app
                                        </p>
                                    </div>
                                )}

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-xl font-semibold hover:from-blue-700 hover:to-blue-800 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-blue-900/5 mt-2"
                                >
                                    {loading ? (
                                        <span className="flex items-center justify-center gap-2">
                                            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                            </svg>
                                            Authenticating...
                                        </span>
                                    ) : showMfa ? 'Verify & Sign In' : 'Sign In to Control Plane'}
                                </button>
                            </form>

                            <div className="mt-6 pt-6 border-t border-surface-100 text-center">
                                <div className="flex items-center justify-center gap-3 text-[10px] text-surface-600 font-medium uppercase tracking-wider">
                                    <span className="flex items-center gap-1">🔒 TLS 1.3</span>
                                    <span className="w-1 h-1 rounded-full bg-surface-300"></span>
                                    <span className="flex items-center gap-1">Audit Logged</span>
                                    <span className="w-1 h-1 rounded-full bg-surface-300"></span>
                                    <span className="flex items-center gap-1">SOC2</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Footer Warning */}
                    <div className="space-y-4">
                        <p className="text-center text-[10px] leading-relaxed text-surface-400 max-w-xs mx-auto">
                            Unauthorized access attempts are a federal offense. 
                            Your IP address has been logged.
                        </p>

                        {/* Environment indicator */}
                        <div className="flex justify-center">
                            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-[10px] font-semibold bg-surface-0 border border-surface-200 text-surface-600 shadow-sm">
                                <span className="relative flex h-2 w-2">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
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
