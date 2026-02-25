'use client';

import * as React from 'react';
import Link from 'next/link';
import { ArrowLeft, Mail } from '@/components/ui/icons';

/**
 * FIX-065: Forgot Password page
 * Provides a form for users to request a password reset email.
 * Uses /api/auth/forgot-password and always shows a success state
 * to prevent email enumeration.
 */
export default function ForgotPasswordPage() {
    const [email, setEmail] = React.useState('');
    const [submitted, setSubmitted] = React.useState(false);
    const [isLoading, setIsLoading] = React.useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);

        try {
            await fetch('/api/auth/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });
            setSubmitted(true);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/30 p-4">
            <div className="w-full max-w-md">
                <Link
                    href="/login"
                    className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground mb-8 transition-colors"
                >
                    <ArrowLeft className="w-4 h-4" />
                    Back to login
                </Link>

                <div className="bg-card rounded-2xl shadow-xl border border-border overflow-hidden">
                    <div className="p-8">
                        {submitted ? (
                            <div className="text-center space-y-4">
                                <div className="mx-auto w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                                    <Mail className="w-6 h-6 text-primary" />
                                </div>
                                <h1 className="text-xl font-bold text-foreground">Check your email</h1>
                                <p className="text-sm text-muted-foreground">
                                    If an account exists for <strong>{email}</strong>, we&apos;ve sent a
                                    password reset link. Check your inbox and spam folder, and allow a few
                                    minutes for delivery.
                                </p>
                                <p className="text-xs text-muted-foreground pt-4">
                                    Didn&apos;t receive it?{' '}
                                    <button
                                        onClick={() => setSubmitted(false)}
                                        className="text-primary font-semibold hover:underline"
                                    >
                                        Try again
                                    </button>
                                </p>
                            </div>
                        ) : (
                            <>
                                <h1 className="text-xl font-bold text-foreground mb-2">
                                    Reset your password
                                </h1>
                                <p className="text-sm text-muted-foreground mb-6">
                                    Enter your email address and we&apos;ll send you a link to reset
                                    your password.
                                </p>

                                <form onSubmit={handleSubmit} className="space-y-4">
                                    <div className="space-y-2">
                                        <label
                                            htmlFor="reset-email"
                                            className="text-sm font-semibold text-foreground"
                                        >
                                            Email
                                        </label>
                                        <input
                                            id="reset-email"
                                            type="email"
                                            autoComplete="email"
                                            required
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            placeholder="name@company.com"
                                            className="w-full px-4 py-3 rounded-lg border border-input focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all placeholder:text-muted-foreground bg-muted/30 text-sm font-medium text-foreground"
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        disabled={isLoading}
                                        className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 transition-all disabled:opacity-60"
                                    >
                                        {isLoading ? (
                                            <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                        ) : (
                                            'Send reset link'
                                        )}
                                    </button>
                                </form>
                            </>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
