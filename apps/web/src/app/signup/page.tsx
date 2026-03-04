'use client';

import { Suspense } from 'react';
import Link from 'next/link';
import { ArrowRight, CheckCircle2 } from '@/components/ui/icons';
import { MCaptchaWidget } from '@/components/security/mcaptcha-widget';
import { useSignupController } from './use-signup-controller';

/**
 * Customer Console Signup Page
 *
 * Self-service registration for ApexMail customers.
 * Supports Free plan by default, or redirects to Stripe checkout for paid plans.
 *
 * URL parameters:
 * - ?plan=starter|pro|growth|scale|enterprise|payg - Pre-select a plan
 * - ?billing=monthly|yearly - Pre-select billing interval
 */
function SignupPageContent() {
    const {
        isLoading,
        error,
        success,
        csrfToken,
        mcaptchaToken,
        setMcaptchaToken,
        mcaptchaError,
        form,
        updateForm,
        formErrors,
        selectedPlan,
        billingInterval,
        handleSubmit,
    } = useSignupController();

    if (success) {
        return (
            <div className="min-h-screen bg-surface-50 flex items-center justify-center px-6 py-12">
                <div className="w-full max-w-md">
                    <div className="rounded-2xl border border-surface-200 bg-white p-8 shadow-card text-center">
                        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-success-100">
                            <CheckCircle2 className="h-8 w-8 text-success-600" />
                        </div>
                        <h1 className="text-2xl font-semibold text-surface-900">Check your email</h1>
                        <p className="mt-3 text-surface-600">
                            We&apos;ve sent a verification link to <strong>{form.email}</strong>.
                            Please click the link to activate your account.
                        </p>
                        <p className="mt-4 text-sm text-surface-500">
                            Didn&apos;t receive the email? Check your spam folder or{' '}
                            <button type="button" className="text-brand-600 hover:underline">
                                resend verification
                            </button>
                        </p>
                        <div className="mt-8">
                            <Link
                                href="/login"
                                className="inline-flex items-center gap-2 text-sm font-medium text-brand-600 hover:text-brand-700"
                            >
                                Go to login
                                <ArrowRight className="h-4 w-4" />
                            </Link>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

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
                            Get Started Free
                        </div>
                        <h1 className="mt-6 text-4xl font-semibold text-surface-900 tracking-tight">
                            Start sending emails in minutes, not days.
                        </h1>
                        <p className="mt-4 max-w-[520px] text-[16px] text-surface-600 leading-relaxed">
                            ApexMail gives you enterprise-grade deliverability with developer-friendly APIs. No credit card required for the Free plan.
                        </p>
                        <div className="mt-8 space-y-3 text-sm text-surface-600">
                            {[
                                '3,000 emails/month free forever',
                                'Instant API key generation',
                                'Domain verification in minutes',
                                'Real-time delivery analytics',
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

                    <div className="w-full max-w-md justify-self-center lg:justify-self-end">
                        <div className="rounded-2xl border border-surface-200 bg-white p-8 shadow-card">
                            <h2 className="text-2xl font-semibold text-surface-900">Create your account</h2>
                            <p className="mt-2 text-sm text-surface-600">
                                {selectedPlan && selectedPlan !== 'free'
                                    ? `You're signing up for the ${selectedPlan.charAt(0).toUpperCase() + selectedPlan.slice(1)} plan`
                                    : "Start with our free plan — upgrade anytime"
                                }
                            </p>

                            <form onSubmit={handleSubmit} className="mt-6 space-y-5">
                                <input type="hidden" name="csrf_token" value={csrfToken ?? ''} />

                                {error && (
                                    <div className="rounded-lg border border-error-200 bg-error-50 p-3 text-sm text-error-700">
                                        {error}
                                    </div>
                                )}

                                <div className="space-y-1.5">
                                    <label htmlFor="companyName" className="text-sm font-medium text-surface-700">
                                        Company / Organization Name
                                    </label>
                                    <input
                                        id="companyName"
                                        type="text"
                                        value={form.companyName}
                                        onChange={(e) => updateForm('companyName', e.target.value)}
                                        className="w-full rounded-lg border border-surface-300 px-4 py-2.5 text-sm transition-colors focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100"
                                        placeholder="Acme Corp"
                                        maxLength={100}
                                        required
                                        autoComplete="organization"
                                    />
                                    {formErrors.companyName && (
                                        <p className="text-xs text-error-600">{formErrors.companyName}</p>
                                    )}
                                </div>

                                <div className="space-y-1.5">
                                    <label htmlFor="email" className="text-sm font-medium text-surface-700">
                                        Work Email
                                    </label>
                                    <input
                                        id="email"
                                        type="email"
                                        value={form.email}
                                        onChange={(e) => updateForm('email', e.target.value)}
                                        className="w-full rounded-lg border border-surface-300 px-4 py-2.5 text-sm transition-colors focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100"
                                        placeholder="you@company.com"
                                        maxLength={254}
                                        required
                                        autoComplete="email"
                                    />
                                    {formErrors.email && (
                                        <p className="text-xs text-error-600">{formErrors.email}</p>
                                    )}
                                </div>

                                <div className="space-y-1.5">
                                    <label htmlFor="name" className="text-sm font-medium text-surface-700">
                                        Full Name
                                    </label>
                                    <input
                                        id="name"
                                        type="text"
                                        value={form.name}
                                        onChange={(e) => updateForm('name', e.target.value)}
                                        className="w-full rounded-lg border border-surface-300 px-4 py-2.5 text-sm transition-colors focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100"
                                        placeholder="Jane Doe"
                                        maxLength={100}
                                        required
                                        autoComplete="name"
                                    />
                                    {formErrors.name && (
                                        <p className="text-xs text-error-600">{formErrors.name}</p>
                                    )}
                                </div>

                                <div className="space-y-1.5">
                                    <label htmlFor="password" className="text-sm font-medium text-surface-700">
                                        Password
                                    </label>
                                    <input
                                        id="password"
                                        type="password"
                                        value={form.password}
                                        onChange={(e) => updateForm('password', e.target.value)}
                                        className="w-full rounded-lg border border-surface-300 px-4 py-2.5 text-sm transition-colors focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100"
                                        placeholder="••••••••••"
                                        minLength={12}
                                        maxLength={128}
                                        required
                                        autoComplete="new-password"
                                    />
                                    {formErrors.password && (
                                        <p className="text-xs text-error-600">{formErrors.password}</p>
                                    )}
                                    <p className="text-xs text-surface-500">
                                        At least 12 characters with uppercase, lowercase, number, and special character.
                                    </p>
                                </div>

                                <div className="space-y-1.5">
                                    <label htmlFor="confirmPassword" className="text-sm font-medium text-surface-700">
                                        Confirm Password
                                    </label>
                                    <input
                                        id="confirmPassword"
                                        type="password"
                                        value={form.confirmPassword}
                                        onChange={(e) => updateForm('confirmPassword', e.target.value)}
                                        className="w-full rounded-lg border border-surface-300 px-4 py-2.5 text-sm transition-colors focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100"
                                        placeholder="••••••••••"
                                        minLength={12}
                                        maxLength={128}
                                        required
                                        autoComplete="new-password"
                                    />
                                    {formErrors.confirmPassword && (
                                        <p className="text-xs text-error-600">{formErrors.confirmPassword}</p>
                                    )}
                                </div>

                                <div className="flex items-start gap-3">
                                    <input
                                        id="acceptTerms"
                                        type="checkbox"
                                        checked={form.acceptTerms}
                                        onChange={(e) => updateForm('acceptTerms', e.target.checked)}
                                        className="mt-1 h-4 w-4 rounded border-surface-300 text-brand-600 focus:ring-brand-500"
                                        required
                                    />
                                    <label htmlFor="acceptTerms" className="text-sm text-surface-600">
                                        I agree to the{' '}
                                        <a href="https://apexmail.ee/terms" target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline">
                                            Terms of Service
                                        </a>{' '}
                                        and{' '}
                                        <a href="https://apexmail.ee/privacy" target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline">
                                            Privacy Policy
                                        </a>
                                    </label>
                                </div>
                                {formErrors.acceptTerms && (
                                    <p className="text-xs text-error-600">{formErrors.acceptTerms}</p>
                                )}

                                <MCaptchaWidget
                                    token={mcaptchaToken ?? ''}
                                    onTokenChange={(t) => setMcaptchaToken(t || null)}
                                    error={mcaptchaError ?? undefined}
                                />
                                {mcaptchaError && (
                                    <p className="text-xs text-error-600">{mcaptchaError}</p>
                                )}

                                <button
                                    type="submit"
                                    disabled={isLoading}
                                    className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-6 py-3 text-sm font-medium text-white transition-colors hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {isLoading ? (
                                        <>
                                            <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                                            Creating account...
                                        </>
                                    ) : (
                                        <>
                                            Create Account
                                            <ArrowRight className="h-4 w-4" />
                                        </>
                                    )}
                                </button>
                            </form>

                            <div className="mt-6 text-center text-sm text-surface-600">
                                Already have an account?{' '}
                                <Link href="/login" className="font-medium text-brand-600 hover:text-brand-700">
                                    Sign in
                                </Link>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default function SignupPage() {
    return (
        <Suspense fallback={<div className="min-h-screen bg-surface-50" />}>
            <SignupPageContent />
        </Suspense>
    );
}
