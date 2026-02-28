/**
 * Customer Registration API Route
 *
 * Creates a new tenant and user account.
 * For paid plans, creates a Stripe checkout session.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { validateCsrf } from '@/lib/csrf';
import { verifyMCaptchaToken } from '@/lib/security/mcaptcha';
import { createLogger } from '@apexmail/lib/logger';

const logger = createLogger({ name: 'auth-register' });

const registerSchema = z.object({
    companyName: z.string().min(2).max(100),
    email: z.string().email().max(254),
    name: z.string().min(2).max(100),
    password: z
        .string()
        .min(12)
        .max(128)
        .regex(
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/,
            'Password must include uppercase, lowercase, number, and special character'
        ),
    plan: z.enum(['free', 'starter', 'pro', 'growth', 'scale', 'enterprise', 'payg']).default('free'),
    billingInterval: z.enum(['monthly', 'yearly']).default('monthly'),
    mcaptchaToken: z.string().max(4096).optional(),
});

const PAID_PLANS = ['starter', 'pro', 'growth', 'scale', 'enterprise'];

export async function POST(request: NextRequest) {
    // Validate CSRF token
    const csrf = await validateCsrf(request);
    if (!csrf.ok) {
        return csrf.response!;
    }

    try {
        const body = await request.json();
        const validatedData = registerSchema.parse(body);

        // Verify CAPTCHA
        const captchaResult = await verifyMCaptchaToken(validatedData.mcaptchaToken);
        if (!captchaResult.ok) {
            const status = captchaResult.reason === 'provider' || captchaResult.reason === 'misconfigured' ? 503 : 400;
            const errorCode = captchaResult.reason === 'missing'
                ? 'MCAPTCHA_REQUIRED'
                : captchaResult.reason === 'invalid'
                    ? 'MCAPTCHA_INVALID'
                    : 'MCAPTCHA_UNAVAILABLE';

            return NextResponse.json(
                {
                    error: errorCode === 'MCAPTCHA_REQUIRED'
                        ? 'Complete the CAPTCHA challenge and try again.'
                        : errorCode === 'MCAPTCHA_INVALID'
                            ? 'CAPTCHA verification failed. Please retry.'
                            : 'CAPTCHA verification service is unavailable. Please try again shortly.',
                    errorCode,
                },
                { status }
            );
        }

        const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
        const billingBaseUrl = process.env.BILLING_URL || 'http://localhost:3004';

        // Step 1: Create tenant and user via core API
        const registerResponse = await fetch(`${apiBaseUrl}/v1/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Internal-Key': process.env.INTERNAL_API_KEY || '',
            },
            body: JSON.stringify({
                companyName: validatedData.companyName,
                email: validatedData.email,
                name: validatedData.name,
                password: validatedData.password,
                plan: validatedData.plan,
            }),
            signal: AbortSignal.timeout(10000),
        });

        const registerData = await registerResponse.json().catch(() => ({}));

        if (!registerResponse.ok) {
            logger.warn('Registration failed', {
                status: registerResponse.status,
                email: validatedData.email.replace(/@.*/, '@***'),
            });

            if (registerResponse.status === 409) {
                return NextResponse.json(
                    { error: 'An account with this email already exists', errorCode: 'EMAIL_EXISTS' },
                    { status: 409 }
                );
            }

            return NextResponse.json(
                { error: registerData.error || 'Registration failed. Please try again.' },
                { status: registerResponse.status }
            );
        }

        const { tenantId, userId, verificationToken } = registerData;

        logger.info('User registered', {
            tenantId,
            userId,
            plan: validatedData.plan,
        });

        // Step 2: Send verification email
        try {
            await fetch(`${apiBaseUrl}/v1/internal/send-verification-email`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Internal-Key': process.env.INTERNAL_API_KEY || '',
                },
                body: JSON.stringify({
                    email: validatedData.email,
                    name: validatedData.name,
                    verificationToken,
                }),
                signal: AbortSignal.timeout(5000),
            });
        } catch (emailErr) {
            logger.error('Failed to send verification email', { error: emailErr, userId });
            // Don't fail registration if email fails - user can request resend
        }

        // Step 3: For paid plans, create Stripe checkout session
        if (PAID_PLANS.includes(validatedData.plan)) {
            try {
                const appBaseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://app.apexmail.ee';
                
                const checkoutResponse = await fetch(`${billingBaseUrl}/api/checkout/create`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Internal-Key': process.env.INTERNAL_API_KEY || '',
                    },
                    body: JSON.stringify({
                        tenantId,
                        plan: validatedData.plan,
                        billingInterval: validatedData.billingInterval,
                        email: validatedData.email,
                        successUrl: `${appBaseUrl}/dashboard?welcome=1&plan=${validatedData.plan}`,
                        cancelUrl: `${appBaseUrl}/signup?plan=${validatedData.plan}&cancelled=1`,
                    }),
                    signal: AbortSignal.timeout(10000),
                });

                const checkoutData = await checkoutResponse.json().catch(() => ({}));

                if (checkoutResponse.ok && checkoutData.checkoutUrl) {
                    return NextResponse.json({
                        success: true,
                        message: 'Account created. Redirecting to payment...',
                        checkoutUrl: checkoutData.checkoutUrl,
                    });
                }
            } catch (checkoutErr) {
                logger.error('Failed to create checkout session', { error: checkoutErr, tenantId });
                // Continue without checkout - user can upgrade later
            }
        }

        // For free/PAYG plans or if checkout fails, just return success
        return NextResponse.json({
            success: true,
            message: 'Account created. Please check your email to verify your account.',
        });

    } catch (err) {
        if (err instanceof z.ZodError) {
            const firstError = err.errors[0];
            return NextResponse.json(
                { error: firstError?.message || 'Invalid input', errorCode: 'VALIDATION_ERROR' },
                { status: 400 }
            );
        }

        logger.error('Registration error', { error: err });
        return NextResponse.json(
            { error: 'An unexpected error occurred. Please try again.' },
            { status: 500 }
        );
    }
}
