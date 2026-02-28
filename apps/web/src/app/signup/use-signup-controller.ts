'use client';

import { useState, useEffect, useCallback, FormEvent } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';

interface SignupForm {
    companyName: string;
    email: string;
    name: string;
    password: string;
    confirmPassword: string;
    acceptTerms: boolean;
}

interface FormErrors {
    companyName?: string;
    email?: string;
    name?: string;
    password?: string;
    confirmPassword?: string;
    acceptTerms?: string;
}

type PlanName = 'free' | 'starter' | 'pro' | 'growth' | 'scale' | 'enterprise' | 'payg';
type BillingInterval = 'monthly' | 'yearly';

export function useSignupController() {
    const router = useRouter();
    const searchParams = useSearchParams();
    
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState(false);
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const [mcaptchaToken, setMcaptchaToken] = useState<string | null>(null);
    const [mcaptchaError, setMcaptchaError] = useState<string | null>(null);
    const [formErrors, setFormErrors] = useState<FormErrors>({});
    
    const [form, setForm] = useState<SignupForm>({
        companyName: '',
        email: '',
        name: '',
        password: '',
        confirmPassword: '',
        acceptTerms: false,
    });
    
    // Extract plan from URL params
    const selectedPlan = (searchParams.get('plan') as PlanName) || 'free';
    const billingInterval = (searchParams.get('billing') as BillingInterval) || 'monthly';
    
    // Load CSRF token on mount
    useEffect(() => {
        const loadCsrfToken = async () => {
            try {
                const response = await fetch('/api/csrf');
                if (response.ok) {
                    const data = await response.json();
                    setCsrfToken(data.token);
                }
            } catch {
                // Ignore CSRF fetch errors - form submission will handle it
            }
        };
        loadCsrfToken();
    }, []);
    
    const updateForm = useCallback(<K extends keyof SignupForm>(
        key: K,
        value: SignupForm[K]
    ) => {
        setForm((prev) => ({ ...prev, [key]: value }));
        // Clear field error when user types
        if (formErrors[key as keyof FormErrors]) {
            setFormErrors((prev) => ({ ...prev, [key]: undefined }));
        }
    }, [formErrors]);
    
    const validateForm = useCallback((): boolean => {
        const errors: FormErrors = {};
        
        // Company name validation
        if (!form.companyName.trim()) {
            errors.companyName = 'Company name is required';
        } else if (form.companyName.length < 2) {
            errors.companyName = 'Company name must be at least 2 characters';
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!form.email.trim()) {
            errors.email = 'Email is required';
        } else if (!emailRegex.test(form.email)) {
            errors.email = 'Please enter a valid email address';
        }
        
        // Name validation
        if (!form.name.trim()) {
            errors.name = 'Name is required';
        } else if (form.name.length < 2) {
            errors.name = 'Name must be at least 2 characters';
        }
        
        // Password validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{12,}$/;
        if (!form.password) {
            errors.password = 'Password is required';
        } else if (form.password.length < 12) {
            errors.password = 'Password must be at least 12 characters';
        } else if (!passwordRegex.test(form.password)) {
            errors.password = 'Password must include uppercase, lowercase, number, and special character';
        }
        
        // Confirm password validation
        if (!form.confirmPassword) {
            errors.confirmPassword = 'Please confirm your password';
        } else if (form.password !== form.confirmPassword) {
            errors.confirmPassword = 'Passwords do not match';
        }
        
        // Terms acceptance
        if (!form.acceptTerms) {
            errors.acceptTerms = 'You must accept the terms to continue';
        }
        
        setFormErrors(errors);
        return Object.keys(errors).length === 0;
    }, [form]);
    
    const handleSubmit = useCallback(async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError(null);
        setMcaptchaError(null);
        
        // Validate form
        if (!validateForm()) {
            return;
        }
        
        // Check CAPTCHA
        if (!mcaptchaToken) {
            setMcaptchaError('Please complete the CAPTCHA verification');
            return;
        }
        
        setIsLoading(true);
        
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken || '',
                },
                body: JSON.stringify({
                    companyName: form.companyName.trim(),
                    email: form.email.trim().toLowerCase(),
                    name: form.name.trim(),
                    password: form.password,
                    plan: selectedPlan,
                    billingInterval,
                    mcaptchaToken,
                }),
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                if (data.errorCode === 'EMAIL_EXISTS') {
                    setFormErrors((prev) => ({ 
                        ...prev, 
                        email: 'An account with this email already exists' 
                    }));
                } else if (data.errorCode === 'MCAPTCHA_INVALID') {
                    setMcaptchaError('CAPTCHA verification failed. Please try again.');
                } else {
                    setError(data.error || 'Registration failed. Please try again.');
                }
                return;
            }
            
            // Registration successful
            setSuccess(true);
            
            // If it's a paid plan, redirect to Stripe checkout
            if (data.checkoutUrl) {
                window.location.href = data.checkoutUrl;
                return;
            }
            
        } catch (err) {
            setError('Network error. Please check your connection and try again.');
        } finally {
            setIsLoading(false);
        }
    }, [form, csrfToken, mcaptchaToken, selectedPlan, billingInterval, validateForm]);
    
    return {
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
    };
}
