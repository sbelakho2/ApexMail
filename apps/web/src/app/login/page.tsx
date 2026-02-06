'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, ArrowRight } from 'lucide-react';

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
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [csrfToken, setCsrfToken] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    fetch('/api/csrf')
      .then((res) => res.json())
      .then((data) => {
        if (isMounted) {
          setCsrfToken(data.token || null);
        }
      })
      .catch(() => {
        if (isMounted) {
          setError('Unable to initialize security token. Please refresh.');
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    if (!csrfToken) {
      setError('Security token missing. Please refresh and try again.');
      setIsLoading(false);
      return;
    }
    
    const formData = new FormData(e.currentTarget);
    const email = formData.get('email') as string;
    const password = formData.get('password') as string;
    
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.error || 'Invalid credentials');
        setIsLoading(false);
        return;
      }
      
      // Authentication successful - redirect to dashboard
      router.push('/dashboard');
    } catch {
      setError('Network error. Please try again.');
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-[400px]">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/20 mb-6">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
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
        <div className="bg-card rounded-2xl shadow-xl border border-border overflow-hidden">
          <form onSubmit={handleSubmit} className="p-8 space-y-5">
            {error && (
              <div className="bg-destructive/10 border border-destructive/20 text-destructive text-sm rounded-lg p-3">
                {error}
              </div>
            )}
            <div className="space-y-2">
              <label className="text-sm font-semibold text-foreground" htmlFor="email">
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                placeholder="name@company.com"
                className="w-full px-4 py-3 rounded-lg border border-input focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all placeholder:text-muted-foreground bg-muted/30 text-sm font-medium text-foreground"
              />
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
                type="password"
                required
                className="w-full px-4 py-3 rounded-lg border border-input focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all bg-muted/30 text-foreground"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
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
          </form>

          {/* Social / SSO (Visual Placeholder) */}
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
              <button disabled title="SSO coming soon" className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border hover:bg-accent hover:border-accent-foreground/10 transition-all opacity-60 cursor-not-allowed">
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                  <path d="M5.84 14.17c-.22-.66-.35-1.36-.35-2.17s.13-1.51.35-2.17V7.69H2.18C.79 10.45 0 13.63 0 17c0 3.37.79 6.55 2.18 9.31l3.66-2.84z" fill="#FBBC05"/>
                  <path d="M12 4.6c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.09 14.97 0 12 0 7.7 0 3.99 2.47 2.18 5.69l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                <span className="text-sm font-semibold text-foreground">Google</span>
                <span className="text-[10px] text-muted-foreground ml-1">(Coming Soon)</span>
              </button>
              <button disabled title="SSO coming soon" className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border hover:bg-accent hover:border-accent-foreground/10 transition-all opacity-60 cursor-not-allowed">
                <svg className="w-5 h-5 text-foreground" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.03.555-3.885-1.425-3.885-1.425-.546-1.38-1.335-1.755-1.335-1.755-1.005-.69.075-.675.075-.675 1.11.075 1.695 1.14 1.695 1.14 1.005 1.725 2.64 1.23 3.285.945.105-.72.39-1.215.705-1.485-2.565-.285-5.265-1.29-5.265-5.73 0-1.26.45-2.295 1.185-3.09-.12-.285-.525-1.455.105-3.045 0 0 .96-.3 3.15 1.2A10.965 10.965 0 0 1 12 5.805c.9.015 1.785.12 2.64.24 2.19-1.5 3.15-1.2 3.15-1.2.63 1.59.225 2.76.105 3.045.735.795 1.185 1.83 1.185 3.09 0 4.455-2.715 5.43-5.295 5.715.39.345.735 1.02.735 2.055 0 1.485-.015 2.685-.015 3.045 0 .315.225.69.84.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12" />
                </svg>
                <span className="text-sm font-semibold text-foreground">GitHub</span>
                <span className="text-[10px] text-muted-foreground ml-1">(Coming Soon)</span>
              </button>
            </div>
          </div>
          
          <div className="bg-muted/30 px-8 py-4 border-t border-border flex items-center justify-center gap-2">
             <Shield className="w-3 h-3 text-muted-foreground" />
             <span className="text-xs font-semibold text-muted-foreground">
               Secured by ApexMail Identity
             </span>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center mt-8 text-xs text-muted-foreground">
          Don&apos;t have an account?{' '}
          <Link href="https://apexmail.ee/signup" className="font-semibold text-primary hover:underline">
            Get your API keys
          </Link>
        </p>
      </div>
    </div>
  );
}
