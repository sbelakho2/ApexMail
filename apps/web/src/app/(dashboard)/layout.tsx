'use client';

import * as React from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Sidebar } from '@/components/layout/sidebar';
import { Header } from '@/components/layout/header';
import { ImpersonationBanner } from '@/components/impersonation-banner';
import { cn } from '@/lib/utils';
import { useUserStore } from '@/stores';

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const router = useRouter();
    const pathname = usePathname();
    const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
    const setUser = useUserStore((state) => state.setUser);
    const setLoading = useUserStore((state) => state.setLoading);

    React.useEffect(() => {
        let cancelled = false;
        let activeController: AbortController | null = null;

        const verifySession = async () => {
            try {
                activeController?.abort();
                activeController = new AbortController();

                const response = await fetch('/api/auth/session', {
                    cache: 'no-store',
                    signal: activeController.signal,
                });
                if (!response.ok) return;
                const data = await response.json();
                if (!cancelled) {
                    setUser(data?.authenticated ? (data?.user ?? null) : null);
                    setLoading(false);
                }
                if (!cancelled && !data?.authenticated) {
                    const next = pathname?.startsWith('/') ? pathname : '/dashboard';
                    router.replace(`/login?next=${encodeURIComponent(next)}&reason=session_expired`);
                }
            } catch (error) {
                if (error instanceof DOMException && error.name === 'AbortError') {
                    return;
                }
                if (!cancelled) {
                    setUser(null);
                    setLoading(false);
                    const next = pathname?.startsWith('/') ? pathname : '/dashboard';
                    router.replace(`/login?next=${encodeURIComponent(next)}&reason=session_check_failed`);
                }
            }
        };

        verifySession();
        const interval = window.setInterval(verifySession, 60_000);

        return () => {
            cancelled = true;
            activeController?.abort();
            window.clearInterval(interval);
        };
    }, [pathname, router, setLoading, setUser]);

    return (
        <div className="flex h-screen overflow-hidden bg-surface-50">
            {/* Impersonation Banner - Shows when control plane operator is viewing */}
            <ImpersonationBanner />
            
            {/* Desktop Sidebar */}
            <Sidebar className="hidden md:flex" />

            {/* Mobile Sidebar Overlay */}
            {mobileMenuOpen && (
                <>
                    <div
                        className="fixed inset-0 z-40 bg-black/50 md:hidden"
                        onClick={() => setMobileMenuOpen(false)}
                    />
                    <div className="fixed inset-y-0 left-0 z-50 w-64 md:hidden shadow-2xl">
                        <Sidebar onClose={() => setMobileMenuOpen(false)} />
                    </div>
                </>
            )}

            {/* Main Content */}
            <div className="flex flex-1 flex-col overflow-hidden">
                <Header 
                    onMenuClick={() => setMobileMenuOpen(!mobileMenuOpen)} 
                    isMobileMenuOpen={mobileMenuOpen}
                />
                <main
                    className={cn(
                        'relative flex-1 overflow-y-auto bg-gradient-to-br from-surface-50 via-background to-brand-50/40 p-4 md:p-6 lg:p-8 safe-area-inset-bottom dark:from-surface-50 dark:via-surface-100 dark:to-brand-900/25'
                    )}
                >
                    <div className="pointer-events-none absolute inset-0">
                        <div className="absolute -top-24 right-12 h-56 w-56 rounded-full bg-brand-100/60 blur-3xl dark:bg-brand-900/35" />
                        <div className="absolute bottom-[-120px] left-10 h-64 w-64 rounded-full bg-brand-50/80 blur-3xl dark:bg-brand-800/25" />
                    </div>
                    <div className="relative">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
}
