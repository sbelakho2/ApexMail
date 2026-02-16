'use client';

import { useState } from 'react';
import { usePathname } from 'next/navigation';
import { Sidebar } from './sidebar';

interface ControlPlaneShellProps {
    children: React.ReactNode;
}

/**
 * Control Plane Shell Component
 * 
 * Handles responsive layout with mobile menu support.
 * Uses client-side state for mobile menu toggle.
 */
export function ControlPlaneShell({ children }: ControlPlaneShellProps) {
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const pathname = usePathname();
    const isLoginPage = pathname === '/login';

    return (
        <>
            <div className="min-h-screen bg-background">
                {!isLoginPage && (
                    <>
                        {/* Mobile Header */}
                        <div className="md:hidden fixed left-0 right-0 top-0 z-40 flex items-center justify-between p-4 bg-card border-b border-border">
                            <div className="flex items-center gap-3">
                                <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center text-primary-foreground font-bold text-sm">
                                    A
                                </div>
                                <span className="text-sm font-semibold text-foreground">Control Plane</span>
                            </div>
                            <button
                                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                                className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted/50 rounded-lg transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
                                aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
                                aria-expanded={mobileMenuOpen}
                            >
                                {mobileMenuOpen ? (
                                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                ) : (
                                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                                    </svg>
                                )}
                            </button>
                        </div>

                        {/* Mobile Menu Overlay */}
                        {mobileMenuOpen && (
                            <div 
                                className="md:hidden fixed inset-0 bg-black/50 z-40"
                                onClick={() => setMobileMenuOpen(false)}
                                aria-hidden="true"
                            />
                        )}

                        {/* Desktop Sidebar — fixed */}
                        <div className="hidden md:block">
                            <Sidebar className="fixed left-0 top-0 h-screen w-64" />
                        </div>

                        {/* Mobile Sidebar — slide-in */}
                        <div 
                            className={`md:hidden fixed left-0 top-0 h-screen z-50 transition-transform duration-300 ${
                                mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
                            }`}
                        >
                            <Sidebar 
                                className="h-full w-64" 
                                onNavigate={() => setMobileMenuOpen(false)} 
                            />
                        </div>
                    </>
                )}

                {/* Main Content */}
                <main className={isLoginPage ? "w-full" : "ml-0 md:ml-64 p-4 md:p-8 pt-4 md:pt-8"}>
                    {children}
                </main>
            </div>
        </>
    );
}
