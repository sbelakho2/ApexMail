'use client';

import * as React from 'react';
import { Sidebar } from '@/components/layout/sidebar';
import { Header } from '@/components/layout/header';
import { ImpersonationBanner } from '@/components/impersonation-banner';
import { cn } from '@/lib/utils';

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

    return (
        <div className="flex h-screen overflow-hidden">
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
                        'flex-1 overflow-y-auto bg-muted/30 p-4 md:p-6 lg:p-8 safe-area-inset-bottom'
                    )}
                >
                    {children}
                </main>
            </div>
        </div>
    );
}
