'use client';

import { useState, useEffect } from 'react';
import { X, Eye, AlertTriangle } from '@/components/ui/icons';
import { getCsrfToken } from '@/hooks/use-api';

interface ImpersonationInfo {
    operatorName: string;
    tenantId: string;
    expiresAt: number;
}

/**
 * Impersonation Banner
 * 
 * Displays a prominent banner when a Control Plane operator is
 * viewing the console as a customer. This ensures transparency
 * and prevents accidental actions while impersonating.
 */
export function ImpersonationBanner() {
    const [impersonationInfo, setImpersonationInfo] = useState<ImpersonationInfo | null>(null);
    const [timeRemaining, setTimeRemaining] = useState<string>('');
    const [isEndingSession, setIsEndingSession] = useState(false);
    const [endSessionError, setEndSessionError] = useState<string | null>(null);
    
    useEffect(() => {
        // Check for impersonation session
        const checkImpersonation = async () => {
            try {
                const response = await fetch('/v1/auth/session', {
                    cache: 'no-store',
                    credentials: 'include',
                });
                const data = await response.json();
                
                if (data.impersonation) {
                    const nextInfo = {
                        operatorName: data.impersonation.operatorName,
                        tenantId: data.impersonation.tenantId,
                        expiresAt: data.impersonation.exp,
                    };
                    setImpersonationInfo(nextInfo);
                } else {
                    setImpersonationInfo(null);
                }
            } catch {
                // Not impersonating or error
            }
        };
        
        checkImpersonation();
    }, []);
    
    useEffect(() => {
        if (!impersonationInfo) return;

        let timeoutId: ReturnType<typeof setTimeout> | undefined;

        const updateTimer = () => {
            const remaining = impersonationInfo.expiresAt - Date.now();
            if (remaining <= 0) {
                setTimeRemaining((prev) => (prev === 'Expired' ? prev : 'Expired'));
                return;
            }

            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);

            const nextLabel = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            setTimeRemaining((prev) => (prev === nextLabel ? prev : nextLabel));

            const nextDelayMs = remaining > 5 * 60_000
                ? 60_000
                : remaining > 60_000
                    ? 15_000
                    : 1_000;

            timeoutId = setTimeout(updateTimer, nextDelayMs);
        };

        updateTimer();

        return () => {
            if (timeoutId) {
                clearTimeout(timeoutId);
            }
        };
    }, [impersonationInfo]);
    
    const handleEndSession = async () => {
        setEndSessionError(null);
        setIsEndingSession(true);
        try {
            const csrfToken = await getCsrfToken();
            const response = await fetch('/v1/auth/impersonate/end', {
                method: 'POST',
                credentials: 'include',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
            });
            if (!response.ok) {
                throw new Error('Unable to end session');
            }
            window.location.href = '/login';
        } catch {
            setEndSessionError('Could not end impersonation session. Please try again.');
        } finally {
            setIsEndingSession(false);
        }
    };
    
    if (!impersonationInfo) return null;
    
    return (
        <div className="fixed top-0 left-0 right-0 z-[100] bg-warning text-white shadow-lg" role="alert" aria-live="polite">
            <div className="max-w-7xl mx-auto px-4 py-2">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-2 bg-white/20 rounded-full px-3 py-1">
                            <Eye className="w-4 h-4" />
                            <span className="text-xs font-bold uppercase tracking-wide">
                                Impersonation Mode
                            </span>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                            <span className="opacity-80">Viewing as tenant:</span>
                            <span className="font-semibold bg-white/10 px-2 py-0.5 rounded">
                                {impersonationInfo.tenantId}
                            </span>
                        </div>
                        <div className="hidden md:flex items-center gap-2 text-sm">
                            <span className="opacity-80">Operator:</span>
                            <span className="font-medium">
                                {impersonationInfo.operatorName}
                            </span>
                        </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                        {endSessionError ? (
                            <span className="text-xs font-medium text-white/95">{endSessionError}</span>
                        ) : null}
                        <div className="flex items-center gap-2 text-sm">
                            <AlertTriangle className="w-4 h-4" />
                            <span className="hidden sm:inline opacity-80">Expires in:</span>
                            <span className="font-mono font-bold bg-white/20 px-2 py-0.5 rounded">
                                {timeRemaining}
                            </span>
                        </div>
                        
                        <button
                            onClick={handleEndSession}
                            disabled={isEndingSession}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/20 hover:bg-white/30 rounded-lg text-sm font-semibold transition-colors"
                        >
                            <X className="w-4 h-4" />
                            <span className="hidden sm:inline">{isEndingSession ? 'Ending…' : 'End Session'}</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
