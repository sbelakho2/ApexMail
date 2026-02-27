'use client';

import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { Sidebar } from './sidebar';
import { cn } from '../../lib/utils';

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
    const [showShortcutSheet, setShowShortcutSheet] = useState(false);
    const [incident, setIncident] = useState<{ title: string; severity: 'info' | 'warning' | 'critical' } | null>(null);
    const [autopilotPaused, setAutopilotPaused] = useState(false);
    const [dependencyIssues, setDependencyIssues] = useState<Array<{ name: string; status: 'healthy' | 'degraded' | 'down' }>>([]);
    const [highLatency, setHighLatency] = useState(false);
    const pathname = usePathname();
    const isLoginPage = pathname === '/login';

    useEffect(() => {
        async function loadOperationalState() {
            const startedAt = performance.now();
            try {
                const [incidentResponse, autopilotResponse, dependencyResponse] = await Promise.all([
                    fetch('/api/system/incident', { credentials: 'include' }),
                    fetch('/api/autopilot/status', { credentials: 'include' }),
                    fetch('/api/system/dependencies', { credentials: 'include' }),
                ]);

                const elapsed = performance.now() - startedAt;
                setHighLatency(elapsed > 1200);

                if (incidentResponse.ok) {
                    const payload = await incidentResponse.json();
                    setIncident(payload?.active ? { title: payload.title, severity: payload.severity } : null);
                }

                if (autopilotResponse.ok) {
                    const payload = await autopilotResponse.json();
                    setAutopilotPaused(Boolean(payload?.paused));
                }

                if (dependencyResponse.ok) {
                    const payload = await dependencyResponse.json();
                    const degraded = Array.isArray(payload)
                        ? payload.filter((item) => item.status !== 'healthy')
                        : [];
                    setDependencyIssues(degraded);
                }
            } catch {
                // Silent operational fallback
            }
        }

        loadOperationalState();
    }, []);

    useEffect(() => {
        function onKeyDown(event: KeyboardEvent) {
            if ((event.key === '?' || (event.shiftKey && event.key === '/')) && !event.metaKey && !event.ctrlKey) {
                event.preventDefault();
                setShowShortcutSheet(true);
            }
            if (event.key === 'Escape') {
                setShowShortcutSheet(false);
            }
        }

        window.addEventListener('keydown', onKeyDown);
        return () => window.removeEventListener('keydown', onKeyDown);
    }, []);

    return (
        <>
            <div className="min-h-screen bg-background">
                {!isLoginPage && (
                    <>
                        {incident && (
                            <div className={cn(
                                'px-4 py-2 text-xs font-medium border-b',
                                incident.severity === 'critical' ? 'bg-destructive/10 text-destructive border-destructive/20' :
                                incident.severity === 'warning' ? 'bg-warning/10 text-warning border-warning/20' :
                                'bg-primary/10 text-primary border-primary/20'
                            )}>
                                Incident: {incident.title}
                            </div>
                        )}

                        {autopilotPaused && (
                            <div className="px-4 py-2 text-xs font-medium border-b border-warning/20 bg-warning/10 text-warning">
                                Safe mode active: Autopilot is currently paused.
                            </div>
                        )}

                        {highLatency && (
                            <div className="px-4 py-2 text-xs font-medium border-b border-warning/20 bg-warning/10 text-warning">
                                High latency detected for proxied service calls. Actions may complete slower than usual.
                            </div>
                        )}

                        {dependencyIssues.length > 0 && (
                            <div className="px-4 py-2 text-xs border-b border-border bg-muted/40 text-muted-foreground">
                                Degraded dependencies:
                                <span className="ml-2 font-medium text-foreground">
                                    {dependencyIssues.map((dependency) => `${dependency.name} (${dependency.status})`).join(', ')}
                                </span>
                            </div>
                        )}

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

            {showShortcutSheet && !isLoginPage && (
                <div className="fixed inset-0 z-[100] bg-background/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={() => setShowShortcutSheet(false)}>
                    <div className="w-full max-w-md rounded-xl border border-border bg-card p-5 shadow-xl" onClick={(event) => event.stopPropagation()}>
                        <div className="flex items-center justify-between mb-3">
                            <h2 className="text-base font-semibold text-foreground">Operator Shortcuts</h2>
                            <button aria-label="Close operator shortcuts" className="text-sm text-muted-foreground hover:text-foreground" onClick={() => setShowShortcutSheet(false)}>Close</button>
                        </div>
                        <ul className="space-y-2 text-sm text-foreground">
                            <li><span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted mr-2">?</span>Open shortcut sheet</li>
                            <li><span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted mr-2">Esc</span>Close active dialog/sheet</li>
                            <li><span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted mr-2">g + s</span>Go to support queue</li>
                            <li><span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted mr-2">g + r</span>Go to risk monitoring</li>
                            <li><span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted mr-2">g + a</span>Go to audit logs</li>
                        </ul>
                    </div>
                </div>
            )}
        </>
    );
}
