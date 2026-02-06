'use client';

import { useState, useEffect, useCallback } from 'react';
import { formatNumber, cn, timeAgo } from '../../lib/utils';
import { useDialog } from '../../components/ui/confirm-dialog';

/**
 * IP Warmer Management - Dedicated IP warming interface
 * 
 * The owner can:
 * - View all IP pools and their warmup status
 * - Monitor individual IP warmup progress
 * - Start/pause/reset warmup for IPs
 * - Manually adjust warmup days (recovery scenarios)
 * - Trigger daily warmup advancement
 * - View ISP-specific warmup schedules
 */

// Types matching the backend WarmupManager
interface IPWarmupInfo {
    id: string;
    ipAddress: string;
    poolId: string;
    warmupDay: number;
    dailyLimit: number;
    dailySent: number;
    warmupStartedAt: string | null;
    status: 'active' | 'paused' | 'inactive';
    isFullyWarmed: boolean;
    nextDayLimit: number | null;
    utilizationPercent: number;
}

interface WarmupPoolInfo {
    id: string;
    name: string;
    tenantId: string;
    ipCount: number;
    activeIPs: number;
    totalDailyLimit: number;
    totalDailySent: number;
    utilizationPercent: number;
}

interface WarmupScheduleInfo {
    schedule: number[];
    maxDay: number;
    maxLimit: number;
}

// Demo data matching backend structures


const STATUS_CONFIG: Record<string, { label: string; color: string; bgColor: string; borderColor: string }> = {
    active: { label: 'Active', color: 'text-success', bgColor: 'bg-success/10', borderColor: 'border-success/20' },
    paused: { label: 'Paused', color: 'text-warning', bgColor: 'bg-warning/10', borderColor: 'border-warning/20' },
    inactive: { label: 'Not Started', color: 'text-muted-foreground', bgColor: 'bg-muted', borderColor: 'border-border' },
};

export default function IPWarmerPage() {
    const dialog = useDialog();
    const [pools, setPools] = useState<WarmupPoolInfo[]>([]);
    const [selectedPool, setSelectedPool] = useState<WarmupPoolInfo | null>(null);
    const [poolIPs, setPoolIPs] = useState<IPWarmupInfo[]>([]);
    const [schedules, setSchedules] = useState<Record<string, WarmupScheduleInfo>>({});
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState<string | null>(null);
    const [selectedIP, setSelectedIP] = useState<IPWarmupInfo | null>(null);
    const [showSetDayModal, setShowSetDayModal] = useState(false);
    const [newWarmupDay, setNewWarmupDay] = useState(0);
    const [activeTab, setActiveTab] = useState<'pools' | 'schedules'>('pools');
    const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

    useEffect(() => {
        loadData();
    }, []);

    useEffect(() => {
        if (toast) {
            const timer = setTimeout(() => setToast(null), 4000);
            return () => clearTimeout(timer);
        }
    }, [toast]);

    async function loadData() {
        try {
            const response = await fetch('/api/warmup', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch warmup data: ${response.status}`);
            const data = await response.json();
            setPools(data.pools);
            setSchedules(data.schedules);
        } catch (err) {
            console.error('Failed to load warmup data:', err);
        } finally {
            setLoading(false);
        }
    }

    async function loadPoolIPs(pool: WarmupPoolInfo) {
        setSelectedPool(pool);
        try {
            const response = await fetch(`/api/warmup?poolId=${pool.id}`, { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch pool IPs: ${response.status}`);
            const data = await response.json();
            setPoolIPs(data.ips?.[pool.id] || []);
        } catch (err) {
            console.error('Failed to load pool IPs:', err);
            setPoolIPs([]);
        }
    }

    const showToast = useCallback((message: string, type: 'success' | 'error') => {
        setToast({ message, type });
    }, []);

    async function handleStartWarmup(ip: IPWarmupInfo) {
        setActionLoading(ip.id);
        try {
            // In production: POST to /api/warmup/ip/{ipAddress}/start
            await new Promise(resolve => setTimeout(resolve, 500));
            
            setPoolIPs(prev => prev.map(i => 
                i.id === ip.id ? { 
                    ...i, 
                    status: 'active' as const, 
                    warmupStartedAt: new Date().toISOString(),
                    warmupDay: 0,
                    dailyLimit: schedules.default?.schedule[0] || 100,
                } : i
            ));
            showToast(`Warmup started for ${ip.ipAddress}`, 'success');
        } catch {
            showToast('Failed to start warmup', 'error');
        } finally {
            setActionLoading(null);
        }
    }

    async function handlePauseWarmup(ip: IPWarmupInfo) {
        setActionLoading(ip.id);
        try {
            // In production: POST to /api/warmup/ip/{ipAddress}/pause
            await new Promise(resolve => setTimeout(resolve, 500));
            
            setPoolIPs(prev => prev.map(i => 
                i.id === ip.id ? { ...i, status: 'paused' as const } : i
            ));
            showToast(`Warmup paused for ${ip.ipAddress}`, 'success');
        } catch {
            showToast('Failed to pause warmup', 'error');
        } finally {
            setActionLoading(null);
        }
    }

    async function handleResumeWarmup(ip: IPWarmupInfo) {
        setActionLoading(ip.id);
        try {
            // In production: POST to /api/warmup/ip/{ipAddress}/start
            await new Promise(resolve => setTimeout(resolve, 500));
            
            setPoolIPs(prev => prev.map(i => 
                i.id === ip.id ? { ...i, status: 'active' as const } : i
            ));
            showToast(`Warmup resumed for ${ip.ipAddress}`, 'success');
        } catch {
            showToast('Failed to resume warmup', 'error');
        } finally {
            setActionLoading(null);
        }
    }

    async function handleResetWarmup(ip: IPWarmupInfo) {
        const confirmed = await dialog.confirm({
            title: 'Reset Warmup',
            message: `Reset warmup for ${ip.ipAddress}? This will restart from Day 0.`,
            confirmLabel: 'Reset',
            variant: 'destructive',
        });
        if (!confirmed) return;
        
        setActionLoading(ip.id);
        try {
            // In production: POST to /api/warmup/ip/{ipAddress}/reset
            await new Promise(resolve => setTimeout(resolve, 500));
            
            setPoolIPs(prev => prev.map(i => 
                i.id === ip.id ? { 
                    ...i, 
                    status: 'active' as const,
                    warmupDay: 0,
                    dailyLimit: schedules.default?.schedule[0] || 100,
                    dailySent: 0,
                    warmupStartedAt: new Date().toISOString(),
                    isFullyWarmed: false,
                    nextDayLimit: schedules.default?.schedule[1] || 200,
                    utilizationPercent: 0,
                } : i
            ));
            showToast(`Warmup reset for ${ip.ipAddress}`, 'success');
        } catch {
            showToast('Failed to reset warmup', 'error');
        } finally {
            setActionLoading(null);
        }
    }

    async function handleSetWarmupDay() {
        if (!selectedIP) return;
        
        setActionLoading(selectedIP.id);
        try {
            // In production: POST to /api/warmup/ip/{ipAddress}/day with { day: newWarmupDay }
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const schedule = schedules.default?.schedule || [];
            const newLimit = schedule[Math.min(newWarmupDay, schedule.length - 1)] || 100;
            const nextLimit = newWarmupDay < schedule.length - 1 ? schedule[newWarmupDay + 1] : null;
            
            setPoolIPs(prev => prev.map(i => 
                i.id === selectedIP.id ? { 
                    ...i, 
                    warmupDay: newWarmupDay,
                    dailyLimit: newLimit,
                    isFullyWarmed: newWarmupDay >= (schedules.default?.maxDay || 14),
                    nextDayLimit: nextLimit,
                } : i
            ));
            showToast(`Warmup day set to ${newWarmupDay} for ${selectedIP.ipAddress}`, 'success');
            setShowSetDayModal(false);
            setSelectedIP(null);
        } catch {
            showToast('Failed to set warmup day', 'error');
        } finally {
            setActionLoading(null);
        }
    }

    async function handleTriggerAdvancement() {
        const confirmed = await dialog.confirm({
            title: 'Run Daily Advancement',
            message: 'Run daily warmup advancement for all IPs? This is typically run by cron at midnight UTC.',
            confirmLabel: 'Run Advancement',
        });
        if (!confirmed) return;
        
        setActionLoading('advance');
        try {
            // In production: POST to /api/warmup/advance
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            // Simulate advancement
            setPoolIPs(prev => prev.map(ip => {
                if (ip.status !== 'active' || ip.isFullyWarmed) return ip;
                if (ip.utilizationPercent < 75) return ip; // Need 75% utilization to advance
                
                const schedule = schedules.default?.schedule || [];
                const newDay = Math.min(ip.warmupDay + 1, schedule.length - 1);
                const newLimit = schedule[newDay] || ip.dailyLimit;
                const nextLimit = newDay < schedule.length - 1 ? schedule[newDay + 1] : null;
                
                return {
                    ...ip,
                    warmupDay: newDay,
                    dailyLimit: newLimit,
                    dailySent: 0,
                    isFullyWarmed: newDay >= schedule.length - 1,
                    nextDayLimit: nextLimit,
                    utilizationPercent: 0,
                };
            }));
            
            showToast('Daily advancement completed successfully', 'success');
            loadData(); // Refresh pool stats
        } catch {
            showToast('Failed to run daily advancement', 'error');
        } finally {
            setActionLoading(null);
        }
    }

    function openSetDayModal(ip: IPWarmupInfo) {
        setSelectedIP(ip);
        setNewWarmupDay(ip.warmupDay);
        setShowSetDayModal(true);
    }

    // Calculate overall stats
    const totalIPs = pools.reduce((acc, p) => acc + p.ipCount, 0);
    const activeIPs = pools.reduce((acc, p) => acc + p.activeIPs, 0);
    const totalCapacity = pools.reduce((acc, p) => acc + p.totalDailyLimit, 0);
    const totalSent = pools.reduce((acc, p) => acc + p.totalDailySent, 0);
    const overallUtilization = totalCapacity > 0 ? Math.round((totalSent / totalCapacity) * 100) : 0;

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Toast Notification */}
            {toast && (
                <div className={cn(
                    'fixed top-20 right-4 z-50 px-4 py-3 rounded-lg shadow-lg transition-all transform',
                    toast.type === 'success' ? 'bg-emerald-600 text-white' : 'bg-red-600 text-white'
                )}>
                    <div className="flex items-center gap-2">
                        <span>{toast.type === 'success' ? '✓' : '✕'}</span>
                        <span className="text-sm font-medium">{toast.message}</span>
                    </div>
                </div>
            )}

            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">IP Warmer</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage IP warmup schedules and track progress
                    </p>
                </div>
                <button
                    onClick={handleTriggerAdvancement}
                    disabled={actionLoading === 'advance'}
                    className={cn(
                        'px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors',
                        'disabled:opacity-50 disabled:cursor-not-allowed',
                        'flex items-center gap-2'
                    )}
                >
                    {actionLoading === 'advance' ? (
                        <>
                            <span className="animate-spin">⟳</span>
                            Running...
                        </>
                    ) : (
                        <>
                            ⚡ Run Daily Advancement
                        </>
                    )}
                </button>
            </div>

            {/* Global Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Total IPs</div>
                    <div className="text-2xl font-bold text-foreground">{totalIPs}</div>
                    <div className="text-xs text-muted-foreground mt-1">{activeIPs} active</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">IP Pools</div>
                    <div className="text-2xl font-bold text-foreground">{pools.length}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Daily Capacity</div>
                    <div className="text-2xl font-bold text-primary">{formatNumber(totalCapacity)}</div>
                    <div className="text-xs text-muted-foreground mt-1">{formatNumber(totalSent)} sent today</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Utilization</div>
                    <div className={cn(
                        'text-2xl font-bold',
                        overallUtilization >= 80 ? 'text-emerald-600' : 
                        overallUtilization >= 50 ? 'text-amber-600' : 'text-muted-foreground'
                    )}>
                        {overallUtilization}%
                    </div>
                    <div className="w-full h-2 bg-muted rounded-full mt-2 overflow-hidden">
                        <div 
                            className={cn(
                                'h-full rounded-full transition-all',
                                overallUtilization >= 80 ? 'bg-emerald-500' : 
                                overallUtilization >= 50 ? 'bg-amber-500' : 'bg-muted-foreground'
                            )}
                            style={{ width: `${Math.min(overallUtilization, 100)}%` }}
                        />
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-border mb-6 overflow-x-auto">
                <nav className="flex gap-6 min-w-max">
                    {[
                        { key: 'pools', label: 'IP Pools', icon: '🖥️' },
                        { key: 'schedules', label: 'Warmup Schedules', icon: '📅' },
                    ].map(tab => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key as typeof activeTab)}
                            className={cn(
                                'flex items-center gap-2 pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                                activeTab === tab.key
                                    ? 'border-primary text-primary'
                                    : 'border-transparent text-muted-foreground hover:text-foreground'
                            )}
                        >
                            <span>{tab.icon}</span>
                            {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {activeTab === 'pools' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Pools List */}
                    <div className="lg:col-span-1 space-y-3">
                        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">IP Pools</h2>
                        {pools.map(pool => (
                            <button
                                key={pool.id}
                                onClick={() => loadPoolIPs(pool)}
                                className={cn(
                                    'w-full text-left bg-card rounded-xl border p-4 transition-all',
                                    selectedPool?.id === pool.id
                                        ? 'border-primary ring-2 ring-primary/20'
                                        : 'border-border hover:border-muted-foreground/50'
                                )}
                            >
                                <div className="flex items-center justify-between mb-2">
                                    <span className="font-medium text-foreground">{pool.name}</span>
                                    <span className="text-xs text-muted-foreground">{pool.activeIPs}/{pool.ipCount} IPs</span>
                                </div>
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-muted-foreground">
                                        {formatNumber(pool.totalDailySent)}/{formatNumber(pool.totalDailyLimit)}
                                    </span>
                                    <span className={cn(
                                        'font-medium',
                                        pool.utilizationPercent >= 70 ? 'text-emerald-600' : 'text-muted-foreground'
                                    )}>
                                        {pool.utilizationPercent}%
                                    </span>
                                </div>
                                <div className="w-full h-1.5 bg-muted rounded-full mt-2 overflow-hidden">
                                    <div 
                                        className={cn(
                                            'h-full rounded-full transition-all',
                                            pool.utilizationPercent >= 70 ? 'bg-emerald-500' : 'bg-primary'
                                        )}
                                        style={{ width: `${Math.min(pool.utilizationPercent, 100)}%` }}
                                    />
                                </div>
                            </button>
                        ))}
                    </div>

                    {/* Pool Details */}
                    <div className="lg:col-span-2">
                        {selectedPool ? (
                            <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                                <div className="p-4 border-b border-border bg-muted/50">
                                    <h3 className="font-semibold text-foreground">{selectedPool.name}</h3>
                                    <p className="text-sm text-muted-foreground mt-1">
                                        {selectedPool.activeIPs} active IPs • {formatNumber(selectedPool.totalDailyLimit)} daily capacity
                                    </p>
                                </div>
                                
                                <div className="overflow-x-auto">
                                    <table className="w-full min-w-[700px]">
                                        <thead className="bg-muted/30 border-b border-border">
                                            <tr>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">IP Address</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Day</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Progress</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Limit</th>
                                                <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-border">
                                            {poolIPs.map(ip => {
                                                const statusConfig = STATUS_CONFIG[ip.status] || STATUS_CONFIG.inactive;
                                                const maxDay = schedules.default?.maxDay || 14;
                                                const progressPercent = Math.round((ip.warmupDay / maxDay) * 100);
                                                
                                                return (
                                                    <tr key={ip.id} className="hover:bg-muted/50 transition-colors">
                                                        <td className="px-4 py-3">
                                                            <div className="font-mono text-sm text-foreground">{ip.ipAddress}</div>
                                                            {ip.warmupStartedAt && (
                                                                <div className="text-xs text-muted-foreground mt-0.5">
                                                                    Started {timeAgo(ip.warmupStartedAt)}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={cn(
                                                                'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
                                                                statusConfig.bgColor,
                                                                statusConfig.color,
                                                                statusConfig.borderColor
                                                            )}>
                                                                {ip.isFullyWarmed ? '✓ Fully Warmed' : statusConfig.label}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-medium text-foreground">Day {ip.warmupDay}</span>
                                                                <span className="text-xs text-muted-foreground">/ {maxDay}</span>
                                                            </div>
                                                            <div className="w-24 h-1.5 bg-muted rounded-full mt-1 overflow-hidden">
                                                                <div 
                                                                    className={cn(
                                                                        'h-full rounded-full',
                                                                        ip.isFullyWarmed ? 'bg-emerald-500' : 'bg-primary'
                                                                    )}
                                                                    style={{ width: `${progressPercent}%` }}
                                                                />
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="text-sm">
                                                                <span className={cn(
                                                                    'font-medium',
                                                                    ip.utilizationPercent >= 75 ? 'text-emerald-600' :
                                                                    ip.utilizationPercent >= 50 ? 'text-amber-600' : 'text-muted-foreground'
                                                                )}>
                                                                    {ip.utilizationPercent}%
                                                                </span>
                                                                <span className="text-muted-foreground ml-1">utilized</span>
                                                            </div>
                                                            <div className="text-xs text-muted-foreground">
                                                                {formatNumber(ip.dailySent)}/{formatNumber(ip.dailyLimit)}
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="text-sm font-medium text-foreground">
                                                                {formatNumber(ip.dailyLimit)}
                                                            </div>
                                                            {ip.nextDayLimit && (
                                                                <div className="text-xs text-muted-foreground">
                                                                    Next: {formatNumber(ip.nextDayLimit)}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3 text-right">
                                                            <div className="flex items-center justify-end gap-1">
                                                                {ip.status === 'inactive' ? (
                                                                    <button
                                                                        onClick={() => handleStartWarmup(ip)}
                                                                        disabled={actionLoading === ip.id}
                                                                        className="px-2.5 py-1 text-xs font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded transition-colors disabled:opacity-50"
                                                                    >
                                                                        Start
                                                                    </button>
                                                                ) : ip.status === 'paused' ? (
                                                                    <button
                                                                        onClick={() => handleResumeWarmup(ip)}
                                                                        disabled={actionLoading === ip.id}
                                                                        className="px-2.5 py-1 text-xs font-medium text-emerald-foreground bg-emerald-600 hover:bg-emerald-600/90 rounded transition-colors disabled:opacity-50"
                                                                    >
                                                                        Resume
                                                                    </button>
                                                                ) : (
                                                                    <button
                                                                        onClick={() => handlePauseWarmup(ip)}
                                                                        disabled={actionLoading === ip.id}
                                                                        className="px-2.5 py-1 text-xs font-medium text-amber-700 bg-amber-100/50 hover:bg-amber-100 border border-amber-200 rounded transition-colors disabled:opacity-50"
                                                                    >
                                                                        Pause
                                                                    </button>
                                                                )}
                                                                <button
                                                                    onClick={() => openSetDayModal(ip)}
                                                                    disabled={actionLoading === ip.id}
                                                                    className="px-2.5 py-1 text-xs font-medium text-muted-foreground bg-muted hover:bg-muted/80 rounded transition-colors disabled:opacity-50"
                                                                    title="Set warmup day manually"
                                                                >
                                                                    Set Day
                                                                </button>
                                                                <button
                                                                    onClick={() => handleResetWarmup(ip)}
                                                                    disabled={actionLoading === ip.id}
                                                                    className="px-2.5 py-1 text-xs font-medium text-destructive bg-destructive/10 hover:bg-destructive/20 rounded transition-colors disabled:opacity-50"
                                                                    title="Reset warmup to Day 0"
                                                                >
                                                                    Reset
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ) : (
                            <div className="bg-card rounded-xl border border-border p-12 text-center">
                                <div className="text-4xl mb-4">🖥️</div>
                                <h3 className="text-lg font-medium text-foreground mb-2">Select an IP Pool</h3>
                                <p className="text-muted-foreground text-sm">
                                    Choose a pool from the list to view and manage its IPs
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {activeTab === 'schedules' && (
                <div className="space-y-6">
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h3 className="text-lg font-semibold text-foreground mb-4">ISP-Specific Warmup Schedules</h3>
                        <p className="text-sm text-muted-foreground mb-6">
                            Daily sending limits are automatically applied based on the warmup day. 
                            IPs must achieve 75% utilization to advance to the next day.
                        </p>
                        
                        <div className="space-y-6">
                            {Object.entries(schedules).map(([isp, info]) => (
                                <div key={isp} className="border border-border rounded-lg overflow-hidden">
                                    <div className="px-4 py-3 bg-muted/30 border-b border-border flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <span className="text-lg">
                                                {isp === 'gmail' ? '📧' : 
                                                 isp === 'microsoft' ? '📪' : 
                                                 isp === 'yahoo' ? '📬' : 
                                                 isp === 'apple' ? '🍎' : '📨'}
                                            </span>
                                            <div>
                                                <span className="font-medium text-foreground capitalize">{isp}</span>
                                                <span className="text-xs text-muted-foreground ml-2">
                                                    {info.maxDay + 1} days to full warmup
                                                </span>
                                            </div>
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            Max: <span className="font-medium text-foreground">{formatNumber(info.maxLimit)}</span>/day
                                        </div>
                                    </div>
                                    <div className="p-4 overflow-x-auto">
                                        <div className="flex gap-2 min-w-max">
                                            {info.schedule.map((limit, day) => (
                                                <div 
                                                    key={day}
                                                    className="flex flex-col items-center min-w-[60px] px-2.5 py-2 bg-muted/50 rounded-lg"
                                                >
                                                    <span className="text-[10px] font-medium text-muted-foreground uppercase">Day {day}</span>
                                                    <span className="text-sm font-semibold text-foreground mt-1">
                                                        {limit >= 1000 ? `${(limit / 1000).toFixed(0)}k` : limit}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Warmup Guidelines */}
                    <div className="bg-primary/5 border border-primary/20 rounded-xl p-6">
                        <h4 className="font-semibold text-primary mb-3">📘 Warmup Best Practices</h4>
                        <ul className="space-y-2 text-sm text-primary/80">
                            <li className="flex items-start gap-2">
                                <span className="text-primary mt-0.5">•</span>
                                <span><strong>Target 75%+ utilization</strong> daily to advance warmup progression</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-primary mt-0.5">•</span>
                                <span><strong>Maintain consistent sending</strong> — gaps can reset reputation</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-primary mt-0.5">•</span>
                                <span><strong>Monitor bounce rates</strong> — high bounces may require pausing</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-primary mt-0.5">•</span>
                                <span><strong>Use the &quot;Set Day&quot; feature</strong> for recovery scenarios (e.g., after infrastructure issues)</span>
                            </li>
                        </ul>
                    </div>
                </div>
            )}

            {/* Set Day Modal */}
            {showSetDayModal && selectedIP && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-card rounded-xl shadow-xl border border-border max-w-md w-full">
                        <div className="p-6 border-b border-border">
                            <div className="flex items-center justify-between">
                                <h3 className="text-lg font-semibold text-foreground">Set Warmup Day</h3>
                                <button 
                                    onClick={() => setShowSetDayModal(false)}
                                    className="text-muted-foreground hover:text-foreground transition-colors"
                                >
                                    ✕
                                </button>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">
                                Manually adjust warmup day for <span className="font-mono text-foreground">{selectedIP.ipAddress}</span>
                            </p>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className="block text-sm font-medium text-foreground mb-2">
                                    Warmup Day (0-{schedules.default?.maxDay || 14})
                                </label>
                                <input
                                    type="number"
                                    min={0}
                                    max={schedules.default?.maxDay || 14}
                                    value={newWarmupDay}
                                    onChange={(e) => setNewWarmupDay(Math.max(0, Math.min(schedules.default?.maxDay || 14, parseInt(e.target.value) || 0)))}
                                    className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-border outline-none transition-all"
                                />
                            </div>
                            <div className="bg-muted/50 rounded-lg p-3 mb-4">
                                <div className="text-xs text-muted-foreground mb-1">New Daily Limit</div>
                                <div className="text-lg font-bold text-foreground">
                                    {formatNumber(schedules.default?.schedule[Math.min(newWarmupDay, schedules.default.schedule.length - 1)] || 100)} emails/day
                                </div>
                            </div>
                            <div className="bg-warning/10 border border-warning/20 rounded-lg p-3 text-xs text-warning">
                                ⚠️ Use this for recovery scenarios only. Artificially advancing warmup without actual sending may harm deliverability.
                            </div>
                        </div>
                        <div className="p-4 border-t border-border flex justify-end gap-3">
                            <button
                                onClick={() => setShowSetDayModal(false)}
                                className="px-4 py-2 text-sm font-medium text-secondary-foreground bg-secondary hover:bg-secondary/80 rounded-lg transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleSetWarmupDay}
                                disabled={actionLoading === selectedIP.id}
                                className="px-4 py-2 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-lg transition-colors disabled:opacity-50"
                            >
                                {actionLoading === selectedIP.id ? 'Saving...' : 'Set Day'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
