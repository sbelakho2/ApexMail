'use client';

import { useState, useEffect, useCallback } from 'react';
import { formatNumber, cn, timeAgo } from '../../lib/utils';

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
const DEMO_WARMUP_SCHEDULES: Record<string, WarmupScheduleInfo> = {
    gmail: { schedule: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000, 30000], maxDay: 13, maxLimit: 30000 },
    microsoft: { schedule: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000], maxDay: 12, maxLimit: 50000 },
    yahoo: { schedule: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000], maxDay: 12, maxLimit: 20000 },
    apple: { schedule: [75, 150, 300, 600, 1200, 2400, 4000, 6000, 9000, 12000, 16000, 22000, 30000], maxDay: 12, maxLimit: 30000 },
    default: { schedule: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000, 75000, 100000], maxDay: 14, maxLimit: 100000 },
};

const DEMO_POOLS: WarmupPoolInfo[] = [
    { id: 'pool-1', name: 'Primary Shared Pool', tenantId: 'system', ipCount: 8, activeIPs: 6, totalDailyLimit: 45000, totalDailySent: 32400, utilizationPercent: 72 },
    { id: 'pool-2', name: 'Enterprise Dedicated', tenantId: 'tenant-1', ipCount: 4, activeIPs: 4, totalDailyLimit: 120000, totalDailySent: 89500, utilizationPercent: 75 },
    { id: 'pool-3', name: 'Newsletter Pool', tenantId: 'tenant-2', ipCount: 2, activeIPs: 2, totalDailyLimit: 25000, totalDailySent: 18200, utilizationPercent: 73 },
    { id: 'pool-4', name: 'Transactional Pool', tenantId: 'system', ipCount: 3, activeIPs: 3, totalDailyLimit: 85000, totalDailySent: 71000, utilizationPercent: 84 },
];

const DEMO_IPS: Record<string, IPWarmupInfo[]> = {
    'pool-1': [
        { id: 'ip-1', ipAddress: '198.51.100.1', poolId: 'pool-1', warmupDay: 10, dailyLimit: 12000, dailySent: 9600, warmupStartedAt: new Date(Date.now() - 864000000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 18000, utilizationPercent: 80 },
        { id: 'ip-2', ipAddress: '198.51.100.2', poolId: 'pool-1', warmupDay: 8, dailyLimit: 8000, dailySent: 5600, warmupStartedAt: new Date(Date.now() - 691200000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 12000, utilizationPercent: 70 },
        { id: 'ip-3', ipAddress: '198.51.100.3', poolId: 'pool-1', warmupDay: 6, dailyLimit: 5000, dailySent: 4200, warmupStartedAt: new Date(Date.now() - 518400000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 8000, utilizationPercent: 84 },
        { id: 'ip-4', ipAddress: '198.51.100.4', poolId: 'pool-1', warmupDay: 14, dailyLimit: 100000, dailySent: 13000, warmupStartedAt: new Date(Date.now() - 1209600000).toISOString(), status: 'active', isFullyWarmed: true, nextDayLimit: null, utilizationPercent: 13 },
        { id: 'ip-5', ipAddress: '198.51.100.5', poolId: 'pool-1', warmupDay: 3, dailyLimit: 800, dailySent: 0, warmupStartedAt: new Date(Date.now() - 259200000).toISOString(), status: 'paused', isFullyWarmed: false, nextDayLimit: 1500, utilizationPercent: 0 },
        { id: 'ip-6', ipAddress: '198.51.100.6', poolId: 'pool-1', warmupDay: 0, dailyLimit: 100, dailySent: 0, warmupStartedAt: null, status: 'inactive', isFullyWarmed: false, nextDayLimit: 200, utilizationPercent: 0 },
    ],
    'pool-2': [
        { id: 'ip-7', ipAddress: '203.0.113.1', poolId: 'pool-2', warmupDay: 14, dailyLimit: 100000, dailySent: 78000, warmupStartedAt: new Date(Date.now() - 1209600000).toISOString(), status: 'active', isFullyWarmed: true, nextDayLimit: null, utilizationPercent: 78 },
        { id: 'ip-8', ipAddress: '203.0.113.2', poolId: 'pool-2', warmupDay: 14, dailyLimit: 100000, dailySent: 82000, warmupStartedAt: new Date(Date.now() - 1209600000).toISOString(), status: 'active', isFullyWarmed: true, nextDayLimit: null, utilizationPercent: 82 },
        { id: 'ip-9', ipAddress: '203.0.113.3', poolId: 'pool-2', warmupDay: 11, dailyLimit: 25000, dailySent: 18500, warmupStartedAt: new Date(Date.now() - 950400000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 35000, utilizationPercent: 74 },
        { id: 'ip-10', ipAddress: '203.0.113.4', poolId: 'pool-2', warmupDay: 9, dailyLimit: 18000, dailySent: 11000, warmupStartedAt: new Date(Date.now() - 777600000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 25000, utilizationPercent: 61 },
    ],
    'pool-3': [
        { id: 'ip-11', ipAddress: '192.0.2.1', poolId: 'pool-3', warmupDay: 12, dailyLimit: 50000, dailySent: 35000, warmupStartedAt: new Date(Date.now() - 1036800000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 75000, utilizationPercent: 70 },
        { id: 'ip-12', ipAddress: '192.0.2.2', poolId: 'pool-3', warmupDay: 7, dailyLimit: 8000, dailySent: 6200, warmupStartedAt: new Date(Date.now() - 604800000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 12000, utilizationPercent: 78 },
    ],
    'pool-4': [
        { id: 'ip-13', ipAddress: '198.18.0.1', poolId: 'pool-4', warmupDay: 14, dailyLimit: 100000, dailySent: 92000, warmupStartedAt: new Date(Date.now() - 1209600000).toISOString(), status: 'active', isFullyWarmed: true, nextDayLimit: null, utilizationPercent: 92 },
        { id: 'ip-14', ipAddress: '198.18.0.2', poolId: 'pool-4', warmupDay: 13, dailyLimit: 75000, dailySent: 58000, warmupStartedAt: new Date(Date.now() - 1123200000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 100000, utilizationPercent: 77 },
        { id: 'ip-15', ipAddress: '198.18.0.3', poolId: 'pool-4', warmupDay: 10, dailyLimit: 18000, dailySent: 14000, warmupStartedAt: new Date(Date.now() - 864000000).toISOString(), status: 'active', isFullyWarmed: false, nextDayLimit: 25000, utilizationPercent: 78 },
    ],
};

const STATUS_CONFIG: Record<string, { label: string; color: string; bgColor: string }> = {
    active: { label: 'Active', color: 'text-emerald-700', bgColor: 'bg-emerald-100' },
    paused: { label: 'Paused', color: 'text-amber-700', bgColor: 'bg-amber-100' },
    inactive: { label: 'Not Started', color: 'text-surface-500', bgColor: 'bg-surface-100' },
};

export default function IPWarmerPage() {
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
            // In production: fetch from Ops API
            // const [poolsRes, schedulesRes] = await Promise.all([
            //     fetch('/api/warmup/pools'),
            //     fetch('/api/warmup/schedules'),
            // ]);
            // setPools(await poolsRes.json());
            // setSchedules(await schedulesRes.json());
            
            setPools(DEMO_POOLS);
            setSchedules(DEMO_WARMUP_SCHEDULES);
        } finally {
            setLoading(false);
        }
    }

    async function loadPoolIPs(pool: WarmupPoolInfo) {
        setSelectedPool(pool);
        // In production: fetch from Ops API
        // const res = await fetch(`/api/warmup/pools/${pool.id}`);
        // setPoolIPs(await res.json());
        setPoolIPs(DEMO_IPS[pool.id] || []);
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
        if (!confirm(`Reset warmup for ${ip.ipAddress}? This will restart from Day 0.`)) return;
        
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
        if (!confirm('Run daily warmup advancement for all IPs? This is typically run by cron at midnight UTC.')) return;
        
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
                    <h1 className="text-2xl font-bold text-surface-900">IP Warmer</h1>
                    <p className="text-surface-600 mt-1">
                        Manage IP warmup schedules and track progress
                    </p>
                </div>
                <button
                    onClick={handleTriggerAdvancement}
                    disabled={actionLoading === 'advance'}
                    className={cn(
                        'px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 font-medium transition-colors',
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
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Total IPs</div>
                    <div className="text-2xl font-bold text-surface-900">{totalIPs}</div>
                    <div className="text-xs text-surface-400 mt-1">{activeIPs} active</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">IP Pools</div>
                    <div className="text-2xl font-bold text-surface-900">{pools.length}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Daily Capacity</div>
                    <div className="text-2xl font-bold text-blue-600">{formatNumber(totalCapacity)}</div>
                    <div className="text-xs text-surface-400 mt-1">{formatNumber(totalSent)} sent today</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Utilization</div>
                    <div className={cn(
                        'text-2xl font-bold',
                        overallUtilization >= 80 ? 'text-emerald-600' : 
                        overallUtilization >= 50 ? 'text-amber-600' : 'text-surface-600'
                    )}>
                        {overallUtilization}%
                    </div>
                    <div className="w-full h-2 bg-surface-100 rounded-full mt-2 overflow-hidden">
                        <div 
                            className={cn(
                                'h-full rounded-full transition-all',
                                overallUtilization >= 80 ? 'bg-emerald-500' : 
                                overallUtilization >= 50 ? 'bg-amber-500' : 'bg-surface-300'
                            )}
                            style={{ width: `${Math.min(overallUtilization, 100)}%` }}
                        />
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-surface-200 mb-6 overflow-x-auto">
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
                                    ? 'border-blue-600 text-blue-600'
                                    : 'border-transparent text-surface-500 hover:text-surface-700'
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
                        <h2 className="text-sm font-semibold text-surface-700 uppercase tracking-wider">IP Pools</h2>
                        {pools.map(pool => (
                            <button
                                key={pool.id}
                                onClick={() => loadPoolIPs(pool)}
                                className={cn(
                                    'w-full text-left bg-surface-0 rounded-xl border p-4 transition-all',
                                    selectedPool?.id === pool.id
                                        ? 'border-blue-500 ring-2 ring-blue-100'
                                        : 'border-surface-200 hover:border-surface-300'
                                )}
                            >
                                <div className="flex items-center justify-between mb-2">
                                    <span className="font-medium text-surface-900">{pool.name}</span>
                                    <span className="text-xs text-surface-400">{pool.activeIPs}/{pool.ipCount} IPs</span>
                                </div>
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-surface-500">
                                        {formatNumber(pool.totalDailySent)}/{formatNumber(pool.totalDailyLimit)}
                                    </span>
                                    <span className={cn(
                                        'font-medium',
                                        pool.utilizationPercent >= 70 ? 'text-emerald-600' : 'text-surface-500'
                                    )}>
                                        {pool.utilizationPercent}%
                                    </span>
                                </div>
                                <div className="w-full h-1.5 bg-surface-100 rounded-full mt-2 overflow-hidden">
                                    <div 
                                        className={cn(
                                            'h-full rounded-full transition-all',
                                            pool.utilizationPercent >= 70 ? 'bg-emerald-500' : 'bg-blue-400'
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
                            <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                                <div className="p-4 border-b border-surface-200 bg-surface-50">
                                    <h3 className="font-semibold text-surface-900">{selectedPool.name}</h3>
                                    <p className="text-sm text-surface-500 mt-1">
                                        {selectedPool.activeIPs} active IPs • {formatNumber(selectedPool.totalDailyLimit)} daily capacity
                                    </p>
                                </div>
                                
                                <div className="overflow-x-auto">
                                    <table className="w-full min-w-[700px]">
                                        <thead className="bg-surface-50 border-b border-surface-200">
                                            <tr>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">IP Address</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Status</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Day</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Progress</th>
                                                <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Limit</th>
                                                <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-surface-100">
                                            {poolIPs.map(ip => {
                                                const statusConfig = STATUS_CONFIG[ip.status] || STATUS_CONFIG.inactive;
                                                const maxDay = schedules.default?.maxDay || 14;
                                                const progressPercent = Math.round((ip.warmupDay / maxDay) * 100);
                                                
                                                return (
                                                    <tr key={ip.id} className="hover:bg-surface-50/50 transition-colors">
                                                        <td className="px-4 py-3">
                                                            <div className="font-mono text-sm text-surface-900">{ip.ipAddress}</div>
                                                            {ip.warmupStartedAt && (
                                                                <div className="text-xs text-surface-400 mt-0.5">
                                                                    Started {timeAgo(ip.warmupStartedAt)}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={cn(
                                                                'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                                statusConfig.bgColor,
                                                                statusConfig.color
                                                            )}>
                                                                {ip.isFullyWarmed ? '✓ Fully Warmed' : statusConfig.label}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-medium text-surface-900">Day {ip.warmupDay}</span>
                                                                <span className="text-xs text-surface-400">/ {maxDay}</span>
                                                            </div>
                                                            <div className="w-24 h-1.5 bg-surface-100 rounded-full mt-1 overflow-hidden">
                                                                <div 
                                                                    className={cn(
                                                                        'h-full rounded-full',
                                                                        ip.isFullyWarmed ? 'bg-emerald-500' : 'bg-blue-500'
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
                                                                    ip.utilizationPercent >= 50 ? 'text-amber-600' : 'text-surface-600'
                                                                )}>
                                                                    {ip.utilizationPercent}%
                                                                </span>
                                                                <span className="text-surface-400 ml-1">utilized</span>
                                                            </div>
                                                            <div className="text-xs text-surface-400">
                                                                {formatNumber(ip.dailySent)}/{formatNumber(ip.dailyLimit)}
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="text-sm font-medium text-surface-900">
                                                                {formatNumber(ip.dailyLimit)}
                                                            </div>
                                                            {ip.nextDayLimit && (
                                                                <div className="text-xs text-surface-400">
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
                                                                        className="px-2.5 py-1 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded transition-colors disabled:opacity-50"
                                                                    >
                                                                        Start
                                                                    </button>
                                                                ) : ip.status === 'paused' ? (
                                                                    <button
                                                                        onClick={() => handleResumeWarmup(ip)}
                                                                        disabled={actionLoading === ip.id}
                                                                        className="px-2.5 py-1 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-700 rounded transition-colors disabled:opacity-50"
                                                                    >
                                                                        Resume
                                                                    </button>
                                                                ) : (
                                                                    <button
                                                                        onClick={() => handlePauseWarmup(ip)}
                                                                        disabled={actionLoading === ip.id}
                                                                        className="px-2.5 py-1 text-xs font-medium text-amber-700 bg-amber-100 hover:bg-amber-200 rounded transition-colors disabled:opacity-50"
                                                                    >
                                                                        Pause
                                                                    </button>
                                                                )}
                                                                <button
                                                                    onClick={() => openSetDayModal(ip)}
                                                                    disabled={actionLoading === ip.id}
                                                                    className="px-2.5 py-1 text-xs font-medium text-surface-600 bg-surface-100 hover:bg-surface-200 rounded transition-colors disabled:opacity-50"
                                                                    title="Set warmup day manually"
                                                                >
                                                                    Set Day
                                                                </button>
                                                                <button
                                                                    onClick={() => handleResetWarmup(ip)}
                                                                    disabled={actionLoading === ip.id}
                                                                    className="px-2.5 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded transition-colors disabled:opacity-50"
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
                            <div className="bg-surface-0 rounded-xl border border-surface-200 p-12 text-center">
                                <div className="text-4xl mb-4">🖥️</div>
                                <h3 className="text-lg font-medium text-surface-900 mb-2">Select an IP Pool</h3>
                                <p className="text-surface-500 text-sm">
                                    Choose a pool from the list to view and manage its IPs
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {activeTab === 'schedules' && (
                <div className="space-y-6">
                    <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                        <h3 className="text-lg font-semibold text-surface-900 mb-4">ISP-Specific Warmup Schedules</h3>
                        <p className="text-sm text-surface-500 mb-6">
                            Daily sending limits are automatically applied based on the warmup day. 
                            IPs must achieve 75% utilization to advance to the next day.
                        </p>
                        
                        <div className="space-y-6">
                            {Object.entries(schedules).map(([isp, info]) => (
                                <div key={isp} className="border border-surface-200 rounded-lg overflow-hidden">
                                    <div className="px-4 py-3 bg-surface-50 border-b border-surface-200 flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <span className="text-lg">
                                                {isp === 'gmail' ? '📧' : 
                                                 isp === 'microsoft' ? '📪' : 
                                                 isp === 'yahoo' ? '📬' : 
                                                 isp === 'apple' ? '🍎' : '📨'}
                                            </span>
                                            <div>
                                                <span className="font-medium text-surface-900 capitalize">{isp}</span>
                                                <span className="text-xs text-surface-400 ml-2">
                                                    {info.maxDay + 1} days to full warmup
                                                </span>
                                            </div>
                                        </div>
                                        <div className="text-sm text-surface-500">
                                            Max: <span className="font-medium text-surface-900">{formatNumber(info.maxLimit)}</span>/day
                                        </div>
                                    </div>
                                    <div className="p-4 overflow-x-auto">
                                        <div className="flex gap-2 min-w-max">
                                            {info.schedule.map((limit, day) => (
                                                <div 
                                                    key={day}
                                                    className="flex flex-col items-center min-w-[60px] px-2.5 py-2 bg-surface-50 rounded-lg"
                                                >
                                                    <span className="text-[10px] font-medium text-surface-600 uppercase">Day {day}</span>
                                                    <span className="text-sm font-semibold text-surface-900 mt-1">
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
                    <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
                        <h4 className="font-semibold text-blue-900 mb-3">📘 Warmup Best Practices</h4>
                        <ul className="space-y-2 text-sm text-blue-800">
                            <li className="flex items-start gap-2">
                                <span className="text-blue-500 mt-0.5">•</span>
                                <span><strong>Target 75%+ utilization</strong> daily to advance warmup progression</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-blue-500 mt-0.5">•</span>
                                <span><strong>Maintain consistent sending</strong> — gaps can reset reputation</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-blue-500 mt-0.5">•</span>
                                <span><strong>Monitor bounce rates</strong> — high bounces may require pausing</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-blue-500 mt-0.5">•</span>
                                <span><strong>Use the &quot;Set Day&quot; feature</strong> for recovery scenarios (e.g., after infrastructure issues)</span>
                            </li>
                        </ul>
                    </div>
                </div>
            )}

            {/* Set Day Modal */}
            {showSetDayModal && selectedIP && (
                <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
                    <div className="bg-white rounded-xl shadow-xl max-w-md w-full">
                        <div className="p-6 border-b border-surface-200">
                            <div className="flex items-center justify-between">
                                <h3 className="text-lg font-semibold text-surface-900">Set Warmup Day</h3>
                                <button 
                                    onClick={() => setShowSetDayModal(false)}
                                    className="text-surface-400 hover:text-surface-600 transition-colors"
                                >
                                    ✕
                                </button>
                            </div>
                            <p className="text-sm text-surface-500 mt-1">
                                Manually adjust warmup day for <span className="font-mono">{selectedIP.ipAddress}</span>
                            </p>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className="block text-sm font-medium text-surface-700 mb-2">
                                    Warmup Day (0-{schedules.default?.maxDay || 14})
                                </label>
                                <input
                                    type="number"
                                    min={0}
                                    max={schedules.default?.maxDay || 14}
                                    value={newWarmupDay}
                                    onChange={(e) => setNewWarmupDay(Math.max(0, Math.min(schedules.default?.maxDay || 14, parseInt(e.target.value) || 0)))}
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                                />
                            </div>
                            <div className="bg-surface-50 rounded-lg p-3 mb-4">
                                <div className="text-xs text-surface-500 mb-1">New Daily Limit</div>
                                <div className="text-lg font-bold text-surface-900">
                                    {formatNumber(schedules.default?.schedule[Math.min(newWarmupDay, schedules.default.schedule.length - 1)] || 100)} emails/day
                                </div>
                            </div>
                            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-700">
                                ⚠️ Use this for recovery scenarios only. Artificially advancing warmup without actual sending may harm deliverability.
                            </div>
                        </div>
                        <div className="p-4 border-t border-surface-200 flex justify-end gap-3">
                            <button
                                onClick={() => setShowSetDayModal(false)}
                                className="px-4 py-2 text-sm font-medium text-surface-700 bg-surface-100 hover:bg-surface-200 rounded-lg transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleSetWarmupDay}
                                disabled={actionLoading === selectedIP.id}
                                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50"
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
