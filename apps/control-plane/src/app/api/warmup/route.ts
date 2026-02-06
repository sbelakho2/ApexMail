/**
 * IP Warmer API
 * 
 * Returns IP warmup pools, IPs, and schedules.
 * Used by the /ip-warmer page.
 */

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with real IP warmup service/DB queries
const DEMO_WARMUP_SCHEDULES: Record<string, { schedule: number[]; maxDay: number; maxLimit: number }> = {
    gmail: { schedule: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000, 30000], maxDay: 13, maxLimit: 30000 },
    microsoft: { schedule: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000], maxDay: 12, maxLimit: 50000 },
    yahoo: { schedule: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000], maxDay: 12, maxLimit: 20000 },
    apple: { schedule: [75, 150, 300, 600, 1200, 2400, 4000, 6000, 9000, 12000, 16000, 22000, 30000], maxDay: 12, maxLimit: 30000 },
    default: { schedule: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000, 75000, 100000], maxDay: 14, maxLimit: 100000 },
};

const DEMO_POOLS = [
    { id: 'pool-1', name: 'Primary Shared Pool', tenantId: 'system', ipCount: 8, activeIPs: 6, totalDailyLimit: 45000, totalDailySent: 32400, utilizationPercent: 72 },
    { id: 'pool-2', name: 'Enterprise Dedicated', tenantId: 'tenant-1', ipCount: 4, activeIPs: 4, totalDailyLimit: 120000, totalDailySent: 89500, utilizationPercent: 75 },
    { id: 'pool-3', name: 'Newsletter Pool', tenantId: 'tenant-2', ipCount: 2, activeIPs: 2, totalDailyLimit: 25000, totalDailySent: 18200, utilizationPercent: 73 },
    { id: 'pool-4', name: 'Transactional Pool', tenantId: 'system', ipCount: 3, activeIPs: 3, totalDailyLimit: 85000, totalDailySent: 71000, utilizationPercent: 84 },
];

const DEMO_IPS: Record<string, Array<{
    id: string; ipAddress: string; poolId: string; warmupDay: number;
    dailyLimit: number; dailySent: number; warmupStartedAt: string | null;
    status: string; isFullyWarmed: boolean; nextDayLimit: number | null; utilizationPercent: number;
}>> = {
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

export async function GET() {
    try {
        // TODO: Replace with real IP warmup service queries
        return NextResponse.json({
            pools: DEMO_POOLS,
            schedules: DEMO_WARMUP_SCHEDULES,
            ips: DEMO_IPS,
        });
    } catch (error) {
        console.error('IP Warmer API error:', error);
        return NextResponse.json({
            pools: DEMO_POOLS,
            schedules: DEMO_WARMUP_SCHEDULES,
            ips: DEMO_IPS,
        });
    }
}
