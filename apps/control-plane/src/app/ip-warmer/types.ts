export interface IPWarmupInfo {
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

export interface WarmupPoolInfo {
    id: string;
    name: string;
    tenantId: string;
    ipCount: number;
    activeIPs: number;
    totalDailyLimit: number;
    totalDailySent: number;
    utilizationPercent: number;
}

export interface WarmupScheduleInfo {
    schedule: number[];
    maxDay: number;
    maxLimit: number;
}

export const STATUS_CONFIG: Record<string, { label: string; color: string; bgColor: string; borderColor: string }> = {
    active: { label: 'Active', color: 'text-success', bgColor: 'bg-success/10', borderColor: 'border-success/20' },
    paused: { label: 'Paused', color: 'text-warning', bgColor: 'bg-warning/10', borderColor: 'border-warning/20' },
    inactive: { label: 'Not Started', color: 'text-muted-foreground', bgColor: 'bg-muted', borderColor: 'border-border' },
};
