import { formatShortDate } from '../../lib/utils';

export type TimeRange = '24h' | '7d' | '30d' | '90d' | '12m';
export type AnalyticsSection = 'overview' | 'email' | 'tenants' | 'revenue' | 'sales';

export interface AnalyticsApiResponse {
    stats: {
        totalSent: number;
        totalDelivered: number;
        totalOpened: number;
        totalClicked: number;
        totalBounced: number;
        totalComplaints: number;
        deliveryRate: string;
        openRate: string;
        clickRate: string;
        bounceRate: string;
        complaintRate: string;
    };
    timeSeries: Array<{
        date: string;
        sent: number;
        delivered: number;
        opened: number;
        clicked: number;
    }>;
    providers: Array<{
        provider: string;
        count: number;
    }>;
}

export const TIME_RANGE_OPTIONS: TimeRange[] = ['24h', '7d', '30d', '90d', '12m'];

export const ANALYTICS_SECTION_TABS: Array<{ key: AnalyticsSection; label: string; icon: string }> = [
    { key: 'overview', label: 'Overview', icon: 'OV' },
    { key: 'email', label: 'Email Performance', icon: 'EM' },
    { key: 'tenants', label: 'Tenant Analytics', icon: 'TN' },
    { key: 'revenue', label: 'Revenue Intelligence', icon: 'RV' },
    { key: 'sales', label: 'Sales Pipeline', icon: 'SL' },
];

export const DELIVERABILITY_BY_ISP = [
    { name: 'Gmail', delivered: 98.9, inbox: 94.2, spam: 3.8 },
    { name: 'Microsoft 365', delivered: 99.1, inbox: 96.1, spam: 2.1 },
    { name: 'Yahoo/AOL', delivered: 97.8, inbox: 91.5, spam: 5.2 },
    { name: 'Apple iCloud', delivered: 99.4, inbox: 97.8, spam: 1.2 },
    { name: 'Other', delivered: 98.2, inbox: 93.4, spam: 4.1 },
];

export const TOP_TENANTS = [
    { name: 'Acme Corp', plan: 'Enterprise', emails: 2450000, delivery: 99.2, health: 95, mrr: 12500 },
    { name: 'TechStart Inc', plan: 'Enterprise', emails: 1820000, delivery: 98.8, health: 92, mrr: 8900 },
    { name: 'Global Media', plan: 'Professional', emails: 1540000, delivery: 98.5, health: 88, mrr: 4500 },
    { name: 'SaaS Company', plan: 'Professional', emails: 1230000, delivery: 99.1, health: 94, mrr: 3200 },
    { name: 'E-Commerce Plus', plan: 'Enterprise', emails: 980000, delivery: 97.8, health: 78, mrr: 6800 },
];

export const TOP_CAMPAIGNS = [
    { name: 'SaaS Founders Q1', sent: 8234, replies: 1847, meetings: 423, conversion: 5.1 },
    { name: 'Enterprise IT Leaders', sent: 5420, replies: 892, meetings: 245, conversion: 4.5 },
    { name: 'Product Hunt Followers', sent: 3200, replies: 534, meetings: 156, conversion: 4.9 },
];

export function toShortDate(dateValue: string): string {
    const date = new Date(dateValue);
    return Number.isNaN(date.getTime()) ? dateValue : formatShortDate(date);
}

export function buildHeatMapData(timeSeries: AnalyticsApiResponse['timeSeries']) {
    const byWeekdayTotals = new Array<number>(7).fill(0);
    const byWeekdayCounts = new Array<number>(7).fill(0);

    for (const point of timeSeries) {
        const date = new Date(point.date);
        if (Number.isNaN(date.getTime())) continue;
        const weekday = date.getDay();
        byWeekdayTotals[weekday] += point.sent;
        byWeekdayCounts[weekday] += 1;
    }

    const data: { day: number; hour: number; value: number }[] = [];
    for (let day = 0; day < 7; day++) {
        const weekdayAverage = byWeekdayCounts[day] > 0
            ? byWeekdayTotals[day] / byWeekdayCounts[day]
            : 0;
        for (let hour = 0; hour < 24; hour++) {
            const isBusinessHour = hour >= 9 && hour <= 17;
            const weight = isBusinessHour ? 1 : 0.35;
            data.push({
                day,
                hour,
                value: Math.round(weekdayAverage * weight),
            });
        }
    }
    return data;
}