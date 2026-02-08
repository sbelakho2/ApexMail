/**
 * Autopilot Console API
 *
 * Proxies to the Sales Autopilot operator/loop endpoints (port 3010).
 * Falls back to demo data when the backend is unreachable.
 */

import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const AUTOPILOT_BASE = process.env.AUTOPILOT_API_URL || 'http://localhost:3010';

async function autopilotFetch(path: string, init?: RequestInit) {
    try {
        const res = await fetch(`${AUTOPILOT_BASE}${path}`, {
            ...init,
            headers: { 'Content-Type': 'application/json', ...init?.headers },
            signal: AbortSignal.timeout(5000),
        });
        return await res.json();
    } catch {
        return null;
    }
}

// ── Demo data used when backend is offline ──

const DEMO_OVERVIEW = {
    status: 'idle',
    canStart: true,
    canStop: false,
    hoursRun: 47,
    currentHour: 47,
    pendingApprovals: 3,
    activeCandidates: 5,
    safeModeCount: 1,
    safetyOk: true,
    safetyMessage: 'OK',
};

const DEMO_METRICS = {
    totalSent: 1243,
    totalOpened: 498,
    totalClicked: 112,
    totalReplied: 34,
    totalNegative: 6,
    totalBounced: 8,
    totalUnsubscribed: 3,
    aggregateOpenRate: 0.4006,
    aggregateReplyRate: 0.0274,
    aggregateNegativeRate: 0.0048,
    aggregateBounceRate: 0.0064,
};

const DEMO_BASELINE = {
    hasBaseline: true,
    comparison: {
        baseline: {
            subjectLabel: 'SaaS Founders — Give First',
            valuePropLabel: 'Free deliverability audit',
            openRate: 0.375,
            replyRate: 0.022,
            negativeRate: 0.005,
            impressions: 180,
        },
        aggregate: {
            openRate: 0.4006,
            replyRate: 0.0274,
            negativeRate: 0.0048,
            totalSent: 1243,
        },
        deltas: {
            openRateDelta: 0.0256,
            replyRateDelta: 0.0054,
            negativeRateDelta: -0.0002,
        },
        verdict: 'improving',
    },
};

const DEMO_CANDIDATES = [
    { armId: 'arm_base', label: 'SaaS Founders — Give First', stage: 'subject', icpCluster: 'saas_founders', impressions: 180, opens: 68, clicks: 15, replies: 4, negatives: 1, openRate: 0.378, replyRate: 0.022, negativeRate: 0.006, lowerBound: 0.012, upperBound: 0.040, consecutiveHoursBeating: 0, status: 'baseline' as const },
    { armId: 'arm_001', label: 'Quick Q re: {{company}} stack', stage: 'subject', icpCluster: 'saas_founders', impressions: 240, opens: 106, clicks: 28, replies: 9, negatives: 1, openRate: 0.442, replyRate: 0.0375, negativeRate: 0.004, lowerBound: 0.021, upperBound: 0.059, consecutiveHoursBeating: 4, status: 'promoted' as const },
    { armId: 'arm_002', label: 'Saw your launch on PH — congrats!', stage: 'subject', icpCluster: 'saas_founders', impressions: 190, opens: 78, clicks: 18, replies: 5, negatives: 0, openRate: 0.411, replyRate: 0.026, negativeRate: 0.0, lowerBound: 0.011, upperBound: 0.052, consecutiveHoursBeating: 2, status: 'active' as const },
    { armId: 'arm_003', label: 'Email at scale — how?', stage: 'subject', icpCluster: 'enterprise_it', impressions: 155, opens: 54, clicks: 10, replies: 3, negatives: 2, openRate: 0.348, replyRate: 0.019, negativeRate: 0.013, lowerBound: 0.006, upperBound: 0.044, consecutiveHoursBeating: 0, status: 'active' as const },
    { armId: 'arm_004', label: 'URGENT: Your emails are broken', stage: 'subject', icpCluster: 'saas_founders', impressions: 62, opens: 18, clicks: 3, replies: 0, negatives: 5, openRate: 0.290, replyRate: 0.0, negativeRate: 0.081, lowerBound: 0.0, upperBound: 0.030, consecutiveHoursBeating: 0, status: 'killed' as const },
    { armId: 'arm_005', label: 'variant-h46-1', stage: 'subject', icpCluster: 'saas_founders', impressions: 38, opens: 14, clicks: 4, replies: 1, negatives: 0, openRate: 0.368, replyRate: 0.026, negativeRate: 0.0, lowerBound: 0.002, upperBound: 0.078, consecutiveHoursBeating: 1, status: 'active' as const },
];

const DEMO_OUTCOMES = [
    { hour: 47, verdict: 'improved', baselineOpenRate: 0.375, aggregateOpenRate: 0.402, baselineReplyRate: 0.022, aggregateReplyRate: 0.031, candidatesPromoted: [], candidatesPruned: [], candidatesKilled: [], newVariantsSeeded: 0, safeModeTriggered: false },
    { hour: 46, verdict: 'held_steady', baselineOpenRate: 0.375, aggregateOpenRate: 0.388, baselineReplyRate: 0.022, aggregateReplyRate: 0.024, candidatesPromoted: ['arm_001'], candidatesPruned: [], candidatesKilled: [], newVariantsSeeded: 1, safeModeTriggered: false },
    { hour: 45, verdict: 'improved', baselineOpenRate: 0.375, aggregateOpenRate: 0.395, baselineReplyRate: 0.022, aggregateReplyRate: 0.028, candidatesPromoted: [], candidatesPruned: ['arm_old_2'], candidatesKilled: ['arm_004'], newVariantsSeeded: 1, safeModeTriggered: false },
    { hour: 44, verdict: 'retreated', baselineOpenRate: 0.375, aggregateOpenRate: 0.340, baselineReplyRate: 0.022, aggregateReplyRate: 0.016, candidatesPromoted: [], candidatesPruned: [], candidatesKilled: [], newVariantsSeeded: 0, safeModeTriggered: true },
    { hour: 43, verdict: 'held_steady', baselineOpenRate: 0.375, aggregateOpenRate: 0.380, baselineReplyRate: 0.022, aggregateReplyRate: 0.023, candidatesPromoted: [], candidatesPruned: [], candidatesKilled: [], newVariantsSeeded: 0, safeModeTriggered: false },
    { hour: 42, verdict: 'improved', baselineOpenRate: 0.375, aggregateOpenRate: 0.410, baselineReplyRate: 0.022, aggregateReplyRate: 0.030, candidatesPromoted: [], candidatesPruned: [], candidatesKilled: [], newVariantsSeeded: 1, safeModeTriggered: false },
];

const DEMO_PENDING = [
    { id: 'appr_001', contactEmail: 'cto@rocketship.io', subject: 'Quick Q re: Rocketship stack', bodyPreview: 'Hi Marcus, noticed you just closed your Series A…', armLabel: 'Quick Q re: {{company}} stack', campaignId: 'camp_1', createdAt: new Date(Date.now() - 300_000).toISOString(), status: 'pending' },
    { id: 'appr_002', contactEmail: 'founder@buildfast.co', subject: 'Saw your launch on PH — congrats!', bodyPreview: 'Hey Sarah, congrats on the Product Hunt launch…', armLabel: 'Saw your launch on PH — congrats!', campaignId: 'camp_1', createdAt: new Date(Date.now() - 180_000).toISOString(), status: 'pending' },
    { id: 'appr_003', contactEmail: 'vp-eng@scaleup.com', subject: 'Quick Q re: ScaleUp stack', bodyPreview: 'Hi Jordan, I\'ve been following ScaleUp\'s growth…', armLabel: 'Quick Q re: {{company}} stack', campaignId: 'camp_2', createdAt: new Date(Date.now() - 60_000).toISOString(), status: 'pending' },
];

const DEMO_ACTIONS = [
    { action: 'EMAIL_APPROVED', performedAt: new Date(Date.now() - 3600_000).toISOString(), operatorId: 'operator', detail: 'Approved appr_098' },
    { action: 'EMAIL_BULK_APPROVED', performedAt: new Date(Date.now() - 7200_000).toISOString(), operatorId: 'operator', detail: 'Approved 5 emails' },
    { action: 'SYSTEM_ON', performedAt: new Date(Date.now() - 86400_000 * 2).toISOString(), operatorId: 'operator', detail: 'Hourly optimisation loop started' },
    { action: 'SAFE_MODE_EXIT', performedAt: new Date(Date.now() - 86400_000 * 1).toISOString(), operatorId: 'operator', detail: 'Manually exited safe mode' },
];

const DEMO_SAFETY = {
    throttleStatus: { throttle: false, halt: false, reason: 'OK' },
    recentTraces: [],
    banditPoolCount: 4,
    totalArms: 12,
    frozenArms: 3,
    cadenceAtLimit: 8,
    cadenceStopped: 15,
};

// ── GET handler — returns combined dashboard data ──

export async function GET(request: NextRequest) {
    const section = request.nextUrl.searchParams.get('section') || 'overview';

    switch (section) {
        case 'overview': {
            const data = await autopilotFetch('/api/v1/operator/overview');
            return NextResponse.json(data?.data ?? DEMO_OVERVIEW);
        }
        case 'metrics': {
            const data = await autopilotFetch('/api/v1/operator/metrics');
            return NextResponse.json(data?.data ?? DEMO_METRICS);
        }
        case 'baseline': {
            const data = await autopilotFetch('/api/v1/operator/baseline');
            return NextResponse.json(data?.data ?? DEMO_BASELINE);
        }
        case 'candidates': {
            const data = await autopilotFetch('/api/v1/operator/candidates');
            return NextResponse.json(data?.data ?? DEMO_CANDIDATES);
        }
        case 'outcomes': {
            const data = await autopilotFetch('/api/v1/operator/outcomes');
            return NextResponse.json(data?.data ?? DEMO_OUTCOMES);
        }
        case 'pending': {
            const data = await autopilotFetch('/api/v1/operator/approvals/pending');
            return NextResponse.json(data?.data ?? DEMO_PENDING);
        }
        case 'actions': {
            const data = await autopilotFetch('/api/v1/operator/actions');
            return NextResponse.json(data?.data ?? DEMO_ACTIONS);
        }
        case 'safety': {
            const data = await autopilotFetch('/api/v1/operator/safety');
            return NextResponse.json(data?.data ?? DEMO_SAFETY);
        }
        default:
            return NextResponse.json({ error: 'Unknown section' }, { status: 400 });
    }
}

// ── POST handler — start/stop, approve/reject ──

export async function POST(request: NextRequest) {
    const body = await request.json();
    const action = body.action as string;

    switch (action) {
        case 'start': {
            const data = await autopilotFetch('/api/v1/operator/start', { method: 'POST' });
            return NextResponse.json(data ?? { success: true, message: 'Started (demo)' });
        }
        case 'stop': {
            const data = await autopilotFetch('/api/v1/operator/stop', { method: 'POST' });
            return NextResponse.json(data ?? { success: true, message: 'Stopped (demo)' });
        }
        case 'approve': {
            const id = body.id as string;
            const data = await autopilotFetch(`/api/v1/operator/approvals/${id}/approve`, { method: 'POST' });
            return NextResponse.json(data ?? { success: true });
        }
        case 'reject': {
            const id = body.id as string;
            const data = await autopilotFetch(`/api/v1/operator/approvals/${id}/reject`, { method: 'POST' });
            return NextResponse.json(data ?? { success: true });
        }
        case 'approve-all': {
            const data = await autopilotFetch('/api/v1/operator/approvals/approve-all', { method: 'POST' });
            return NextResponse.json(data ?? { success: true, approved: 0 });
        }
        case 'exit-safe-mode': {
            const data = await autopilotFetch('/api/v1/operator/safe-mode/exit', { method: 'POST' });
            return NextResponse.json(data ?? { success: true });
        }
        default:
            return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
}
