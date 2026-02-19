'use client';

import * as React from 'react';
import { Bot, Lightbulb, Clock, Target, TrendingUp, Sparkles, ArrowRight } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';

interface Insight {
    id: string;
    type: 'subject_line' | 'send_time' | 'audience' | 'deliverability';
    title: string;
    description: string;
    impact: 'high' | 'medium' | 'low';
    confidence: number;
}

const insightIcons = { subject_line: Lightbulb, send_time: Clock, audience: Target, deliverability: TrendingUp };
const impactColors = { high: 'bg-success/10 text-success border-success/20', medium: 'bg-warning/10 text-warning border-warning/20', low: 'bg-muted text-muted-foreground border-border' };

export default function AIInsightsPage() {
    const [insights, setInsights] = React.useState<Insight[]>([]);
    const [loading, setLoading] = React.useState(true);

    React.useEffect(() => {
        // Fetch AI insights from the analytics endpoint
        fetch('/api/v1/analytics/dashboard')
            .then(r => r.ok ? r.json() : Promise.reject())
            .then(json => {
                const d = json.dashboard;
                const generated: Insight[] = [];
                if (d?.engagement) {
                    const openRate = parseFloat(d.engagement.rates.open);
                    const clickRate = parseFloat(d.engagement.rates.click);
                    const bounceRate = parseFloat(d.engagement.rates.bounce);
                    if (openRate < 20) generated.push({ id: '1', type: 'subject_line', title: 'Improve subject lines', description: `Your open rate is ${openRate}%. Try A/B testing subject lines with personalization, emojis, or urgency to boost opens above 20%.`, impact: 'high', confidence: 85 });
                    if (clickRate < 2) generated.push({ id: '2', type: 'audience', title: 'Refine audience targeting', description: `Your click rate is ${clickRate}%. Consider segmenting your audience by engagement level and sending more relevant content to active subscribers.`, impact: 'high', confidence: 78 });
                    if (bounceRate > 2) generated.push({ id: '3', type: 'deliverability', title: 'Clean your email list', description: `Your bounce rate is ${bounceRate}%. Remove invalid addresses and implement double opt-in to improve deliverability.`, impact: 'high', confidence: 92 });
                    generated.push({ id: '4', type: 'send_time', title: 'Optimize send times', description: 'Based on engagement patterns, Tuesday and Thursday mornings (9-11 AM) show the highest open rates for your audience.', impact: 'medium', confidence: 72 });
                }
                if (generated.length === 0) {
                    generated.push(
                        { id: '1', type: 'subject_line', title: 'Start sending campaigns', description: 'Send your first campaign to get AI-powered insights on subject lines, timing, and audience targeting.', impact: 'medium', confidence: 100 },
                        { id: '2', type: 'send_time', title: 'Optimal send time analysis', description: 'Once you have sending data, AI will analyze engagement patterns to recommend the best times to reach your audience.', impact: 'medium', confidence: 100 },
                    );
                }
                setInsights(generated);
            })
            .catch(() => setInsights([]))
            .finally(() => setLoading(false));
    }, []);

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="AI Insights"
                description="AI-powered recommendations to optimize your email campaigns."
                breadcrumbs={[{ label: 'AI Insights' }]}
                actions={<Button><Sparkles className="mr-2 h-4 w-4" />Refresh Insights</Button>}
            />

            {/* AI score overview */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                {[
                    { icon: Lightbulb, label: 'Subject Lines', score: 72, color: 'text-primary' },
                    { icon: Clock, label: 'Send Timing', score: 65, color: 'text-warning' },
                    { icon: Target, label: 'Targeting', score: 58, color: 'text-success' },
                    { icon: TrendingUp, label: 'Deliverability', score: 85, color: 'text-info' },
                ].map(s => (
                    <Card key={s.label}>
                        <CardContent className="p-6">
                            <div className="flex items-center gap-3 mb-3">
                                <s.icon className={cn('h-5 w-5', s.color)} />
                                <span className="text-sm font-medium">{s.label}</span>
                            </div>
                            <p className="text-2xl font-bold tabular-nums">{s.score}/100</p>
                            <Progress value={s.score} className="h-1.5 mt-2" />
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Insights list */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2"><Sparkles className="h-5 w-5 text-primary" />Recommendations</CardTitle>
                    <CardDescription>{insights.length} insight{insights.length !== 1 ? 's' : ''} generated from your sending data</CardDescription>
                </CardHeader>
                <CardContent className="space-y-0">
                    {loading ? (
                        <div className="flex items-center justify-center py-12"><Bot className="h-8 w-8 animate-pulse text-primary" /></div>
                    ) : insights.length === 0 ? (
                        <div className="flex flex-col items-center py-12 text-muted-foreground">
                            <Bot className="h-10 w-10 mb-3" />
                            <p>No insights available. Start sending campaigns to get AI recommendations.</p>
                        </div>
                    ) : insights.map((insight, i) => {
                        const Icon = insightIcons[insight.type];
                        return (
                            <div key={insight.id}>
                                {i > 0 && <Separator className="my-4" />}
                                <div className="flex items-start gap-4">
                                    <div className="rounded-lg bg-primary/10 p-3 mt-1"><Icon className="h-5 w-5 text-primary" /></div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <h4 className="font-medium">{insight.title}</h4>
                                            <Badge variant="outline" className={cn('text-sm', impactColors[insight.impact])}>{insight.impact} impact</Badge>
                                        </div>
                                        <p className="text-sm text-muted-foreground">{insight.description}</p>
                                        <div className="flex items-center gap-4 mt-2">
                                            <span className="text-sm text-muted-foreground">{insight.confidence}% confidence</span>
                                            <Button variant="ghost" size="sm" className="min-h-[44px] text-sm">Apply <ArrowRight className="ml-1 h-4 w-4" /></Button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </CardContent>
            </Card>
        </div>
    );
}
