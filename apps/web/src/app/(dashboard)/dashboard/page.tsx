'use client';

import * as React from 'react';
import {
    Send,
    Users,
    Mail,
    ArrowUpRight,
    ArrowDownRight,
    MoreHorizontal,
    Eye,
    MousePointer,
    Calendar,
    Zap,
} from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { ApexAreaChart, ApexBarChart } from '@/components/charts';
import { cn, formatNumber, formatPercent, formatRelativeTime } from '@/lib/utils';

// Mock data - in production, this would come from the API
const stats = [
    {
        title: 'Total Subscribers',
        value: 48293,
        change: 12.5,
        changeType: 'positive' as const,
        icon: Users,
        color: 'text-primary',
        bgColor: 'bg-primary/10',
    },
    {
        title: 'Emails Sent',
        value: 1284892,
        change: 8.2,
        changeType: 'positive' as const,
        icon: Send,
        color: 'text-success',
        bgColor: 'bg-success/10',
    },
    {
        title: 'Average Open Rate',
        value: 24.8,
        change: -2.1,
        changeType: 'negative' as const,
        icon: Eye,
        color: 'text-warning',
        bgColor: 'bg-warning/10',
        isPercent: true,
    },
    {
        title: 'Click-through Rate',
        value: 3.2,
        change: 0.8,
        changeType: 'positive' as const,
        icon: MousePointer,
        color: 'text-error',
        bgColor: 'bg-error/10',
        isPercent: true,
    },
];

const recentCampaigns = [
    {
        id: '1',
        name: 'Summer Sale Announcement',
        status: 'sent',
        sentAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        sent: 12458,
        openRate: 28.4,
        clickRate: 4.2,
    },
    {
        id: '2',
        name: 'Weekly Newsletter #42',
        status: 'sent',
        sentAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        sent: 34521,
        openRate: 22.1,
        clickRate: 2.8,
    },
    {
        id: '3',
        name: 'Product Launch Teaser',
        status: 'scheduled',
        scheduledAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        sent: 0,
        openRate: 0,
        clickRate: 0,
    },
    {
        id: '4',
        name: 'Re-engagement Campaign',
        status: 'sending',
        sentAt: new Date().toISOString(),
        sent: 4521,
        openRate: 18.5,
        clickRate: 1.9,
    },
    {
        id: '5',
        name: 'Black Friday Preview',
        status: 'draft',
        sent: 0,
        openRate: 0,
        clickRate: 0,
    },
];

const engagementData = [
    { date: 'Mon', opens: 4200, clicks: 1800 },
    { date: 'Tue', opens: 3800, clicks: 1600 },
    { date: 'Wed', opens: 5100, clicks: 2200 },
    { date: 'Thu', opens: 4600, clicks: 1900 },
    { date: 'Fri', opens: 5800, clicks: 2400 },
    { date: 'Sat', opens: 3200, clicks: 1400 },
    { date: 'Sun', opens: 2800, clicks: 1200 },
];

const subscriberGrowth = [
    { month: 'Jan', subscribers: 32000 },
    { month: 'Feb', subscribers: 34500 },
    { month: 'Mar', subscribers: 37200 },
    { month: 'Apr', subscribers: 39800 },
    { month: 'May', subscribers: 43500 },
    { month: 'Jun', subscribers: 48293 },
];

const topPerformingLists = [
    { name: 'VIP Customers', subscribers: 5420, openRate: 45.2, growth: 12.3 },
    { name: 'Newsletter', subscribers: 28450, openRate: 24.8, growth: 8.1 },
    { name: 'Product Updates', subscribers: 12320, openRate: 32.1, growth: 15.7 },
];

const statusStyles: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'secondary' }> = {
    sent: { label: 'Sent', variant: 'success' },
    sending: { label: 'Sending', variant: 'warning' },
    scheduled: { label: 'Scheduled', variant: 'secondary' },
    draft: { label: 'Draft', variant: 'default' },
    paused: { label: 'Paused', variant: 'default' },
};

export default function DashboardPage() {
    return (
        <div className="space-y-8">
            <PageHeader
                title="Dashboard"
                description="Welcome back! Here's an overview of your email marketing performance."
                actions={
                    <>
                        <Button variant="outline">
                            <Calendar className="mr-2 h-4 w-4" />
                            Last 30 Days
                        </Button>
                        <Button>
                            <Send className="mr-2 h-4 w-4" />
                            New Campaign
                        </Button>
                    </>
                }
            />

            {/* Stats Grid */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {stats.map((stat) => (
                    <Card key={stat.title}>
                        <CardContent className="p-6">
                            <div className="flex items-center justify-between">
                                <div className={cn('rounded-sm p-2', stat.bgColor)}>
                                    <stat.icon className={cn('h-5 w-5', stat.color)} />
                                </div>
                                <div
                                    className={cn(
                                        'flex items-center text-sm font-bold tabular-nums',
                                        stat.changeType === 'positive'
                                            ? 'text-success'
                                            : 'text-destructive'
                                    )}
                                >
                                    {stat.changeType === 'positive' ? (
                                        <ArrowUpRight className="mr-1 h-4 w-4" />
                                    ) : (
                                        <ArrowDownRight className="mr-1 h-4 w-4" />
                                    )}
                                    {Math.abs(stat.change)}%
                                </div>
                            </div>
                            <div className="mt-4">
                                <p className="text-sm text-muted-foreground">{stat.title}</p>
                                <p className="text-2xl font-bold tabular-nums">
                                    {stat.isPercent
                                        ? formatPercent(stat.value / 100)
                                        : formatNumber(stat.value)}
                                </p>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Charts Row */}
            <div className="grid gap-6 lg:grid-cols-2">
                <ApexAreaChart
                    data={engagementData}
                    xKey="date"
                    areas={[
                        { key: 'opens', name: 'Opens', color: '#2563EB' },
                        { key: 'clicks', name: 'Clicks', color: '#10B981' },
                    ]}
                    title="Engagement This Week"
                    description="Opens and clicks over the past 7 days"
                    height={300}
                />

                <ApexBarChart
                    data={subscriberGrowth}
                    xKey="month"
                    bars={[{ key: 'subscribers', name: 'Subscribers', color: '#2563EB' }]}
                    title="Subscriber Growth"
                    description="Total subscribers over the past 6 months"
                    height={300}
                />
            </div>

            {/* Recent Campaigns & Top Lists */}
            <div className="grid gap-6 lg:grid-cols-3">
                {/* Recent Campaigns */}
                <Card className="lg:col-span-2">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <div>
                            <CardTitle>Recent Campaigns</CardTitle>
                            <CardDescription>
                                Your latest email campaigns and their performance
                            </CardDescription>
                        </div>
                        <Button variant="ghost" size="sm">
                            View All
                        </Button>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Campaign</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead className="text-right">Sent</TableHead>
                                    <TableHead className="text-right">Open Rate</TableHead>
                                    <TableHead className="text-right">CTR</TableHead>
                                    <TableHead />
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {recentCampaigns.map((campaign) => (
                                    <TableRow key={campaign.id}>
                                        <TableCell>
                                            <div>
                                                <p className="font-medium">{campaign.name}</p>
                                                <p className="text-sm text-muted-foreground">
                                                    {campaign.sentAt
                                                        ? formatRelativeTime(new Date(campaign.sentAt))
                                                        : campaign.scheduledAt
                                                          ? `Scheduled for ${formatRelativeTime(new Date(campaign.scheduledAt))}`
                                                          : 'Not scheduled'}
                                                </p>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant={statusStyles[campaign.status].variant}>
                                                {statusStyles[campaign.status].label}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="text-right">
                                            {formatNumber(campaign.sent)}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            {campaign.openRate > 0
                                                ? formatPercent(campaign.openRate / 100)
                                                : '-'}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            {campaign.clickRate > 0
                                                ? formatPercent(campaign.clickRate / 100)
                                                : '-'}
                                        </TableCell>
                                        <TableCell>
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild>
                                                    <Button variant="ghost" size="icon">
                                                        <MoreHorizontal className="h-4 w-4" />
                                                    </Button>
                                                </DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem>View Details</DropdownMenuItem>
                                                    <DropdownMenuItem>Duplicate</DropdownMenuItem>
                                                    <DropdownMenuItem>Edit</DropdownMenuItem>
                                                    <DropdownMenuItem destructive>Delete</DropdownMenuItem>
                                                </DropdownMenuContent>
                                            </DropdownMenu>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </CardContent>
                </Card>

                {/* Top Performing Lists */}
                <Card>
                    <CardHeader>
                        <CardTitle>Top Performing Lists</CardTitle>
                        <CardDescription>Lists with the highest engagement</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        {topPerformingLists.map((list, index) => (
                            <div key={list.name} className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <div
                                            className={cn(
                                                'flex h-8 w-8 items-center justify-center rounded-sm text-sm font-bold text-white',
                                                index === 0
                                                    ? 'bg-primary'
                                                    : index === 1
                                                      ? 'bg-success'
                                                      : 'bg-warning'
                                            )}
                                        >
                                            {index + 1}
                                        </div>
                                        <div>
                                            <p className="font-medium">{list.name}</p>
                                            <p className="text-sm text-muted-foreground">
                                                {formatNumber(list.subscribers)} subscribers
                                            </p>
                                        </div>
                                    </div>
                                    <Badge variant="success" size="sm">
                                        +{list.growth}%
                                    </Badge>
                                </div>
                                <div className="space-y-1">
                                    <div className="flex justify-between text-sm">
                                        <span className="text-muted-foreground">Open Rate</span>
                                        <span className="font-medium">
                                            {formatPercent(list.openRate / 100)}
                                        </span>
                                    </div>
                                    <Progress value={list.openRate} className="h-2" />
                                </div>
                            </div>
                        ))}
                    </CardContent>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card>
                <CardHeader>
                    <CardTitle>Quick Actions</CardTitle>
                    <CardDescription>Common tasks to help you get started</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6">
                            <Send className="h-6 w-6 text-primary" />
                            <span>Create Campaign</span>
                        </Button>
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6">
                            <Users className="h-6 w-6 text-success" />
                            <span>Import Contacts</span>
                        </Button>
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6">
                            <Mail className="h-6 w-6 text-warning" />
                            <span>Design Template</span>
                        </Button>
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6">
                            <Zap className="h-6 w-6 text-error" />
                            <span>Setup Automation</span>
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
