import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

export default function NewCampaignPage() {
    return (
        <div className="space-y-6">
            <PageHeader
                title="New Campaign"
                description="Create and configure your next campaign."
                breadcrumbs={[{ label: 'Campaigns', href: '/campaigns' }, { label: 'New Campaign' }]}
            />

            <Card>
                <CardHeader>
                    <CardTitle>Campaign Setup</CardTitle>
                    <CardDescription>Define audience, message, and scheduling.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-5">
                    <div className="grid gap-2">
                        <Label htmlFor="name">Campaign Name</Label>
                        <Input id="name" defaultValue="Weekly Product Update" />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="subject">Email Subject</Label>
                        <Input id="subject" defaultValue="New features your team can use today" />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="audience">Audience</Label>
                        <Select defaultValue="all">
                            <SelectTrigger id="audience">
                                <SelectValue placeholder="Select audience" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Subscribers</SelectItem>
                                <SelectItem value="newsletter">Newsletter</SelectItem>
                                <SelectItem value="vip">VIP Customers</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="content">Content Preview</Label>
                        <Textarea id="content" rows={6} defaultValue="Hi there,\n\nWe shipped updates to improve deliverability and analytics visibility this week." />
                    </div>
                    <div className="flex justify-end gap-3">
                        <Button variant="outline">Save Draft</Button>
                        <Button>Schedule Campaign</Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}