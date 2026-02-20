'use client';

import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';

export default function StorybookInputsPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Inputs" description="Form elements and states" breadcrumbs={[{ label: 'Storybook' }, { label: 'Inputs' }]} />
            <Card>
                <CardContent className="grid gap-6 p-6 md:grid-cols-2">
                    <div className="grid gap-2">
                        <Label htmlFor="email">Email</Label>
                        <Input id="email" placeholder="name@company.com" />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="company">Company</Label>
                        <Input id="company" defaultValue="ApexMail" />
                    </div>
                    <div className="grid gap-2 md:col-span-2">
                        <Label htmlFor="message">Message</Label>
                        <Textarea id="message" rows={4} defaultValue="New onboarding sequence draft." />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="segment">Segment</Label>
                        <Select defaultValue="enterprise">
                            <SelectTrigger id="segment">
                                <SelectValue placeholder="Select segment" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="enterprise">Enterprise</SelectItem>
                                <SelectItem value="mid">Mid-Market</SelectItem>
                                <SelectItem value="startup">Startup</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label>Status</Label>
                        <div className="flex items-center gap-3">
                            <Switch defaultChecked />
                            <span className="text-sm text-muted-foreground">Active</span>
                        </div>
                        <div className="flex items-center gap-3">
                            <Checkbox id="beta" defaultChecked />
                            <Label htmlFor="beta">Include beta users</Label>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}