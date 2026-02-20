import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';

export default function SettingsBillingPage() {
    return (
        <div className="space-y-6">
            <PageHeader
                title="Billing"
                description="Review plan details, usage, and payment methods."
                breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Billing' }]}
                actions={<Button variant="outline">Manage Plan</Button>}
            />

            <div className="grid gap-6 lg:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle>Current Plan</CardTitle>
                        <CardDescription>Pro Plan · $249 / month</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="flex items-center justify-between">
                            <span className="text-sm text-muted-foreground">Status</span>
                            <Badge variant="secondary">Active</Badge>
                        </div>
                        <Separator />
                        <div className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                                <span>Monthly sends</span>
                                <span className="font-medium">1,000,000</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Deliverability monitoring</span>
                                <span className="font-medium">Included</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Dedicated IPs</span>
                                <span className="font-medium">2</span>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Payment Method</CardTitle>
                        <CardDescription>Primary card on file</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="font-medium">Visa ending 2418</div>
                                <div className="text-sm text-muted-foreground">Expires 09/28</div>
                            </div>
                            <Button variant="outline" size="sm">Update</Button>
                        </div>
                        <Separator />
                        <div className="text-sm text-muted-foreground">
                            Next invoice scheduled for March 1, 2026.
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}