'use client';

import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';

export default function StorybookModalsPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Modals" description="Dialog and overlay treatments" breadcrumbs={[{ label: 'Storybook' }, { label: 'Modals' }]} />
            <Card>
                <CardContent className="p-6">
                    <Dialog open>
                        <DialogContent>
                            <DialogHeader>
                                <DialogTitle>Confirm publish</DialogTitle>
                                <DialogDescription>
                                    You are about to publish a campaign to 12,458 subscribers.
                                </DialogDescription>
                            </DialogHeader>
                            <DialogFooter>
                                <Button variant="outline">Cancel</Button>
                                <Button>Publish</Button>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                </CardContent>
            </Card>
        </div>
    );
}