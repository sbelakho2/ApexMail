import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';

export default function StorybookTypographyPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Typography" description="Type scale and hierarchy" breadcrumbs={[{ label: 'Storybook' }, { label: 'Typography' }]} />
            <Card>
                <CardContent className="space-y-4 p-6">
                    <h1>Deliverability insights at scale</h1>
                    <h2>Campaign performance overview</h2>
                    <h3>Engagement trends</h3>
                    <p className="text-muted-foreground">
                        ApexMail provides cryptographic proof of delivery for every message, ensuring
                        that enterprise communication meets compliance and audit requirements.
                    </p>
                    <p>
                        Use refined typography to separate headings, subheadings, and supporting text
                        for premium clarity across the UI.
                    </p>
                </CardContent>
            </Card>
        </div>
    );
}