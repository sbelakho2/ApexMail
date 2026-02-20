import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export default function StorybookCardsPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Cards" description="Card variants and layout" breadcrumbs={[{ label: 'Storybook' }, { label: 'Cards' }]} />
            <div className="grid gap-6 md:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle>Standard Card</CardTitle>
                        <CardDescription>Default surface with elevation</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                        <p className="text-sm text-muted-foreground">Premium delivery insights for your campaigns.</p>
                        <Badge variant="secondary">Active</Badge>
                    </CardContent>
                </Card>
                <Card variant="elevated">
                    <CardHeader>
                        <CardTitle>Elevated</CardTitle>
                        <CardDescription>Hover-ready surface</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="text-sm text-muted-foreground">Higher emphasis for key modules.</div>
                    </CardContent>
                </Card>
                <Card variant="outline">
                    <CardHeader>
                        <CardTitle>Outline</CardTitle>
                        <CardDescription>Minimal outline for dense layouts</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="text-sm text-muted-foreground">Use with neutral data tables.</div>
                    </CardContent>
                </Card>
                <Card variant="premium">
                    <CardHeader>
                        <CardTitle>Premium</CardTitle>
                        <CardDescription>Branded highlight card</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="text-sm text-muted-foreground">For featured insights.</div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}