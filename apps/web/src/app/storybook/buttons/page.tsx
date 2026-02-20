'use client';

import { PageHeader } from '@/components/layout/page-header';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

const variants = [
    'default',
    'secondary',
    'outline',
    'ghost',
    'link',
    'premium',
    'success',
    'warning',
    'glass',
    'destructive',
] as const;

const sizes = ['default', 'sm', 'lg', 'xl', 'icon', 'icon-sm', 'icon-lg'] as const;

export default function StorybookButtonsPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Buttons" description="Variant and size matrix" breadcrumbs={[{ label: 'Storybook' }, { label: 'Buttons' }]} />
            <Card>
                <CardContent className="space-y-6 p-6">
                    <div className="grid gap-4 md:grid-cols-2">
                        {variants.map((variant) => (
                            <div key={variant} className="flex flex-wrap items-center gap-3">
                                <Button variant={variant}>Primary</Button>
                                <Button variant={variant} size="sm">Small</Button>
                                <Button variant={variant} size="lg">Large</Button>
                                <Button variant={variant} size="icon">A</Button>
                            </div>
                        ))}
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                        {sizes.map((size) => (
                            <Button key={size} size={size as any}>Size {size}</Button>
                        ))}
                        <Button disabled>Disabled</Button>
                        <Button loading>Loading</Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}