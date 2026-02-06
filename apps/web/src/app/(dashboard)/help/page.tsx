'use client';

import { BookOpen, MessageSquare, Mail, Zap, Shield, Key } from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';

const resources = [
    { icon: BookOpen, title: 'Documentation', description: 'Comprehensive guides for API integration and setup.', href: '/docs', color: 'text-primary bg-primary/10' },
    { icon: Key, title: 'API Reference', description: 'Full REST API documentation with request/response examples.', href: '/docs/api', color: 'text-success bg-success/10' },
    { icon: Zap, title: 'Quick Start Guide', description: 'Get up and running with ApexMail in under 5 minutes.', href: '/docs/quickstart', color: 'text-warning bg-warning/10' },
    { icon: Shield, title: 'Security & Compliance', description: 'SPF, DKIM, DMARC setup and compliance best practices.', href: '/docs/security', color: 'text-info bg-info/10' },
];

const faqs = [
    { q: 'How do I verify my sending domain?', a: 'Go to Settings → Domains, add your domain, and configure the DNS records shown (SPF, DKIM, DMARC). Verification typically takes a few minutes.' },
    { q: 'What is the sending rate limit?', a: 'Rate limits depend on your plan. Free tier: 100 emails/day. Pro: 50,000/day. Enterprise: custom limits. Check your plan details in Billing.' },
    { q: 'How do I handle bounces?', a: 'ApexMail automatically processes bounces and adds hard-bounced addresses to your suppression list. View them in the Compliance section.' },
    { q: 'Can I use a custom SMTP server?', a: 'ApexMail includes its own SMTP infrastructure with DKIM signing. You don\'t need a third-party SMTP service.' },
    { q: 'How do I set up webhooks?', a: 'Go to Settings → API & Webhooks. Add a webhook endpoint URL and select the events you want to receive (delivered, opened, clicked, bounced, etc.).' },
];

export default function HelpPage() {
    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Help & Support"
                description="Get help with ApexMail and contact our support team."
                breadcrumbs={[{ label: 'Help & Support' }]}
            />

            {/* Resources grid */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                {resources.map(r => (
                    <Card key={r.title} className="hover:border-primary/30 transition-colors cursor-pointer" role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') window.location.href = r.href; }}>
                        <CardContent className="p-6">
                            <div className={`inline-flex rounded-lg p-3 ${r.color} mb-4`}>
                                <r.icon className="h-5 w-5" />
                            </div>
                            <h3 className="font-semibold mb-1">{r.title}</h3>
                            <p className="text-sm text-muted-foreground">{r.description}</p>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* FAQ */}
            <Card>
                <CardHeader>
                    <CardTitle>Frequently Asked Questions</CardTitle>
                    <CardDescription>Quick answers to common questions</CardDescription>
                </CardHeader>
                <CardContent className="space-y-0">
                    {faqs.map((faq, i) => (
                        <div key={i}>
                            {i > 0 && <Separator className="my-4" />}
                            <div>
                                <h4 className="font-medium text-sm">{faq.q}</h4>
                                <p className="text-sm text-muted-foreground mt-1">{faq.a}</p>
                            </div>
                        </div>
                    ))}
                </CardContent>
            </Card>

            {/* Contact */}
            <Card>
                <CardContent className="flex flex-col sm:flex-row items-center justify-between gap-4 p-6">
                    <div className="flex items-center gap-4">
                        <div className="rounded-lg bg-primary/10 p-3"><MessageSquare className="h-6 w-6 text-primary" /></div>
                        <div>
                            <h3 className="font-semibold">Need more help?</h3>
                            <p className="text-sm text-muted-foreground">Our support team is available Mon–Fri, 9am–6pm EST.</p>
                        </div>
                    </div>
                    <div className="flex gap-3">
                        <Button variant="outline"><Mail className="mr-2 h-4 w-4" />Email Support</Button>
                        <Button><MessageSquare className="mr-2 h-4 w-4" />Live Chat</Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
