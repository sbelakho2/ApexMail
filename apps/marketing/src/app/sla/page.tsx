import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Service Level Agreement',
    description: 'ApexMail SLA — our uptime and performance commitments.',
};

export default function SlaPage() {
    return (
        <div className="max-w-3xl mx-auto px-6 py-24">
            <h1 className="text-4xl font-bold mb-4">Service Level Agreement</h1>
            <p className="text-muted-foreground mb-8">Last updated: February 2026</p>

            <div className="prose prose-neutral dark:prose-invert max-w-none space-y-6 text-[15px] leading-relaxed">
                <h2 className="text-xl font-semibold mt-8">1. Uptime Commitment</h2>
                <table className="w-full border-collapse">
                    <thead>
                        <tr className="border-b">
                            <th className="text-left py-2">Plan</th>
                            <th className="text-left py-2">Monthly Uptime SLA</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr className="border-b"><td className="py-2">Free / Starter</td><td className="py-2">Best effort</td></tr>
                        <tr className="border-b"><td className="py-2">Pro</td><td className="py-2">99.9%</td></tr>
                        <tr className="border-b"><td className="py-2">Enterprise</td><td className="py-2">99.95%</td></tr>
                    </tbody>
                </table>

                <h2 className="text-xl font-semibold mt-8">2. Service Credits</h2>
                <table className="w-full border-collapse">
                    <thead>
                        <tr className="border-b">
                            <th className="text-left py-2">Monthly Uptime</th>
                            <th className="text-left py-2">Service Credit</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr className="border-b"><td className="py-2">&lt; 99.9%</td><td className="py-2">10% of monthly fee</td></tr>
                        <tr className="border-b"><td className="py-2">&lt; 99.0%</td><td className="py-2">25% of monthly fee</td></tr>
                        <tr className="border-b"><td className="py-2">&lt; 95.0%</td><td className="py-2">50% of monthly fee</td></tr>
                    </tbody>
                </table>

                <h2 className="text-xl font-semibold mt-8">3. Performance Targets</h2>
                <ul className="list-disc pl-6 space-y-2">
                    <li>API response time: &lt; 200ms p95</li>
                    <li>Email acceptance to first delivery attempt: &lt; 30 seconds p95</li>
                    <li>Webhook delivery: &lt; 5 seconds p95</li>
                </ul>

                <h2 className="text-xl font-semibold mt-8">4. Exclusions</h2>
                <p>
                    Scheduled maintenance (with 48-hour notice), force majeure events,
                    and issues caused by customer actions or third-party services are excluded.
                </p>

                <h2 className="text-xl font-semibold mt-8">5. Credit Requests</h2>
                <p>
                    Submit credit requests within 30 days of the incident to
                    <a href="mailto:support@apexmail.ee" className="text-primary hover:underline ml-1">support@apexmail.ee</a>.
                </p>
            </div>
        </div>
    );
}
