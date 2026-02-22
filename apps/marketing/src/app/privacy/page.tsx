import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Privacy Policy',
    description: 'ApexMail Privacy Policy — how we collect, use, and protect your data.',
};

export default function PrivacyPage() {
    return (
        <div className="max-w-3xl mx-auto px-6 py-24">
            <h1 className="text-4xl font-bold mb-4">Privacy Policy</h1>
            <p className="text-muted-foreground mb-8">Last updated: February 2026</p>

            <div className="prose prose-neutral dark:prose-invert max-w-none space-y-6 text-[15px] leading-relaxed">
                <h2 className="text-xl font-semibold mt-8">1. Data Controller</h2>
                <p>
                    Bel Consulting OÜ (trading as ApexMail), registry code 16192499,
                    Sakala 7-2, 10141 Tallinn, Estonia (&ldquo;we&rdquo;, &ldquo;us&rdquo;).
                    Contact: <a href="mailto:privacy@apexmail.ee" className="text-primary hover:underline">privacy@apexmail.ee</a>.
                </p>

                <h2 className="text-xl font-semibold mt-8">2. Data We Collect</h2>
                <p>
                    <strong>Account data:</strong> name, email, company name, billing information.
                    <br /><strong>Usage data:</strong> API calls, sending volumes, event logs.
                    <br /><strong>Technical data:</strong> IP addresses, browser/device info, cookies.
                </p>

                <h2 className="text-xl font-semibold mt-8">3. Legal Basis (GDPR Art. 6)</h2>
                <p>
                    We process data on the basis of (a) contract performance, (b) legitimate interest in
                    service security and improvement, and (c) your consent where required.
                </p>

                <h2 className="text-xl font-semibold mt-8">4. Data Retention</h2>
                <p>
                    Account data is retained for the duration of your subscription plus 90 days.
                    Transactional email metadata is retained for up to 30 days after delivery.
                    Audit logs are retained for up to 2 years, depending on plan.
                </p>

                <h2 className="text-xl font-semibold mt-8">5. Your Rights</h2>
                <p>
                    You have the right to access, rectify, erase, restrict, port, and object to
                    processing of your personal data. Contact us at privacy@apexmail.ee.
                </p>

                <h2 className="text-xl font-semibold mt-8">6. Data Transfers</h2>
                <p>
                    All data is stored within the European Union (Estonia). We do not transfer personal
                    data outside the EEA unless required by law or with appropriate safeguards.
                </p>

                <h2 className="text-xl font-semibold mt-8">7. Sub-processors</h2>
                <p>
                    We use Stripe (payments), Hetzner (infrastructure), and Cloudflare (CDN/DDoS).
                    A full list is available upon request.
                </p>

                <h2 className="text-xl font-semibold mt-8">8. Contact &amp; Complaints</h2>
                <p>
                    For privacy enquiries: privacy@apexmail.ee. You may also lodge a complaint with
                    the Estonian Data Protection Inspectorate (Andmekaitse Inspektsioon).
                </p>
            </div>
        </div>
    );
}
