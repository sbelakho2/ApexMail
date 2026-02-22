import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Terms of Service',
    description: 'ApexMail Terms of Service — the agreement governing your use of our platform.',
};

export default function TermsPage() {
    return (
        <div className="max-w-3xl mx-auto px-6 py-24">
            <h1 className="text-4xl font-bold mb-4">Terms of Service</h1>
            <p className="text-muted-foreground mb-8">Last updated: February 2026</p>

            <div className="prose prose-neutral dark:prose-invert max-w-none space-y-6 text-[15px] leading-relaxed">
                <h2 className="text-xl font-semibold mt-8">1. Acceptance</h2>
                <p>
                    By accessing or using the ApexMail service (&ldquo;Service&rdquo;), operated by
                    Bel Consulting OÜ (&ldquo;Company&rdquo;), you agree to be bound by these Terms.
                </p>

                <h2 className="text-xl font-semibold mt-8">2. Service Description</h2>
                <p>
                    ApexMail provides email infrastructure APIs including transactional email sending,
                    tracking, analytics, and compliance tools.
                </p>

                <h2 className="text-xl font-semibold mt-8">3. Acceptable Use</h2>
                <p>
                    You must not use the Service to send unsolicited bulk email (spam), phishing,
                    malware, or any content that violates applicable law. See our
                    <a href="/acceptable-use" className="text-primary hover:underline ml-1">Acceptable Use Policy</a>.
                </p>

                <h2 className="text-xl font-semibold mt-8">4. Account Responsibilities</h2>
                <p>
                    You are responsible for maintaining the confidentiality of your API keys and
                    account credentials. You must notify us immediately of any unauthorized access.
                </p>

                <h2 className="text-xl font-semibold mt-8">5. Billing &amp; Payment</h2>
                <p>
                    Fees are billed monthly in arrears based on your plan and usage.
                    All fees are in EUR and exclusive of applicable taxes.
                    Overdue invoices accrue interest at 1.5% per month.
                </p>

                <h2 className="text-xl font-semibold mt-8">6. SLA</h2>
                <p>
                    We commit to 99.9% monthly uptime for Scale and Enterprise plans. See our
                    <a href="/sla" className="text-primary hover:underline ml-1">Service Level Agreement</a> for
                    credit terms. Other plans are provided on a best-effort basis with no uptime guarantee.
                </p>

                <h2 className="text-xl font-semibold mt-8">7. Limitation of Liability</h2>
                <p>
                    To the maximum extent permitted by law, our aggregate liability shall not exceed
                    the fees paid by you in the 12 months preceding the claim.
                </p>

                <h2 className="text-xl font-semibold mt-8">8. Governing Law</h2>
                <p>
                    These Terms are governed by the laws of the Republic of Estonia.
                    Disputes shall be resolved in the courts of Tallinn, Estonia.
                </p>

                <h2 className="text-xl font-semibold mt-8">9. Contact</h2>
                <p>
                    Questions about these Terms:
                    <a href="mailto:legal@apexmail.ee" className="text-primary hover:underline ml-1">legal@apexmail.ee</a>.
                </p>
            </div>
        </div>
    );
}
