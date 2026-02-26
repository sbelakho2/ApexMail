import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Acceptable Use Policy',
    description: 'ApexMail Acceptable Use Policy — rules governing how the service may be used.',
};

export default function AcceptableUsePage() {
    return (
        <div className="max-w-3xl mx-auto px-6 py-24">
            <h1 className="text-4xl font-bold mb-4">Acceptable Use Policy</h1>
            <p className="text-surface-500 mb-8">Last updated: February 2026</p>

            <div className="prose prose-neutral max-w-none space-y-6 text-[15px] leading-relaxed">
                <h2 className="text-xl font-semibold mt-8">Prohibited Activities</h2>
                <p>You may not use the ApexMail service to:</p>
                <ul className="list-disc pl-6 space-y-2">
                    <li>Send unsolicited commercial email (spam) or bulk messages to recipients who have not opted in</li>
                    <li>Send phishing emails, malware, or deceptive content</li>
                    <li>Harvest email addresses or scrape data from third-party services</li>
                    <li>Impersonate another person or entity</li>
                    <li>Violate CAN-SPAM, GDPR, CASL, or other applicable anti-spam and privacy regulations</li>
                    <li>Send content that is illegal, harmful, threatening, or discriminatory</li>
                    <li>Attempt to bypass sending limits, rate limits, or abuse-prevention measures</li>
                    <li>Use the service to test email security systems without authorization</li>
                </ul>

                <h2 className="text-xl font-semibold mt-8">Enforcement</h2>
                <p>
                    Violations may result in immediate account suspension, API key revocation,
                    and permanent termination of service. We reserve the right to report illegal
                    activity to the appropriate authorities.
                </p>

                <h2 className="text-xl font-semibold mt-8">Reporting Abuse</h2>
                <p>
                    To report abuse:
                    <a href="mailto:abuse@apexmail.ee" className="text-primary hover:underline ml-1">abuse@apexmail.ee</a>.
                </p>
            </div>
        </div>
    );
}
