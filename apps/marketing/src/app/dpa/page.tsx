import type { Metadata } from 'next';

export const dynamic = 'force-static';
export const revalidate = 3600;

export const metadata: Metadata = {
    title: 'Data Processing Agreement',
    description: 'ApexMail DPA — GDPR-compliant data processing terms.',
    openGraph: {
        title: 'Data Processing Agreement | ApexMail',
        description: 'ApexMail DPA — GDPR-compliant data processing terms.',
        type: 'website',
        images: ['/og-image.png'],
    },
    twitter: {
        card: 'summary_large_image',
        title: 'Data Processing Agreement | ApexMail',
        description: 'ApexMail DPA — GDPR-compliant data processing terms.',
        images: ['/og-image.png'],
    },
};

export default function DpaPage() {
    return (
        <div className="max-w-3xl mx-auto px-6 py-24">
            <h1 className="text-4xl font-bold mb-4">Data Processing Agreement</h1>
            <p className="text-surface-500 mb-8">Last updated: February 2026</p>

            <div className="prose prose-neutral max-w-none space-y-6 text-[15px] leading-relaxed">
                <p>
                    This Data Processing Agreement (&ldquo;DPA&rdquo;) forms part of the Terms of Service
                    between you (&ldquo;Controller&rdquo;) and Bel Consulting OÜ (&ldquo;Processor&rdquo;).
                </p>

                <h2 className="text-xl font-semibold mt-8">1. Scope &amp; Roles</h2>
                <p>
                    You are the data controller. We act as your data processor for personal data
                    contained in emails sent via our API (recipient addresses, message content, metadata).
                </p>

                <h2 className="text-xl font-semibold mt-8">2. Processing Instructions</h2>
                <p>
                    We process personal data solely on your documented instructions, which include
                    the API calls you make to send, track, and manage email communications.
                </p>

                <h2 className="text-xl font-semibold mt-8">3. Security Measures</h2>
                <ul className="list-disc pl-6 space-y-2">
                    <li>AES-256 encryption at rest, TLS 1.2+ in transit</li>
                    <li>Isolated tenant environments with row-level security</li>
                    <li>SOC 2 Type II and ISO 27001 certifications (in progress)</li>
                    <li>Regular penetration testing and vulnerability scanning</li>
                </ul>

                <h2 className="text-xl font-semibold mt-8">4. Data Location</h2>
                <p>
                    All processing occurs within the European Union (Hetzner, Finland/Germany).
                    No personal data is transferred outside the EEA.
                </p>

                <h2 className="text-xl font-semibold mt-8">5. Sub-processors</h2>
                <p>
                    Current sub-processors: Stripe (billing), Hetzner (hosting), Cloudflare (edge).
                    We will notify you 30 days before engaging new sub-processors.
                </p>

                <h2 className="text-xl font-semibold mt-8">6. Data Subject Rights</h2>
                <p>
                    We provide tools (API endpoints for data export and deletion) to help you
                    fulfil data subject access, portability, and erasure requests.
                </p>

                <h2 className="text-xl font-semibold mt-8">7. Breach Notification</h2>
                <p>
                    We will notify you of any personal data breach without undue delay and
                    within 48 hours of becoming aware of it.
                </p>

                <h2 className="text-xl font-semibold mt-8">8. Contact</h2>
                <p>
                    DPA enquiries:
                    <a href="mailto:dpo@apexmail.ee" className="text-primary hover:underline ml-1">dpo@apexmail.ee</a>.
                </p>
            </div>
        </div>
    );
}
