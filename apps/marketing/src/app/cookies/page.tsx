import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Cookie Policy',
    description: 'ApexMail Cookie Policy — how we use cookies and similar technologies.',
    openGraph: {
        title: 'Cookie Policy | ApexMail',
        description: 'ApexMail Cookie Policy — how we use cookies and similar technologies.',
        type: 'website',
        images: ['/og-image.png'],
    },
    twitter: {
        card: 'summary_large_image',
        title: 'Cookie Policy | ApexMail',
        description: 'ApexMail Cookie Policy — how we use cookies and similar technologies.',
        images: ['/og-image.png'],
    },
};

export default function CookiesPage() {
    return (
        <div className="max-w-3xl mx-auto px-6 py-24">
            <h1 className="text-4xl font-bold mb-4">Cookie Policy</h1>
            <p className="text-surface-500 mb-8">Last updated: February 2026</p>

            <div className="prose prose-neutral max-w-none space-y-6 text-[15px] leading-relaxed">
                <h2 className="text-xl font-semibold mt-8">What Are Cookies?</h2>
                <p>
                    Cookies are small text files stored on your device when you visit our website.
                    They help us recognise your browser and remember your preferences.
                </p>

                <h2 className="text-xl font-semibold mt-8">Cookies We Use</h2>
                <table className="w-full border-collapse">
                    <thead>
                        <tr className="border-b">
                            <th scope="col" className="text-left py-2">Cookie</th>
                            <th scope="col" className="text-left py-2">Purpose</th>
                            <th scope="col" className="text-left py-2">Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr className="border-b"><td className="py-2">session_id</td><td className="py-2">Authentication (essential)</td><td className="py-2">Session</td></tr>
                        <tr className="border-b"><td className="py-2">csrf_token</td><td className="py-2">Security (essential)</td><td className="py-2">Session</td></tr>
                        <tr className="border-b"><td className="py-2">preferences</td><td className="py-2">UI settings (functional)</td><td className="py-2">1 year</td></tr>
                    </tbody>
                </table>

                <h2 className="text-xl font-semibold mt-8">Third-Party Cookies</h2>
                <p>
                    We do not use third-party advertising or tracking cookies. Analytics are
                    processed server-side without client-side tracking scripts.
                </p>

                <h2 className="text-xl font-semibold mt-8">Managing Cookies</h2>
                <p>
                    You can control cookies through your browser settings. Disabling essential
                    cookies may affect your ability to use the dashboard.
                </p>

                <h2 className="text-xl font-semibold mt-8">Contact</h2>
                <p>
                    Questions about our cookie usage:
                    <a href="mailto:privacy@apexmail.ee" className="text-primary hover:underline ml-1">privacy@apexmail.ee</a>.
                </p>
            </div>
        </div>
    );
}
