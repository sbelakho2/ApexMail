import type { Metadata } from 'next';
import localFont from 'next/font/local';
import './globals.css';
import { Toaster } from '@/components/ui/toaster';

const apex = localFont({
    src: [
        { path: '../../public/fonts/InterVariable.woff2', weight: '100 900', style: 'normal' },
        { path: '../../public/fonts/InterVariable-Italic.woff2', weight: '100 900', style: 'italic' },
    ],
    variable: '--font-apex',
    display: 'swap',
});
const plexMono = localFont({
    src: [
        { path: '../../public/fonts/JetBrainsMono-Variable.ttf', weight: '100 800', style: 'normal' },
        { path: '../../public/fonts/JetBrainsMono-Italic-Variable.ttf', weight: '100 800', style: 'italic' },
    ],
    variable: '--font-mono',
    display: 'swap',
});

export const metadata: Metadata = {
    title: {
        default: 'ApexMail - Enterprise Email Infrastructure',
        template: '%s | ApexMail',
    },
    description:
        'Enterprise email infrastructure with cryptographic proof of delivery, EU-compliance, and advanced analytics for mission-critical communications.',
    keywords: [
        'email API',
        'email infrastructure',
        'GDPR compliant email',
        'HIPAA email',
        'transactional email',
        'verifiable delivery',
    ],
    authors: [{ name: 'ApexMail' }],
    creator: 'ApexMail',
    openGraph: {
        type: 'website',
        locale: 'en_US',
        url: 'https://apexmail.ee',
        siteName: 'ApexMail',
        title: 'ApexMail - Enterprise Email Infrastructure',
        description:
            'Enterprise email infrastructure with cryptographic proof of delivery and EU-compliance.',
    },
    twitter: {
        card: 'summary_large_image',
        title: 'ApexMail - Enterprise Email Infrastructure',
        description:
            'Enterprise email infrastructure with cryptographic proof of delivery.',
        creator: '@apexmail',
    },
    robots: {
        index: true,
        follow: true,
    },
    manifest: '/manifest.json',
    icons: {
        icon: '/favicon.ico',
        shortcut: '/favicon-16x16.png',
        apple: '/apple-touch-icon.png',
    },
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en" suppressHydrationWarning className={`${apex.variable} ${plexMono.variable}`}>
            <head>
                <meta name="theme-color" content="#2563EB" />
                <meta name="color-scheme" content="light dark" />
                {/* FIX-095: Prevent flash of wrong theme on load */}
                <script src="/theme-init.js" />
            </head>
            <body className="font-apex antialiased text-[16px] leading-[1.55]">
                <main className="min-h-screen bg-background">{children}</main>
                <Toaster />
            </body>
        </html>
    );
}
