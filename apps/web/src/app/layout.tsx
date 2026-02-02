import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Toaster } from '@/components/ui/toaster';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

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
        url: 'https://apexmail.io',
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
        <html lang="en" suppressHydrationWarning>
            <head>
                <meta name="theme-color" content="#2563EB" />
                <meta name="color-scheme" content="light dark" />
                <link rel="preconnect" href="https://fonts.googleapis.com" />
                <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
            </head>
            <body className={`${inter.variable} font-sans antialiased text-[17px] leading-[1.6]`}>
                <main className="min-h-screen bg-background">{children}</main>
                <Toaster />
            </body>
        </html>
    );
}
