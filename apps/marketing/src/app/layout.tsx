import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Analytics } from '@vercel/analytics/react';
import './globals.css';
import { Header } from '@/components/layout/Header';
import { Footer } from '@/components/layout/Footer';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const jetbrains = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
  display: 'swap',
});

export const metadata: Metadata = {
  metadataBase: new URL('https://apexmail.ee'),
  title: {
    default: 'ApexMail - Enterprise Email API for Developers',
    template: '%s | ApexMail',
  },
  description: 'The email API that keeps you out of court. EU-compliant, cryptographically verified delivery, private cloud options, and developer-first experience.',
  keywords: [
    'email API',
    'transactional email',
    'email infrastructure',
    'GDPR compliant email',
    'HIPAA email',
    'email deliverability',
    'enterprise email',
    'developer email API',
  ],
  authors: [{ name: 'Bel Consulting OÜ' }],
  creator: 'Bel Consulting OÜ',
  publisher: 'Bel Consulting OÜ',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://apexmail.ee',
    siteName: 'ApexMail',
    title: 'ApexMail - Enterprise Email API for Developers',
    description: 'The email API that keeps you out of court. EU-compliant, cryptographically verified delivery, and private cloud options.',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'ApexMail - Enterprise Email Infrastructure',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ApexMail - Enterprise Email API',
    description: 'The email API that keeps you out of court.',
    images: ['/og-image.png'],
    creator: '@apexmail',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  alternates: {
    canonical: 'https://apexmail.ee',
  },
};

export const viewport: Viewport = {
  themeColor: '#030712',
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable}`}>
      <head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" href="/icon.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
        <link rel="manifest" href="/manifest.json" />
      </head>
      <body className="font-sans antialiased mesh-gradient min-h-screen">
        <Header />
        <main className="flex-1">{children}</main>
        <Footer />
        <Analytics />
      </body>
    </html>
  );
}
