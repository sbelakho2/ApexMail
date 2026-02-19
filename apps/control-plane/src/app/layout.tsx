import type { Metadata } from 'next';
import { Fraunces, IBM_Plex_Mono, Manrope } from 'next/font/google';
import './globals.css';
import { ControlPlaneShell } from '../components/layout/control-plane-shell';
import { Providers } from '../components/layout/providers';

const manrope = Manrope({ subsets: ['latin'], variable: '--font-sans', display: 'swap' });
const fraunces = Fraunces({ subsets: ['latin'], variable: '--font-display', display: 'swap' });
const plexMono = IBM_Plex_Mono({
    subsets: ['latin'],
    weight: ['400', '500'],
    variable: '--font-mono',
    display: 'swap',
});

export const metadata: Metadata = {
    title: 'ApexMail Control Plane',
    description: 'Internal administration dashboard for ApexMail platform owners',
    robots: 'noindex, nofollow', // Control plane should never be indexed
};

/**
 * Control Plane Root Layout
 * 
 * IMPORTANT: This is a completely separate application from the customer console.
 * 
 * Process Isolation:
 * - Runs on port 3020 (customer console: 3000)
 * - Connects to API (port 3010), NOT customer API (port 3001)
 * - Has its own authentication (owner auth, not tenant auth)
 * 
 * Data Isolation:
 * - Only sees ApexMail's own leads and CRM data
 * - Cannot access customer tenant data
 * - Separate database schemas/tables for control plane data
 */
export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en" className={`${manrope.variable} ${fraunces.variable} ${plexMono.variable}`}>
            <body className="font-sans antialiased text-[17px] leading-[1.6]">
                <Providers>
                    <ControlPlaneShell>{children}</ControlPlaneShell>
                </Providers>
            </body>
        </html>
    );
}
