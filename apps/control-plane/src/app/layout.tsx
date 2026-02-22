import type { Metadata } from 'next';
import localFont from 'next/font/local';
import './globals.css';
import { ControlPlaneShell } from '../components/layout/control-plane-shell';
import { Providers } from '../components/layout/providers';

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
        <html lang="en" className={`${apex.variable} ${plexMono.variable}`}>
            <body className="font-apex antialiased text-[17px] leading-[1.6]">
                <Providers>
                    <ControlPlaneShell>{children}</ControlPlaneShell>
                </Providers>
            </body>
        </html>
    );
}
