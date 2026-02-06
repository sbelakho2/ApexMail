import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { ControlPlaneShell } from '../components/layout/control-plane-shell';
import { Providers } from '../components/layout/providers';

const inter = Inter({ subsets: ['latin'] });

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
 * - Connects to Sales Autopilot API (port 3010), NOT customer API (port 3001)
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
        <html lang="en">
            <body className={inter.className}>
                <Providers>
                    <ControlPlaneShell>{children}</ControlPlaneShell>
                </Providers>
            </body>
        </html>
    );
}
