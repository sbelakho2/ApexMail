import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Sidebar } from '../components/layout/sidebar';

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
                {/* Control Plane Indicator Banner */}
                <div className="fixed top-0 left-0 right-0 z-50 bg-indigo-600 text-white text-center text-xs py-1 font-medium">
                    🔒 ApexMail Control Plane — Internal Use Only
                </div>
                <div className="pt-6 min-h-screen bg-gray-50">
                    <Sidebar />
                    <main className="ml-64 p-8">
                        {children}
                    </main>
                </div>
            </body>
        </html>
    );
}
