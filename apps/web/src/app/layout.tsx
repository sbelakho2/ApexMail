import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
    title: 'ApexMail',
    description: 'Modern email infrastructure for developers',
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en">
            <body className="antialiased">{children}</body>
        </html>
    );
}
