import type { NextConfig } from 'next';

const config: NextConfig = {
    output: 'standalone',
    poweredByHeader: false,
    compress: true,
    reactStrictMode: true,
    experimental: {
        serverActions: {
            bodySizeLimit: '2mb',
        },
    },
    images: {
        remotePatterns: [],
    },
    headers: async () => [
        {
            source: '/:path*',
            headers: [
                { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
                { key: 'X-Content-Type-Options', value: 'nosniff' },
                { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
            ],
        },
    ],
};

export default config;
