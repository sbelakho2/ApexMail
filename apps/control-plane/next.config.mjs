/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    
    // Explicitly define that this is the CONTROL PLANE - completely separate from customer console
    env: {
        NEXT_PUBLIC_APP_NAME: 'ApexMail Control Plane',
        NEXT_PUBLIC_APP_TYPE: 'control-plane',
        
        // Client uses relative paths through Next.js rewrites — no internal URLs leaked
        NEXT_PUBLIC_AUTOPILOT_API_URL: '/api/autopilot',
        NEXT_PUBLIC_COMPLIANCE_API_URL: '/api/compliance',
    },
    
    // Security: Ensure control plane cannot accidentally reference customer API
    async rewrites() {
        return [
            // Route /api/autopilot/* to Sales Autopilot service
            {
                source: '/api/autopilot/:path*',
                destination: `${process.env.AUTOPILOT_API_URL || 'http://localhost:3010'}/api/v1/:path*`,
            },
            // Route /api/compliance/* to Compliance service
            {
                source: '/api/compliance/:path*',
                destination: `${process.env.COMPLIANCE_API_URL || 'http://localhost:3011'}/api/:path*`,
            },
        ];
    },
    
    // Block any accidental requests to customer API
    async headers() {
        return [
            {
                source: '/_next/static/:path*',
                headers: [
                    {
                        key: 'Cache-Control',
                        value: 'public, max-age=31536000, immutable',
                    },
                ],
            },
            {
                source: '/:path*',
                headers: [
                    {
                        key: 'X-Control-Plane',
                        value: 'true',
                    },
                    {
                        key: 'Strict-Transport-Security',
                        value: 'max-age=31536000; includeSubDomains; preload',
                    },
                    {
                        key: 'X-Frame-Options',
                        value: 'DENY',
                    },
                    {
                        key: 'X-Content-Type-Options',
                        value: 'nosniff',
                    },
                    {
                        key: 'Referrer-Policy',
                        value: 'strict-origin-when-cross-origin',
                    },
                    {
                        key: 'X-XSS-Protection',
                        value: '0',
                    },
                    {
                        key: 'Permissions-Policy',
                        value: 'camera=(), microphone=(), geolocation=()',
                    },
                ],
            },
        ];
    },
    compiler: {
        removeConsole: process.env.NODE_ENV === 'production' ? { exclude: ['error', 'warn'] } : false,
    },
    experimental: {
        optimizePackageImports: ['@radix-ui/react-icons', 'date-fns'],
    },
};

export default nextConfig;
