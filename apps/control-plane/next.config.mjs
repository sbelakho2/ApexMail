/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    transpilePackages: ['@apexmail/lib'],
    
    // Explicitly define that this is the CONTROL PLANE - completely separate from customer console
    env: {
        NEXT_PUBLIC_APP_NAME: 'ApexMail Control Plane',
        NEXT_PUBLIC_APP_TYPE: 'control-plane',
        
        // Control plane talks to Sales Autopilot API (port 3010), NOT customer API (port 3001)
        NEXT_PUBLIC_AUTOPILOT_API_URL: process.env.AUTOPILOT_API_URL || 'http://localhost:3010',
        NEXT_PUBLIC_COMPLIANCE_API_URL: process.env.COMPLIANCE_API_URL || 'http://localhost:3011',
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
                source: '/:path*',
                headers: [
                    {
                        key: 'X-Control-Plane',
                        value: 'true',
                    },
                    {
                        key: 'X-Frame-Options',
                        value: 'DENY',
                    },
                ],
            },
        ];
    },
};

export default nextConfig;
