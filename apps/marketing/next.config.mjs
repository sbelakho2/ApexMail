/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    optimizePackageImports: ['framer-motion'],
  },
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'apexmail.ee' },
      { protocol: 'https', hostname: 'cdn.apexmail.ee' },
    ],
    formats: ['image/avif', 'image/webp'],
  },
  headers: async () => [
    {
      source: '/:path*',
      headers: [
        { key: 'X-DNS-Prefetch-Control', value: 'on' },
        { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
        {
          key: 'Content-Security-Policy',
          value:
            "default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'; script-src 'self' 'unsafe-inline' https://va.vercel-scripts.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://apexmail.ee https://cdn.apexmail.ee; font-src 'self' data:; connect-src 'self' https://api.apexmail.ee https://vitals.vercel-insights.com; frame-src 'none'; form-action 'self'; upgrade-insecure-requests",
        },
        {
          key: 'Permissions-Policy',
          value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
        },
      ],
    },
  ],
  redirects: async () => [
    {
      source: '/docs',
      destination: 'https://docs.apexmail.ee',
      permanent: true,
    },
    {
      source: '/app',
      destination: 'https://app.apexmail.ee',
      permanent: false,
    },
  ],
};

export default nextConfig;
