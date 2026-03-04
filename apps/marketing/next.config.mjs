/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    optimizePackageImports: [],
  },
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'apexmail.ee' },
      { protocol: 'https', hostname: 'cdn.apexmail.ee' },
    ],
    formats: ['image/avif', 'image/webp'],
    deviceSizes: [640, 750, 828, 1080, 1200],
    imageSizes: [16, 32, 48, 64, 96],
  },
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
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
    {
      source: '/_next/static/:path*',
      headers: [
        { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
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
      source: '/docs/:path*',
      destination: 'https://docs.apexmail.ee/:path*',
      permanent: true,
    },
    {
      source: '/app',
      destination: 'https://app.apexmail.ee',
      permanent: false,
    },
    {
      source: '/signup',
      destination: 'https://app.apexmail.ee/signup',
      permanent: false,
    },
    {
      source: '/contact',
      destination: '/pricing',
      permanent: false,
    },
    {
      source: '/contact/:path*',
      destination: '/pricing',
      permanent: false,
    },
    {
      source: '/compare',
      destination: '/compare/sendgrid',
      permanent: false,
    },
    {
      source: '/pricing/faq',
      destination: '/pricing#faq',
      permanent: false,
    },
  ],
};

export default nextConfig;
