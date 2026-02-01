/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    optimizePackageImports: ['lucide-react', 'framer-motion'],
  },
  images: {
    domains: ['apexmail.ee', 'cdn.apexmail.ee'],
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
