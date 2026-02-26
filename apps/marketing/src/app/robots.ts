import type { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: '/',
    },
    sitemap: 'https://apexmail.ee/sitemap.xml',
    host: 'https://apexmail.ee',
  };
}
