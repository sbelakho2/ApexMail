import type { MetadataRoute } from 'next';

const BASE_URL = 'https://apexmail.ee';

export default function sitemap(): MetadataRoute.Sitemap {
  const routes = [
    '/',
    '/features',
    '/pricing',
    '/compliance',
    '/case-studies',
    '/compare',
    '/forensic',
    '/private-cloud',
    '/api-console',
    '/status',
    '/privacy',
    '/terms',
    '/cookies',
    '/dpa',
    '/sla',
    '/acceptable-use',
  ];

  const lastModified = new Date();

  return routes.map((route) => ({
    url: `${BASE_URL}${route}`,
    lastModified,
    changeFrequency: route === '/' ? 'daily' : 'weekly',
    priority: route === '/' ? 1 : 0.7,
  }));
}
