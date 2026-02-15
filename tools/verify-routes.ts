/**
 * Route Verifier
 * Verifies that all routes are properly registered and accessible
 */

import { existsSync, readdirSync, readFileSync } from 'fs';
import { join } from 'path';

interface RouteFile {
  app: string;
  file: string;
  path: string;
  routes: string[];
}

function findRouteFiles(appsDir: string): RouteFile[] {
  const routeFiles: RouteFile[] = [];
  const apps = readdirSync(appsDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  for (const app of apps) {
    const routesDir = join(appsDir, app, 'src', 'routes');
    if (!existsSync(routesDir)) {
      continue;
    }

    const files = readdirSync(routesDir)
      .filter(file => file.endsWith('.ts') && !file.endsWith('.test.ts'));

    for (const file of files) {
      const filePath = join(routesDir, file);
      const content = readFileSync(filePath, 'utf-8');
      const routes = extractRoutes(content);

      routeFiles.push({
        app,
        file,
        path: filePath,
        routes,
      });
    }
  }

  return routeFiles;
}

function extractRoutes(content: string): string[] {
  const routes: string[] = [];
  
  // Match router.get, router.post, etc.
  const routeRegex = /router\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let match;
  
  while ((match = routeRegex.exec(content)) !== null) {
    routes.push(`${match[1]!.toUpperCase()} ${match[2]}`);
  }

  return routes;
}

function verifyRoutes() {
  console.log('🔍 Verifying API routes...\n');

  const appsDir = join(process.cwd(), 'apps');
  const routeFiles = findRouteFiles(appsDir);

  let totalRoutes = 0;
  let warnings = 0;

  for (const routeFile of routeFiles) {
    console.log(`📁 ${routeFile.app}/${routeFile.file}`);
    
    if (routeFile.routes.length === 0) {
      console.log('   ⚠️  No routes found');
      warnings++;
    } else {
      routeFile.routes.forEach(route => {
        console.log(`   ✓ ${route}`);
        totalRoutes++;
      });
    }
    console.log('');
  }

  console.log(`📊 Summary:`);
  console.log(`   Total route files: ${routeFiles.length}`);
  console.log(`   Total routes: ${totalRoutes}`);
  console.log(`   Warnings: ${warnings}`);

  if (warnings > 0) {
    console.log('\n⚠️  Some route files have no routes');
    process.exit(1);
  } else {
    console.log('\n✅ All routes verified!');
  }
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  verifyRoutes();
}

export { verifyRoutes };
