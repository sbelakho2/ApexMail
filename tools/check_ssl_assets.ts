import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(currentDir, '..');
const nginxPath = resolve(repoRoot, 'deploy/nginx/nginx.conf');
const composePath = resolve(repoRoot, 'docker-compose.prod.yml');

const nginxConf = readFileSync(nginxPath, 'utf8');
const compose = readFileSync(composePath, 'utf8');

const hasCert = /ssl_certificate\s+\/etc\/letsencrypt\//.test(nginxConf);
const hasKey = /ssl_certificate_key\s+\/etc\/letsencrypt\//.test(nginxConf);
const hasCertbotService = /\n\s*certbot:\n/.test(compose);
const hasLetsencryptMount = /\/etc\/letsencrypt/.test(compose);

const errors: string[] = [];
if (!hasCert || !hasKey) {
  errors.push('nginx.conf missing ssl_certificate or ssl_certificate_key under /etc/letsencrypt');
}
if (!hasCertbotService) {
  errors.push('docker-compose.prod.yml missing certbot service');
}
if (!hasLetsencryptMount) {
  errors.push('docker-compose.prod.yml missing /etc/letsencrypt mount');
}

if (errors.length > 0) {
  console.error('SSL provisioning checks failed:\n- ' + errors.join('\n- '));
  process.exit(1);
}

console.log('SSL provisioning checks passed.');
