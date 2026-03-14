import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT_DIR = path.resolve(__dirname, '../../../..');

function read(relativePath: string): string {
  return fs.readFileSync(path.join(ROOT_DIR, relativePath), 'utf8');
}

function exists(relativePath: string): boolean {
  return fs.existsSync(path.join(ROOT_DIR, relativePath));
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(ROOT_DIR, relativeDir);
  if (!fs.existsSync(absoluteDir)) {
    return [];
  }

  return fs.readdirSync(absoluteDir, { recursive: true })
    .filter((entry): entry is string => typeof entry === 'string')
    .filter((entry) => /\.(ts|tsx|js|mjs)$/.test(entry))
    .map((entry) => path.join(absoluteDir, entry));
}

function collectEndpoints(files: string[]): Set<string> {
  const endpointRegex = /(?<![A-Za-z0-9:])((?:\/v1|\/api\/v1)\/[A-Za-z0-9_\-\/:?=&.*]+)/g;
  const endpoints = new Set<string>();

  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    let match: RegExpExecArray | null;
    while ((match = endpointRegex.exec(source)) !== null) {
      const endpoint = match[1];
      if (endpoint) {
        endpoints.add(endpoint.split('?')[0]);
      }
    }
  }

  return endpoints;
}

function endpointMatchesPattern(endpoint: string, pattern: string): boolean {
  const regex = new RegExp(`^${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*')}$`);
  return regex.test(endpoint);
}

describe('UI Rust Migration Phase 4 foundation', () => {
  it('declares a Rust foundation manifest and crate', () => {
    expect(exists('docs/development/ui-rust-foundation-manifest.json')).toBe(true);
    expect(exists('services/mail-server/crates/ui-foundation/Cargo.toml')).toBe(true);
    expect(exists('services/mail-server/crates/ui-foundation/src/lib.rs')).toBe(true);

    const manifest = JSON.parse(read('docs/development/ui-rust-foundation-manifest.json')) as {
      phase4: {
        designTokens: { status: string; rustModule: string };
        icons: { status: string; rustModule: string };
        routingInfrastructure: { status: string; rustModule: string };
        shellInfrastructure: { status: string; rustModule: string };
        dataAccessLayer: { status: string; rustModule: string };
        primitives: Array<{ name: string; status: string; rustModule: string; source: string }>;
      };
    };

    expect(manifest.phase4.designTokens.status).toBe('implemented');
    expect(manifest.phase4.icons.status).toBe('rendered');
    expect(manifest.phase4.routingInfrastructure.status).toBe('implemented');
    expect(manifest.phase4.shellInfrastructure.status).toBe('implemented');
    expect(manifest.phase4.dataAccessLayer.status).toBe('implemented');
    expect(manifest.phase4.primitives.length).toBeGreaterThanOrEqual(20);
    expect(manifest.phase4.primitives.map((entry) => entry.name)).toEqual(
      expect.arrayContaining(['Button', 'Input', 'Textarea', 'Checkbox', 'Select', 'Switch', 'Slider', 'Label', 'Progress', 'Dialog', 'AlertDialog', 'DropdownMenu', 'Popover', 'Tooltip', 'Tabs', 'ScrollArea', 'Table', 'Card', 'Badge', 'Avatar', 'EmptyState', 'AsyncState', 'Skeleton', 'StatusIndicator', 'PaginationControls', 'Toast', 'Charts']),
    );
    for (const name of ['Button', 'Input', 'Textarea', 'Checkbox', 'Select', 'Switch', 'Slider', 'Label', 'Progress', 'Dialog', 'AlertDialog', 'DropdownMenu', 'Popover', 'Tooltip', 'Tabs', 'ScrollArea', 'Table', 'Card', 'Badge', 'Avatar', 'EmptyState', 'AsyncState', 'Skeleton', 'StatusIndicator', 'PaginationControls', 'Toast', 'Charts']) {
      expect(manifest.phase4.primitives.find((entry) => entry.name === name)?.status).toBe('implemented');
    }
  });

  it('implements Rust-side token and icon accessors', () => {
    const tokens = read('services/mail-server/crates/ui-foundation/src/tokens.rs');
    const icons = read('services/mail-server/crates/ui-foundation/src/icons.rs');
    const routing = read('services/mail-server/crates/ui-foundation/src/routing.rs');
    const shell = read('services/mail-server/crates/ui-foundation/src/shell.rs');
    const data = read('services/mail-server/crates/ui-foundation/src/data.rs');
    const primitives = read('services/mail-server/crates/ui-foundation/src/primitives.rs');

    expect(tokens).toContain('ui-design-token-baseline.json');
    expect(tokens).toContain('pub fn token_entries');
    expect(tokens).toContain('pub fn token_value');
    expect(icons).toContain('apps/web/src/components/ui/icons.tsx');
    expect(icons).toContain('pub fn glyph_names');
    expect(icons).toContain('pub fn glyph_markup');
    expect(icons).toContain('pub fn render_icon');
    expect(routing).toContain('ui-baseline-manifest.json');
    expect(routing).toContain('pub fn surface_ids');
    expect(routing).toContain('pub fn surface_routes');
    expect(routing).toContain('pub fn surface_route_paths');
    expect(routing).toContain('pub fn auth_required');
    expect(routing).toContain('pub fn canonical_pattern');
    expect(routing).toContain('pub fn declared_route_count');
    expect(routing).toContain('pub fn total_route_count');
    expect(shell).toContain('apps/web/src/app/(dashboard)/layout.tsx');
    expect(shell).toContain('apps/web/src/components/layout/sidebar.tsx');
    expect(shell).toContain('apps/web/src/components/layout/header.tsx');
    expect(shell).toContain('apps/web/src/components/impersonation-banner.tsx');
    expect(shell).toContain('apps/web/src/hooks/use-toast.ts');
    expect(shell).toContain('apps/control-plane/src/components/layout/control-plane-shell.tsx');
    // apps/marketing/src/app/layout.tsx removed — old Next.js marketing app deleted
    expect(shell).toContain('pub fn ui_store_persistence_key');
    expect(shell).toContain('pub fn toast_store_global');
    expect(shell).toContain('pub fn toast_remove_delay_ms');
    expect(shell).toContain('pub fn header_shortcut_hint');
    expect(shell).toContain('pub fn shell_source_catalog');
    expect(shell).toContain('pub struct ShellHeader');
    expect(shell).toContain('pub struct ImpersonationBanner');
    expect(shell).toContain('pub struct ToastSurface');
    expect(shell).toContain('pub struct WebDashboardShell');
    expect(shell).toContain('pub struct ControlPlaneShell');
    expect(shell).toContain('pub struct MarketingShell');
    expect(shell).toContain('data-sidebar-storage-key');
    expect(shell).toContain('data-toast-store');
    expect(shell).toContain('data-marketing-shell=');
    expect(shell).toContain('cookie-consent');
    expect(shell).toContain('back-to-top');
    expect(data).toContain('apps/web/src/hooks/use-api.ts');
    expect(data).toContain('apps/web/src/lib/csrf.ts');
    expect(data).toContain('apps/control-plane/src/middleware.ts');
    expect(data).toContain('docs/api-contract-manifest.json');
    expect(data).toContain('docs/development/ui-behavior-baseline-manifest.json');
    expect(data).toContain('pub fn csrf_contract');
    expect(data).toContain('pub fn swr_contract');
    expect(data).toContain('pub fn mutating_methods');
    expect(data).toContain('pub fn api_error_fields');
    expect(data).toContain('pub fn frontend_required_endpoints');
    expect(data).toContain('pub fn backend_route_patterns');
    expect(data).toContain('pub fn auth_contract_scenario_ids');
    expect(data).toContain('pub fn expected_auth_network_contracts');
    expect(data).toContain('pub fn source_catalog');
    expect(primitives).toContain('pub const PRIMITIVES');
    expect(primitives).toContain('pub struct Button');
    expect(primitives).toContain('pub struct Input');
    expect(primitives).toContain('pub struct Select');
    expect(primitives).toContain('pub struct Switch');
    expect(primitives).toContain('pub struct Slider');
    expect(primitives).toContain('pub struct Dialog');
    expect(primitives).toContain('pub struct AlertDialog');
    expect(primitives).toContain('pub struct DropdownMenu');
    expect(primitives).toContain('pub struct Popover');
    expect(primitives).toContain('pub struct Tooltip');
    expect(primitives).toContain('pub struct Card');
    expect(primitives).toContain('pub struct Tabs');
    expect(primitives).toContain('pub struct ScrollArea');
    expect(primitives).toContain('pub struct Table');
    expect(primitives).toContain('pub struct Avatar');
    expect(primitives).toContain('pub struct EmptyState');
    expect(primitives).toContain('pub enum AsyncState');
    expect(primitives).toContain('pub struct Skeleton');
    expect(primitives).toContain('pub struct StatusIndicator');
    expect(primitives).toContain('pub struct PaginationControls');
    expect(primitives).toContain('pub struct Toast');
    expect(primitives).toContain('pub struct ApexLineChart');
    expect(primitives).toContain('pub struct ApexPieChart');
    expect(primitives).toContain('pub struct Tabs');
    expect(primitives).toContain('pub struct ScrollArea');
    expect(primitives).toContain('pub struct Table');
    expect(primitives).toContain('fn card_variant_class');
    expect(primitives).toContain('fn badge_variant_class');
    expect(primitives).toContain('fn scroll_area_orientation_class');
    expect(primitives).toContain('fn toast_variant_class');
    expect(primitives).toContain('fn table_align_class');
    expect(primitives).toContain('fn tabs_list_variant_class');
    expect(primitives).toContain('fn tabs_trigger_variant_class');
    expect(primitives).toContain('fn skeleton_variant_class');
  });

  it('keeps route manifest counts and shell contracts aligned with the Rust foundation layer', () => {
    const baseline = JSON.parse(read('docs/development/ui-baseline-manifest.json')) as {
      surfaces: Array<{ id: string; routeCount: number; routes: Array<{ path: string; authRequired: boolean; category: string }> }>;
    };
    const shell = read('services/mail-server/crates/ui-foundation/src/shell.rs');

    const surfaces = new Map(baseline.surfaces.map((surface) => [surface.id, surface]));
    expect(surfaces.get('web')?.routeCount).toBe(30);
    expect(surfaces.get('control-plane')?.routeCount).toBe(23);
    expect(surfaces.get('marketing')?.routeCount).toBe(19);
    expect(surfaces.get('marketing-zola')?.routeCount).toBe(20);
    expect(baseline.surfaces.reduce((sum, surface) => sum + surface.routes.length, 0)).toBe(92);
    expect(surfaces.get('control-plane')?.routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: '/login', authRequired: false, category: 'auth' }),
        expect.objectContaining({ path: '/analytics', authRequired: true, category: 'admin' }),
      ]),
    );
    expect(surfaces.get('marketing')?.routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: '/pricing/calculator', authRequired: false, category: 'marketing' }),
      ]),
    );
    expect(surfaces.get('marketing-zola')?.routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: '/compare' }),
      ]),
    );

    for (const marker of [
      'data-sidebar-storage-key',
      'data-toast-store',
      'data-remove-delay',
      'data-marketing-shell=',
      'cookie-consent',
      'back-to-top',
      'Impersonation Mode',
      'aria-label=',
      'Notifications',
    ]) {
      expect(shell).toContain(marker);
    }
  });

  it('keeps API and behavior contract manifests aligned with the Rust data layer', () => {
    const apiManifest = JSON.parse(read('docs/api-contract-manifest.json')) as {
      version: number;
      canonicalCustomerPrefix: string;
      gatewayCompatibilityPrefixes: string[];
      frontendRequiredEndpoints: string[];
      backendRoutePatterns: string[];
    };
    const behaviorManifest = JSON.parse(read('docs/development/ui-behavior-baseline-manifest.json')) as {
      version: number;
      requiredBrowsers: string[];
      artifacts: { captureRoot: string };
      scenarios: Array<{
        id: string;
        route: string;
        artifacts?: string[];
        expectedNetwork?: Array<{ urlIncludes?: string; method?: string; status?: number }>;
      }>;
    };
    const data = read('services/mail-server/crates/ui-foundation/src/data.rs');

    expect(apiManifest.version).toBe(1);
    expect(apiManifest.canonicalCustomerPrefix).toBe('/v1');
    expect(apiManifest.gatewayCompatibilityPrefixes).toEqual(['/v1', '/api/v1']);
    expect(apiManifest.frontendRequiredEndpoints).toHaveLength(14);
    expect(apiManifest.backendRoutePatterns).toHaveLength(14);
    expect(apiManifest.frontendRequiredEndpoints).toEqual(
      expect.arrayContaining(['/v1/auth/forgot-password', '/v1/auth/me', '/api/v1/discovery/run']),
    );
    expect(apiManifest.backendRoutePatterns).toEqual(
      expect.arrayContaining(['/v1/campaigns*', '/api/v1/operator/*']),
    );

    expect(behaviorManifest.scenarios).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'web-login-invalid-keyboard-flow', route: '/login' }),
        expect.objectContaining({ id: 'web-login-rate-limited-flow', route: '/login' }),
        expect.objectContaining({ id: 'web-login-mfa-required-flow', route: '/login' }),
        expect.objectContaining({ id: 'control-plane-login-invalid-keyboard-flow', route: '/login' }),
        expect.objectContaining({ id: 'control-plane-login-mfa-flow', route: '/login' }),
      ]),
    );
    expect(behaviorManifest.version).toBe(1);
    expect(behaviorManifest.requiredBrowsers).toEqual(['chromium', 'firefox', 'webkit']);
    expect(behaviorManifest.artifacts.captureRoot).toBe('apps/testing/reports/ui-behavior-baseline');
    for (const scenarioId of [
      'web-behavior-major-states',
      'web-behavior-form-matrix',
      'web-behavior-overlay-matrix',
      'web-behavior-table-matrix',
      'web-behavior-chart-matrix',
    ]) {
      expect(behaviorManifest.scenarios).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: scenarioId,
            route: '/storybook/behavior-matrix',
            artifacts: expect.arrayContaining(['screenshot', 'dom', 'accessibility', 'console', 'network', 'interaction', 'keyboard', 'analytics', 'timing']),
          }),
        ]),
      );
    }

    const authNetworks = behaviorManifest.scenarios
      .filter((scenario) => scenario.route === '/login')
      .flatMap((scenario) => scenario.expectedNetwork ?? []);
    expect(authNetworks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ urlIncludes: '/v1/auth/csrf', method: 'GET', status: 200 }),
        expect.objectContaining({ urlIncludes: '/v1/auth/session', method: 'GET', status: 200 }),
        expect.objectContaining({ urlIncludes: '/v1/auth/login', method: 'POST', status: 429 }),
        expect.objectContaining({ urlIncludes: '/v1/auth/login', method: 'POST', status: 401 }),
      ]),
    );

    for (const marker of [
      'X-CSRF-Token',
      'csrf_token_sig',
      'dedupingInterval: 5000',
      'sessionBinding',
      'frontendRequiredEndpoints',
      'web-login-rate-limited-flow',
    ]) {
      expect(data).toContain(marker);
    }
  });

  it('keeps representative frontend endpoint usage aligned with the contract manifest', () => {
    const apiManifest = JSON.parse(read('docs/api-contract-manifest.json')) as {
      frontendRequiredEndpoints: string[];
      backendRoutePatterns: string[];
    };

    const endpoints = collectEndpoints([
      ...listSourceFiles('apps/web/src'),
      ...listSourceFiles('apps/control-plane/src'),
    ]);

    const legacyWebApiPrefix = [...collectEndpoints(listSourceFiles('apps/web/src'))]
      .filter((endpoint) => endpoint.startsWith('/api/v1/'));
    expect(legacyWebApiPrefix).toEqual([]);

    const representativeEndpoints = [
      '/v1/campaigns',
      '/v1/contacts',
      '/v1/templates',
      '/v1/lists',
      '/v1/dashboard/stats',
      '/v1/billing/payg/usage',
      '/v1/auth/forgot-password',
      '/v1/auth/profile',
      '/api/v1/discovery/run',
    ];

    for (const requiredEndpoint of representativeEndpoints) {
      expect(apiManifest.frontendRequiredEndpoints).toContain(requiredEndpoint);
      expect(endpoints.has(requiredEndpoint), `Missing frontend endpoint usage for ${requiredEndpoint}`).toBe(true);

      const matches = apiManifest.backendRoutePatterns.some((pattern) => endpointMatchesPattern(requiredEndpoint, pattern));
      expect(matches, `No backend contract pattern for ${requiredEndpoint}`).toBe(true);
    }
  });

  it('passes the Rust foundation manifest gate', () => {
    const output = execFileSync('node', ['tools/check-ui-rust-foundation.mjs'], {
      cwd: ROOT_DIR,
      encoding: 'utf8',
    });

    expect(output).toContain('[ui-rust-foundation] ok');
  });

  it('passes the Rust ui-foundation crate tests', () => {
    const output = execFileSync('cargo', ['test', '-p', 'ui-foundation'], {
      cwd: path.join(ROOT_DIR, 'services/mail-server'),
      encoding: 'utf8',
    });

    expect(output).toContain('test result: ok. 59 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;');
  });

  it('passes the prerequisite and contract validators that underpin phase 4 parity evidence', () => {
    const validators: Array<[string, string]> = [
      ['tools/check-ui-rust-migration-plan.mjs', '[ui-rust-migration-plan] ok'],
      ['tools/check-ui-design-tokens.mjs', '[ui-design-tokens] ok'],
      ['tools/check-ui-parity-harness.mjs', '[ui-parity-harness] ok'],
      ['tools/check-ui-diff-infrastructure.mjs', '[ui-diff-infrastructure] ok'],
      ['tools/check-ui-baseline-manifest.mjs', '[ui-baseline-manifest] ok'],
      ['tools/check-ui-behavior-baseline-manifest.mjs', '[ui-behavior-baseline-manifest] ok'],
      ['tools/check-ui-baseline-artifacts.mjs', '[ui-baseline-artifacts] ok'],
      ['tools/check-ui-behavior-baseline-artifacts.mjs', '[ui-behavior-baseline-artifacts] ok'],
      ['tools/check-route-contract-coverage.mjs', '[route-contract-coverage] ok'],
      ['tools/check-contract-manifest.mjs', '[contract-manifest] OK'],
      ['tools/check-contract-backcompat.mjs', '[contract-backcompat] OK'],
      ['tools/contract-tests/consumer-contract-test.mjs', '[consumer-contract-test] OK'],
      ['tools/contract-tests/producer-contract-test.mjs', '[producer-contract-test] OK'],
    ];

    for (const [scriptPath, expectedMarker] of validators) {
      const output = execFileSync('node', [scriptPath], {
        cwd: ROOT_DIR,
        encoding: 'utf8',
      });

      expect(output).toContain(expectedMarker);
    }
  });

  it('passes the prerequisite checklist suites that foundation work depends on', () => {
    const suites = [
      'apps/testing/src/checklist/ui-rust-migration-phase1.test.ts',
      'apps/testing/src/checklist/ui-rust-migration-phase2.test.ts',
      'apps/testing/src/checklist/ui-rust-migration-phase2-behavior.test.ts',
      'apps/testing/src/checklist/ui-rust-migration-phase2-design-tokens.test.ts',
      'apps/testing/src/checklist/ui-rust-migration-phase3.test.ts',
      'apps/testing/src/checklist/ui-rust-migration-phase3-diff-infra.test.ts',
      'apps/testing/src/checklist/api-contract-manifest.test.ts',
    ];

    const output = execFileSync('pnpm', ['exec', 'vitest', 'run', ...suites], {
      cwd: ROOT_DIR,
      encoding: 'utf8',
    });

    expect(output).toContain('Test Files  7 passed (7)');
    expect(output).toContain('Tests  22 passed (22)');
  });
});
