/**
 * Benchmark: Native (Rust/napi-rs) vs JS validation performance
 *
 * Usage:
 *   npx tsx packages/lib/src/__benchmarks__/validation-bench.ts
 *
 * Requires: Native binaries built locally (napi build --release in packages/validator-native)
 * Falls back gracefully if native module unavailable.
 */

import { createRequire } from 'node:module';
import { performance } from 'node:perf_hooks';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatMs(ms: number): string {
  return ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : `${ms.toFixed(2)}ms`;
}

function speedup(jsMs: number, nativeMs: number): string {
  const factor = jsMs / nativeMs;
  return `${factor.toFixed(1)}×`;
}

// ---------------------------------------------------------------------------
// Load native module (best-effort)
// ---------------------------------------------------------------------------

interface NativeValidator {
  validateEmail(email: string): { valid: boolean; reason: string | null };
  isDisposableDomain(domain: string): boolean;
  initializeDnsResolver(): void;
}

let native: NativeValidator | null = null;
try {
  const require = createRequire(import.meta.url);
  native = require('@apexmail/validator-native') as NativeValidator;
  native.initializeDnsResolver();
  console.log('✓ Native validator loaded\n');
} catch {
  console.log('⚠ Native validator not available — only JS benchmarks will run\n');
}

// ---------------------------------------------------------------------------
// Test data generators
// ---------------------------------------------------------------------------

const VALID_EMAILS = Array.from({ length: 10_000 }, (_, i) => `user${i}@example-${i % 100}.com`);
const INVALID_EMAILS = Array.from({ length: 10_000 }, (_, i) => {
  const variants = [
    `user${i}@`,
    `@domain${i}.com`,
    `user ${i}@example.com`,
    `user${i}@@example.com`,
    `user${i}@.com`,
    `user${i}@com.`,
    `user${i}@-example.com`,
    `.user${i}@example.com`,
    `user${i}@example..com`,
    `user${i}@exam ple.com`,
  ];
  return variants[i % variants.length]!;
});
const ALL_EMAILS = [...VALID_EMAILS, ...INVALID_EMAILS]; // 20K emails

const DISPOSABLE_DOMAINS = [
  'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
  'yopmail.com', 'sharklasers.com', 'grr.la', 'guerrillamailblock.com',
  'pokemail.net', 'spam4.me', 'binkmail.com', 'safetymail.info',
];
const LEGIT_DOMAINS = [
  'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
  'icloud.com', 'fastmail.com', 'hey.com', 'tutanota.com',
  'zoho.com', 'aol.com', 'mail.com', 'gmx.com',
];
const DOMAIN_CORPUS = Array.from({ length: 100_000 }, (_, i) => {
  const pool = i % 3 === 0 ? DISPOSABLE_DOMAINS : LEGIT_DOMAINS;
  return pool[i % pool.length]!;
});

// ---------------------------------------------------------------------------
// JS validators (pure TypeScript reimplementations for fair comparison)
// ---------------------------------------------------------------------------

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function jsSyntaxValidate(email: string): boolean {
  if (!email || email.length > 254) return false;
  if (!EMAIL_REGEX.test(email)) return false;
  const [local, domain] = email.split('@');
  if (!local || !domain) return false;
  if (local.length > 64) return false;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
  if (domain.startsWith('-') || domain.endsWith('-') || domain.includes('..')) return false;
  return true;
}

const DISPOSABLE_SET = new Set(DISPOSABLE_DOMAINS);

function jsIsDisposable(domain: string): boolean {
  return DISPOSABLE_SET.has(domain);
}

// ---------------------------------------------------------------------------
// Benchmark runner
// ---------------------------------------------------------------------------

function bench(label: string, fn: () => void, iterations: number): number {
  // warm up
  for (let i = 0; i < Math.min(100, iterations); i++) fn();

  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  const elapsed = performance.now() - start;
  const perOp = elapsed / iterations;
  console.log(`  ${label}: ${formatMs(elapsed)} total, ${formatMs(perOp)}/op (${iterations} ops)`);
  return elapsed;
}

// ---------------------------------------------------------------------------
// Run benchmarks
// ---------------------------------------------------------------------------

console.log('='.repeat(72));
console.log('  ApexMail Validation Benchmark — JS vs Native (Rust/napi-rs)');
console.log('='.repeat(72));

// --- Syntax validation: 10K valid + 10K invalid = 20K emails ---
console.log('\n▸ Email Syntax Validation (20,000 emails)\n');

const jsSyntaxMs = bench('JS  (regex)', () => {
  for (const email of ALL_EMAILS) jsSyntaxValidate(email);
}, 1);

let nativeSyntaxMs: number | null = null;
if (native) {
  const n = native; // narrow
  nativeSyntaxMs = bench('Rust (napi)', () => {
    for (const email of ALL_EMAILS) n.validateEmail(email);
  }, 1);
}

if (nativeSyntaxMs != null) {
  console.log(`\n  → Speedup: ${speedup(jsSyntaxMs, nativeSyntaxMs)} (Rust over JS)`);
} else {
  console.log('\n  → Native not available, skipping comparison');
}

// --- Disposable domain lookup: 100K domains ---
console.log('\n▸ Disposable Domain Lookup (100,000 domains)\n');

const jsDisposableMs = bench('JS  (Set)', () => {
  for (const domain of DOMAIN_CORPUS) jsIsDisposable(domain);
}, 1);

let nativeDisposableMs: number | null = null;
if (native) {
  const n = native;
  nativeDisposableMs = bench('Rust (HashSet)', () => {
    for (const domain of DOMAIN_CORPUS) n.isDisposableDomain(domain);
  }, 1);
}

if (nativeDisposableMs != null) {
  console.log(`\n  → Speedup: ${speedup(jsDisposableMs, nativeDisposableMs)} (Rust over JS)`);
} else {
  console.log('\n  → Native not available, skipping comparison');
}

// --- Bot detection ---
console.log('\n▸ Bot Detection (10,000 user agents)\n');

const BOT_UAS = Array.from({ length: 5_000 }, (_, i) => {
  const bots = [
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0)',
    'claudebot/1.0',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
  ];
  return bots[i % bots.length]!;
});
const HUMAN_UAS = Array.from({ length: 5_000 }, (_, i) => {
  const humans = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
  ];
  return humans[i % humans.length]!;
});
const ALL_UAS = [...BOT_UAS, ...HUMAN_UAS];

const BOT_REGEX = /googlebot|bingbot|yandexbot|gptbot|claudebot|baiduspider|slurp|duckduckbot|facebookexternalhit|twitterbot|linkedinbot|applebot|msnbot|ia_archiver|archive\.org_bot/i;

const jsBotMs = bench('JS  (regex)', () => {
  for (const ua of ALL_UAS) BOT_REGEX.test(ua);
}, 1);

let nativeBotMs: number | null = null;
try {
  const require = createRequire(import.meta.url);
  const botNative = require('@apexmail/bot-detector-native');
  botNative.warmup();
  nativeBotMs = bench('Rust (Aho-Corasick)', () => {
    for (const ua of ALL_UAS) botNative.detectBot(ua);
  }, 1);
} catch {
  // native not available
}

if (nativeBotMs != null) {
  console.log(`\n  → Speedup: ${speedup(jsBotMs, nativeBotMs)} (Rust over JS)`);
} else {
  console.log('\n  → Native bot-detector not available, skipping comparison');
}

// --- Summary ---
console.log('\n' + '='.repeat(72));
console.log('  Summary');
console.log('='.repeat(72));
console.log(`
  Benchmark                  | JS          | Rust (native) | Speedup
  ---------------------------+-------------+---------------+---------
  Syntax validation (20K)    | ${formatMs(jsSyntaxMs).padEnd(11)} | ${nativeSyntaxMs != null ? formatMs(nativeSyntaxMs).padEnd(13) : 'N/A'.padEnd(13)} | ${nativeSyntaxMs != null ? speedup(jsSyntaxMs, nativeSyntaxMs) : 'N/A'}
  Disposable lookup (100K)   | ${formatMs(jsDisposableMs).padEnd(11)} | ${nativeDisposableMs != null ? formatMs(nativeDisposableMs).padEnd(13) : 'N/A'.padEnd(13)} | ${nativeDisposableMs != null ? speedup(jsDisposableMs, nativeDisposableMs) : 'N/A'}
  Bot detection (10K)        | ${formatMs(jsBotMs).padEnd(11)} | ${nativeBotMs != null ? formatMs(nativeBotMs).padEnd(13) : 'N/A'.padEnd(13)} | ${nativeBotMs != null ? speedup(jsBotMs, nativeBotMs) : 'N/A'}

  Expected speedups: 5-20× syntax, 2-5× set lookup, 3-10× bot detection
  Actual speedups depend on CPU, data distribution, and JIT warm-up.
`);
