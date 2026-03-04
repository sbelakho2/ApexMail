/**
 * Bot Detection Service
 *
 * Detects bots and crawlers from User-Agent strings using native Rust
 * Aho-Corasick multi-pattern matching when available, with a JS fallback
 * for environments where the native addon isn't compiled.
 *
 * The native addon matches 70+ patterns in O(n) time regardless of
 * pattern count, vs O(n*m) for the JS regex fallback.
 */

import { createRequire } from 'node:module';
import { createLogger } from '../logger/index.js';

const logger = createLogger({ name: 'bot-detection' });

// ── Native addon acceleration ──────────────────────────────────────────────

interface NativeBotDetectionResult {
  isBot: boolean;
  userAgent: string;
  matchedPattern: string | null;
  category: string | null;
  confidence: number;
}

interface NativeBotDetector {
  detectBot(userAgent: string): NativeBotDetectionResult;
  detectBotsBatch(userAgents: string[]): {
    results: NativeBotDetectionResult[];
    botCount: number;
    humanCount: number;
  };
  warmup(): boolean;
  patternCount(): number;
}

const _cjsRequire = createRequire(import.meta.url);
let _native: NativeBotDetector | null = null;
try {
  _native = _cjsRequire('@apexmail/bot-detector-native') as NativeBotDetector;
  _native.warmup();
  logger.info('Native bot detector loaded — using Aho-Corasick pattern matching', {
    patternCount: _native.patternCount(),
  });
} catch (error) {
  logger.warn('Native bot detector unavailable, falling back to JS regex matching', {
    error: error instanceof Error ? error.message : String(error),
  });
}

// ── JS fallback patterns ───────────────────────────────────────────────────

const BOT_PATTERNS = [
  'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
  'yandexbot', 'sogou', 'exabot', 'facebot', 'facebookexternalhit',
  'ia_archiver', 'alexabot', 'mj12bot', 'ahrefsbot', 'semrushbot',
  'dotbot', 'rogerbot', 'screaming frog', 'uptimerobot', 'pingdom',
  'applebot', 'twitterbot', 'linkedinbot', 'slackbot', 'telegrambot',
  'whatsapp', 'discordbot', 'headlesschrome', 'phantomjs', 'selenium',
  'puppeteer', 'playwright', 'crawl', 'spider', 'bot/', 'bot;',
  'http://', 'https://', 'curl/', 'wget/', 'python-requests',
  'python-urllib', 'go-http-client', 'java/', 'libwww', 'lwp-',
  'httpunit', 'nutch', 'biglotron', 'teoma', 'convera', 'gigablast',
  'ia_archiver', 'webmon', 'httrack', 'grub.org', 'netresearchserver',
  'speedy', 'fluffy', 'findlink', 'msrbot', 'panscient', 'yacybot',
  'aisearchbot', 'ioi', 'cis455crawler', 'gulper', 'archive.org_bot',
  'petalbot', 'bytespider', 'gptbot', 'chatgpt-user', 'claudebot',
  'anthropic-ai', 'ccbot', 'amazonbot', 'meta-externalagent',
];

const BOT_REGEX = new RegExp(BOT_PATTERNS.join('|'), 'i');

// ── Public API ─────────────────────────────────────────────────────────────

export interface BotDetectionResult {
  isBot: boolean;
  userAgent: string;
  matchedPattern: string | null;
  category: string | null;
  confidence: number;
}

/**
 * Detect if a User-Agent string belongs to a known bot.
 *
 * Native fast-path: Aho-Corasick O(n) automaton (70+ patterns).
 * JS fallback: Single combined regex.
 */
export function isBot(userAgent: string): boolean {
  if (_native) {
    return _native.detectBot(userAgent).isBot;
  }
  return BOT_REGEX.test(userAgent);
}

/**
 * Detect bot with full details (pattern matched, category, confidence).
 */
export function detectBot(userAgent: string): BotDetectionResult {
  if (_native) {
    return _native.detectBot(userAgent);
  }

  const match = userAgent.match(BOT_REGEX);
  return {
    isBot: match !== null,
    userAgent,
    matchedPattern: match?.[0] ?? null,
    category: match ? 'unknown' : null,
    confidence: match ? 0.9 : 0.0,
  };
}

/**
 * Batch detect bots in multiple User-Agent strings.
 */
export function detectBotsBatch(userAgents: string[]): {
  results: BotDetectionResult[];
  botCount: number;
  humanCount: number;
} {
  if (_native) {
    return _native.detectBotsBatch(userAgents);
  }

  const results = userAgents.map(detectBot);
  const botCount = results.filter((r) => r.isBot).length;
  return {
    results,
    botCount,
    humanCount: results.length - botCount,
  };
}

/**
 * Check if the native addon is loaded.
 */
export function isNativeAvailable(): boolean {
  return _native !== null;
}
