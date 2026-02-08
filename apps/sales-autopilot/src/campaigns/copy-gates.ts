/**
 * Copy Quality Gates — lint, token sanity, semantic drift, spintax limits
 *
 * Constrains generated copy to protect brand, deliverability, and learning signal:
 *   • Spintax: micro-variants ONLY (greeting, one sentence, CTA, subject)
 *   • Copy lint gate: max subject length, punctuation density, no ALL CAPS, one primary CTA
 *   • Token sanity gate: verify all template tokens replaced
 *   • Tone-transform limits: only predefined phrase substitutions
 *   • Semantic drift check: revert to baseline if body diverges too much
 *   • Safe-mode copy for high-risk leads
 *   • One offer, one CTA rule
 */

import { createLogger } from '@apexmail/lib';
import { calculateTokenDivergence } from './safety.js';

const logger = createLogger({ name: 'copy-gates', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface CopyLintResult {
  passed: boolean;
  violations: CopyViolation[];
}

export interface CopyViolation {
  rule: string;
  message: string;
  severity: 'error' | 'warning';
  location?: string;
}

export interface CopyInput {
  subject: string;
  body: string;
  templateBaseline: {
    subject: string;
    body: string;
  } | null;
  tokens: Record<string, string>;
  isHighRisk: boolean;
}

export interface CopyLintConfig {
  maxSubjectLength: number;
  maxPunctuationDensity: number;
  maxConsecutiveSymbols: number;
  maxCapsBurstLength: number;
  maxTokenDivergencePercent: number;
  maxToneSubstitutions: number;
  semanticDriftThreshold: number;
  requiredTokens: string[];
}

// ────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: CopyLintConfig = {
  maxSubjectLength: 78,
  maxPunctuationDensity: 0.08,
  maxConsecutiveSymbols: 2,
  maxCapsBurstLength: 3,
  maxTokenDivergencePercent: 30,
  maxToneSubstitutions: 5,
  semanticDriftThreshold: 0.4,
  requiredTokens: ['{{lead.first_name}}', '{{lead.company_name}}'],
};

// ────────────────────────────────────────────────────────────────────
// Spintax Validator
// ────────────────────────────────────────────────────────────────────

export type SpintaxCategory = 'greeting' | 'sentence_reorder' | 'cta_phrasing' | 'subject_variant';

const ALLOWED_SPINTAX_ZONES: Record<SpintaxCategory, RegExp> = {
  greeting: /^(Hi|Hello|Hey|Good (morning|afternoon|evening)),?\s/,
  sentence_reorder: /^.{0,150}$/,  // One short sentence only
  cta_phrasing: /(Would you be open|Would it make sense|Could we|I'd love to|Happy to|Let me know if)/,
  subject_variant: /^.{0,78}$/,
};

export function validateSpintax(
  spintaxBlocks: Array<{ category: SpintaxCategory; content: string }>
): CopyLintResult {
  const violations: CopyViolation[] = [];

  for (const block of spintaxBlocks) {
    const pattern = ALLOWED_SPINTAX_ZONES[block.category];
    if (!pattern) {
      violations.push({
        rule: 'spintax_unknown_category',
        message: `Unknown spintax category: ${block.category}`,
        severity: 'error',
      });
      continue;
    }

    // Paragraph-level spintax is never allowed
    if (block.content.includes('\n\n') || block.content.length > 300) {
      violations.push({
        rule: 'spintax_paragraph_level',
        message: `Spintax block too large for category "${block.category}". Max 300 chars, no paragraph breaks.`,
        severity: 'error',
        location: block.content.substring(0, 80),
      });
    }
  }

  return {
    passed: violations.filter(v => v.severity === 'error').length === 0,
    violations,
  };
}

// ────────────────────────────────────────────────────────────────────
// Copy Lint Gate
// ────────────────────────────────────────────────────────────────────

export function lintCopy(
  input: CopyInput,
  config: CopyLintConfig = DEFAULT_CONFIG
): CopyLintResult {
  const violations: CopyViolation[] = [];

  // ── Subject Length ──
  if (input.subject.length > config.maxSubjectLength) {
    violations.push({
      rule: 'subject_length',
      message: `Subject is ${input.subject.length} chars (max ${config.maxSubjectLength})`,
      severity: 'error',
    });
  }

  // ── Punctuation Density ──
  const punctCount = (input.subject.match(/[!?.,;:'"]/g) || []).length;
  const punctDensity = input.subject.length > 0 ? punctCount / input.subject.length : 0;
  if (punctDensity > config.maxPunctuationDensity) {
    violations.push({
      rule: 'punctuation_density',
      message: `Subject punctuation density is ${(punctDensity * 100).toFixed(1)}% (max ${config.maxPunctuationDensity * 100}%)`,
      severity: 'error',
    });
  }

  // ── Repeated Symbols (!!!, ???, ...) ──
  const repeatedSymbols = /([!?.])\1{2,}/;
  if (repeatedSymbols.test(input.subject) || repeatedSymbols.test(input.body)) {
    violations.push({
      rule: 'repeated_symbols',
      message: 'Repeated symbols detected (e.g., !!!, ???). Max 2 consecutive.',
      severity: 'error',
    });
  }

  // ── ALL CAPS Bursts ──
  const capsPattern = /\b[A-Z]{4,}\b/g;
  const capsMatches = input.subject.match(capsPattern) || [];
  const bodyCapsMatches = input.body.match(capsPattern) || [];
  if (capsMatches.length > 0 || bodyCapsMatches.length > 0) {
    const allCaps = [...capsMatches, ...bodyCapsMatches];
    violations.push({
      rule: 'all_caps_burst',
      message: `ALL CAPS words detected: ${allCaps.join(', ')}. Avoid shouting.`,
      severity: 'error',
    });
  }

  // ── One Primary CTA ──
  const ctaPatterns = [
    /schedule (a )?(call|meeting|demo)/i,
    /book (a )?(time|slot|call)/i,
    /sign up/i,
    /subscribe/i,
    /download/i,
    /register/i,
    /try (it )?(for )?free/i,
    /get started/i,
    /reply (to this|back)/i,
    /click here/i,
    /learn more/i,
  ];

  let ctaCount = 0;
  for (const pattern of ctaPatterns) {
    if (pattern.test(input.body)) ctaCount++;
  }
  if (ctaCount > 1) {
    violations.push({
      rule: 'multiple_ctas',
      message: `Found ${ctaCount} competing CTAs. Emails should have exactly one primary ask.`,
      severity: 'error',
    });
  }
  if (ctaCount === 0) {
    violations.push({
      rule: 'no_cta',
      message: 'No clear call-to-action found in email body.',
      severity: 'warning',
    });
  }

  // ── Token Divergence (variability cap) ──
  if (input.templateBaseline) {
    const divergence = calculateTokenDivergence(
      input.templateBaseline.body,
      input.body
    );
    if (divergence > config.maxTokenDivergencePercent) {
      violations.push({
        rule: 'token_divergence',
        message: `Body diverges ${divergence.toFixed(1)}% from template (max ${config.maxTokenDivergencePercent}%)`,
        severity: 'error',
      });
    }
  }

  // ── Safe-mode for high-risk leads ──
  if (input.isHighRisk) {
    const safeModeViolations = validateSafeMode(input);
    violations.push(...safeModeViolations);
  }

  return {
    passed: violations.filter(v => v.severity === 'error').length === 0,
    violations,
  };
}

// ────────────────────────────────────────────────────────────────────
// Token Sanity Gate
// ────────────────────────────────────────────────────────────────────

export function validateTokens(
  content: string,
  tokens: Record<string, string>,
  requiredTokenFields: string[] = []
): CopyLintResult {
  const violations: CopyViolation[] = [];

  // Check for unreplaced template tokens
  const unreplacedPattern = /\{\{[^}]+\}\}/g;
  const unreplaced = content.match(unreplacedPattern) || [];

  for (const token of unreplaced) {
    violations.push({
      rule: 'unreplaced_token',
      message: `Unreplaced token found: ${token}`,
      severity: 'error',
      location: token,
    });
  }

  // Check that required tokens were present (and had values)
  for (const field of requiredTokenFields) {
    const tokenKey = `{{${field}}}`;
    if (content.includes(tokenKey)) {
      // Token still present = not replaced
      violations.push({
        rule: 'required_token_missing_value',
        message: `Required token ${tokenKey} has no value`,
        severity: 'error',
        location: field,
      });
    }

    // Check that the token was supposed to be there but the value is empty
    const value = tokens[field];
    if (value !== undefined && value.trim() === '') {
      violations.push({
        rule: 'required_token_empty',
        message: `Required token ${field} resolved to empty string`,
        severity: 'error',
        location: field,
      });
    }
  }

  return {
    passed: violations.filter(v => v.severity === 'error').length === 0,
    violations,
  };
}

// ────────────────────────────────────────────────────────────────────
// Tone Transform Limits
// ────────────────────────────────────────────────────────────────────

const ALLOWED_TONE_SUBSTITUTIONS: Array<{ from: RegExp; to: string }> = [
  { from: /\bHi\b/g, to: 'Hello' },
  { from: /\bHello\b/g, to: 'Hi' },
  { from: /\bHey\b/g, to: 'Hi' },
  { from: /\bBest,\b/g, to: 'Cheers,' },
  { from: /\bCheers,\b/g, to: 'Best,' },
  { from: /\bWould you be open to\b/g, to: 'Would it make sense to' },
  { from: /\bI'd love to\b/g, to: 'Happy to' },
  { from: /\bquick\b/g, to: 'brief' },
  { from: /\bchat\b/g, to: 'conversation' },
  { from: /\btouch base\b/g, to: 'connect' },
  { from: /\breached out\b/g, to: 'connected' },
  { from: /\bloop in\b/g, to: 'include' },
];

export function applyToneTransform(
  content: string,
  maxSubstitutions: number = DEFAULT_CONFIG.maxToneSubstitutions
): { result: string; substitutionCount: number; reverted: boolean } {
  let result = content;
  let totalSubs = 0;

  for (const sub of ALLOWED_TONE_SUBSTITUTIONS) {
    const matches = result.match(sub.from);
    if (matches) {
      totalSubs += matches.length;
      result = result.replace(sub.from, sub.to);
    }

    if (totalSubs > maxSubstitutions) {
      // Too many substitutions — revert to original
      logger.warn('Tone transform exceeded max substitutions — reverting', {
        count: totalSubs,
        max: maxSubstitutions,
      });
      return { result: content, substitutionCount: totalSubs, reverted: true };
    }
  }

  return { result, substitutionCount: totalSubs, reverted: false };
}

// ────────────────────────────────────────────────────────────────────
// Safe-Mode Copy (high-risk leads)
// ────────────────────────────────────────────────────────────────────

const URGENCY_WORDS = new Set([
  'urgent', 'hurry', 'limited', 'expires', 'deadline', 'last chance',
  'act now', 'don\'t miss', 'only today', 'exclusive offer', 'time-sensitive',
  'rush', 'immediate', 'asap', 'before it\'s too late',
]);

function validateSafeMode(input: CopyInput): CopyViolation[] {
  const violations: CopyViolation[] = [];
  const bodyLower = input.body.toLowerCase();

  // Check for urgency words
  for (const word of URGENCY_WORDS) {
    if (bodyLower.includes(word)) {
      violations.push({
        rule: 'safe_mode_urgency',
        message: `Safe-mode violation: urgency word "${word}" found in high-risk email`,
        severity: 'error',
      });
    }
  }

  // Check length (safe-mode should be shorter)
  const wordCount = input.body.split(/\s+/).length;
  if (wordCount > 150) {
    violations.push({
      rule: 'safe_mode_length',
      message: `Safe-mode emails should be under 150 words (found ${wordCount})`,
      severity: 'warning',
    });
  }

  return violations;
}

// ────────────────────────────────────────────────────────────────────
// Semantic Drift Check
// ────────────────────────────────────────────────────────────────────

/**
 * Simple token-overlap-based "semantic drift" detector.
 * In production, replace with actual embedding comparison.
 */
export function checkSemanticDrift(
  generated: string,
  template: string,
  threshold: number = DEFAULT_CONFIG.semanticDriftThreshold
): { drifted: boolean; distance: number } {
  const genTokens = new Set(generated.toLowerCase().split(/\W+/).filter(Boolean));
  const tplTokens = new Set(template.toLowerCase().split(/\W+/).filter(Boolean));

  const intersection = new Set([...genTokens].filter(t => tplTokens.has(t)));
  const union = new Set([...genTokens, ...tplTokens]);

  const jaccardSim = union.size > 0 ? intersection.size / union.size : 1;
  const distance = 1 - jaccardSim;

  return {
    drifted: distance > threshold,
    distance,
  };
}

// ────────────────────────────────────────────────────────────────────
// Full Copy Validation Pipeline
// ────────────────────────────────────────────────────────────────────

export interface CopyValidationResult {
  approved: boolean;
  lint: CopyLintResult;
  tokenSanity: CopyLintResult;
  semanticDrift: { drifted: boolean; distance: number } | null;
  finalSubject: string;
  finalBody: string;
}

export function validateAndProcessCopy(input: CopyInput): CopyValidationResult {
  // 1. Lint check
  const lint = lintCopy(input);

  // 2. Token sanity
  const tokenSanity = validateTokens(
    `${input.subject} ${input.body}`,
    input.tokens,
    DEFAULT_CONFIG.requiredTokens.map(t => t.replace(/\{\{|\}\}/g, ''))
  );

  // 3. Semantic drift (only if we have a baseline)
  let drift: { drifted: boolean; distance: number } | null = null;
  let finalBody = input.body;
  let finalSubject = input.subject;

  if (input.templateBaseline) {
    drift = checkSemanticDrift(input.body, input.templateBaseline.body);
    if (drift.drifted) {
      logger.warn('Semantic drift detected — reverting to baseline', { distance: drift.distance });
      finalBody = input.templateBaseline.body;
      finalSubject = input.templateBaseline.subject;
    }
  }

  // 4. Apply tone transform
  const toneResult = applyToneTransform(finalBody);
  if (!toneResult.reverted) {
    finalBody = toneResult.result;
  }

  const approved = lint.passed && tokenSanity.passed && !(drift?.drifted);

  if (!approved) {
    logger.warn('Copy rejected by quality gates', {
      lintPassed: lint.passed,
      tokenPassed: tokenSanity.passed,
      drifted: drift?.drifted ?? false,
      violations: [
        ...lint.violations.filter(v => v.severity === 'error'),
        ...tokenSanity.violations.filter(v => v.severity === 'error'),
      ].map(v => v.rule),
    });
  }

  return {
    approved,
    lint,
    tokenSanity,
    semanticDrift: drift,
    finalSubject,
    finalBody,
  };
}
