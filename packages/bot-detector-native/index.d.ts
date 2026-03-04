/// <reference types="node" />

/**
 * @module @apexmail/bot-detector-native
 *
 * Native Node.js bindings for bot/crawler detection using Aho-Corasick
 * multi-pattern matching. 70+ known bot User-Agent patterns are compiled
 * into an automaton at init time for O(n) matching regardless of pattern count.
 */

export interface BotDetectionResult {
  isBot: boolean
  userAgent: string
  matchedPattern: string | null
  category: string | null
  confidence: number
}

export interface BatchBotResult {
  results: BotDetectionResult[]
  botCount: number
  humanCount: number
}

export interface BotPatternInput {
  pattern: string
  category: string
}

/**
 * Detect if a User-Agent string belongs to a known bot.
 *
 * Uses Aho-Corasick automaton for O(n) matching across 70+ patterns.
 */
export declare function detectBot(userAgent: string): BotDetectionResult

/**
 * Batch detect bots in multiple User-Agent strings.
 */
export declare function detectBotsBatch(
  userAgents: string[],
): BatchBotResult

/**
 * Check if a specific pattern exists in the bot pattern database.
 */
export declare function isKnownBotPattern(pattern: string): boolean

/**
 * Get all bot patterns grouped by category.
 */
export declare function getBotPatterns(): Record<string, string[]>

/**
 * Get the total number of loaded patterns.
 */
export declare function patternCount(): number

/**
 * Get all categories as a JSON string.
 */
export declare function getCategories(): string

/**
 * Warm up the Aho-Corasick automaton. Call once at startup.
 * Returns true if the automaton was (re)built.
 */
export declare function warmup(): boolean

/**
 * Add or replace custom bot patterns at runtime.
 *
 * @param patterns - Array of { pattern, category } objects.
 * @param replace  - If true, replaces all patterns; if false, merges.
 * @returns        The new total pattern count.
 */
export declare function setCustomPatterns(
  patterns: BotPatternInput[],
  replace: boolean,
): number
