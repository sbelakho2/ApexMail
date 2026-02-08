/**
 * Personalization Engine — Top-K Retrieval with Fallback Ladder
 *
 * Replaces hard sim>0.5 threshold with:
 *   1. Top-K retrieval (top 50 by similarity)
 *   2. If best sim < 0.35, fall back to cohort priors
 *   3. Fallback ladder: exact cohort → broad cohort → global defaults
 *
 * Additional improvements:
 *   • Weighted cosine similarity (learnable per-dimension weights)
 *   • Recency-weighted engagement scores (30/60/90 days > lifetime)
 *   • Per-channel normalization (open/click inflation by provider)
 *   • De-duplication of similar profiles (no overlearning from one account)
 *   • Cold-start personalization (industry/role/company-size + safe tone)
 */

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface ContactProfile {
  id: string;
  accountId: string;
  industry: string;
  role: string;
  companySize: string;
  /** Feature vector for similarity computation */
  features: number[];
  /** Engagement events with timestamps */
  engagementHistory: EngagementEvent[];
  /** Which email provider (for normalization) */
  emailProvider: string | null;
  createdAt: Date;
}

export interface EngagementEvent {
  type: 'open' | 'click' | 'reply' | 'bounce' | 'unsubscribe';
  occurredAt: Date;
  channel: string;
}

export interface CohortPrior {
  industry: string;
  role: string;
  companySize: string;
  /** Average feature vector for this cohort */
  avgFeatures: number[];
  /** Recommended tone */
  defaultTone: string;
  /** Recommended value props */
  defaultValueProps: string[];
  sampleSize: number;
}

export interface PersonalizationResult {
  strategy: 'top_k' | 'exact_cohort' | 'broad_cohort' | 'global_default' | 'cold_start';
  similarProfiles: SimilarProfile[];
  engagementScore: number;
  recommendedTone: string;
  recommendedValueProps: string[];
  confidenceLevel: number;
}

export interface SimilarProfile {
  contactId: string;
  similarity: number;
  accountId: string;
}

export interface PersonalizationConfig {
  topK: number;
  minSimilarityThreshold: number;
  recencyWeights: RecencyWeights;
  channelNormalization: Record<string, ChannelNorm>;
  maxProfilesPerAccount: number;
  dimensionWeights: number[] | null;
}

export interface RecencyWeights {
  last30d: number;
  last60d: number;
  last90d: number;
  older: number;
}

export interface ChannelNorm {
  openMultiplier: number;
  clickMultiplier: number;
}

// ────────────────────────────────────────────────────────────────────
// Defaults
// ────────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: PersonalizationConfig = {
  topK: 50,
  minSimilarityThreshold: 0.35,
  recencyWeights: {
    last30d: 1.0,
    last60d: 0.6,
    last90d: 0.3,
    older: 0.1,
  },
  channelNormalization: {
    'google': { openMultiplier: 1.0, clickMultiplier: 1.0 },
    'microsoft': { openMultiplier: 0.85, clickMultiplier: 0.9 },
    'yahoo': { openMultiplier: 0.7, clickMultiplier: 0.8 },
    'default': { openMultiplier: 1.0, clickMultiplier: 1.0 },
  },
  maxProfilesPerAccount: 3,
  dimensionWeights: null,
};

const GLOBAL_DEFAULTS = {
  tone: 'professional',
  valueProps: [
    'reliable email delivery infrastructure',
    'real-time event tracking and webhooks',
    'developer-first API with comprehensive SDKs',
  ],
};

// ────────────────────────────────────────────────────────────────────
// Engine
// ────────────────────────────────────────────────────────────────────

export class PersonalizationEngine {
  private config: PersonalizationConfig;
  private cohortPriors: Map<string, CohortPrior> = new Map();
  private profiles: Map<string, ContactProfile> = new Map();

  constructor(config?: Partial<PersonalizationConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ─────── Profile Management ───────

  addProfile(profile: ContactProfile): void {
    this.profiles.set(profile.id, profile);
  }

  addCohortPrior(prior: CohortPrior): void {
    // Key: "industry:role:companySize"
    const key = `${prior.industry}:${prior.role}:${prior.companySize}`;
    this.cohortPriors.set(key, prior);
  }

  // ─────── Main Personalization ───────

  personalize(contact: ContactProfile): PersonalizationResult {
    // Cold-start check: new contacts with no engagement
    if (this.isColdStart(contact)) {
      return this.coldStartPersonalization(contact);
    }

    // Step 1: Top-K retrieval
    const topK = this.topKRetrieval(contact);
    const bestSim = topK.length > 0 ? topK[0]!.similarity : 0;

    if (bestSim >= this.config.minSimilarityThreshold && topK.length > 0) {
      // Good similarity — use top-K personalization
      const engScore = this.recencyWeightedEngagement(contact);
      return {
        strategy: 'top_k',
        similarProfiles: topK.slice(0, 10), // Return top 10 for display
        engagementScore: engScore,
        recommendedTone: this.inferTone(topK),
        recommendedValueProps: this.inferValueProps(topK),
        confidenceLevel: Math.min(1, bestSim * 1.5),
      };
    }

    // Step 2: Fallback ladder
    return this.fallbackLadder(contact);
  }

  // ─────── Top-K Retrieval ───────

  private topKRetrieval(contact: ContactProfile): SimilarProfile[] {
    const allProfiles = Array.from(this.profiles.values()).filter(
      p => p.id !== contact.id
    );

    // Compute weighted cosine similarity
    const scored: SimilarProfile[] = [];
    const accountCounts: Map<string, number> = new Map();

    for (const profile of allProfiles) {
      const sim = this.weightedCosineSimilarity(contact.features, profile.features);
      scored.push({
        contactId: profile.id,
        similarity: sim,
        accountId: profile.accountId,
      });
    }

    // Sort by similarity descending
    scored.sort((a, b) => b.similarity - a.similarity);

    // De-duplicate: max N profiles per account to prevent overlearning
    const deduped: SimilarProfile[] = [];
    for (const item of scored) {
      const count = accountCounts.get(item.accountId) || 0;
      if (count >= this.config.maxProfilesPerAccount) continue;
      accountCounts.set(item.accountId, count + 1);
      deduped.push(item);
      if (deduped.length >= this.config.topK) break;
    }

    return deduped;
  }

  // ─────── Weighted Cosine Similarity ───────

  private weightedCosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length || a.length === 0) return 0;

    const w = this.config.dimensionWeights;
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      const weight = w && w[i] !== undefined ? w[i]! : 1.0;
      const wa = a[i]! * weight;
      const wb = b[i]! * weight;
      dotProduct += wa * wb;
      normA += wa * wa;
      normB += wb * wb;
    }

    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dotProduct / denom;
  }

  // ─────── Recency-Weighted Engagement ───────

  recencyWeightedEngagement(contact: ContactProfile): number {
    const now = Date.now();
    const d30 = 30 * 24 * 3600_000;
    const d60 = 60 * 24 * 3600_000;
    const d90 = 90 * 24 * 3600_000;

    let score = 0;
    const norm = this.getChannelNorm(contact.emailProvider);

    for (const event of contact.engagementHistory) {
      const age = now - event.occurredAt.getTime();
      let weight: number;

      if (age <= d30) weight = this.config.recencyWeights.last30d;
      else if (age <= d60) weight = this.config.recencyWeights.last60d;
      else if (age <= d90) weight = this.config.recencyWeights.last90d;
      else weight = this.config.recencyWeights.older;

      // Event type scoring with channel normalization
      let eventScore: number;
      switch (event.type) {
        case 'open': eventScore = 1 * norm.openMultiplier; break;
        case 'click': eventScore = 3 * norm.clickMultiplier; break;
        case 'reply': eventScore = 5; break;
        case 'bounce': eventScore = -2; break;
        case 'unsubscribe': eventScore = -5; break;
        default: eventScore = 0;
      }

      score += eventScore * weight;
    }

    return Math.max(0, score);
  }

  // ─────── Fallback Ladder ───────

  private fallbackLadder(contact: ContactProfile): PersonalizationResult {
    // 1. Exact cohort: industry + role + companySize
    const exactKey = `${contact.industry}:${contact.role}:${contact.companySize}`;
    const exactCohort = this.cohortPriors.get(exactKey);
    if (exactCohort && exactCohort.sampleSize >= 5) {
      return {
        strategy: 'exact_cohort',
        similarProfiles: [],
        engagementScore: this.recencyWeightedEngagement(contact),
        recommendedTone: exactCohort.defaultTone,
        recommendedValueProps: exactCohort.defaultValueProps,
        confidenceLevel: 0.5,
      };
    }

    // 2. Broad cohort: industry only
    for (const [key, cohort] of this.cohortPriors) {
      if (key.startsWith(`${contact.industry}:`) && cohort.sampleSize >= 10) {
        return {
          strategy: 'broad_cohort',
          similarProfiles: [],
          engagementScore: this.recencyWeightedEngagement(contact),
          recommendedTone: cohort.defaultTone,
          recommendedValueProps: cohort.defaultValueProps,
          confidenceLevel: 0.3,
        };
      }
    }

    // 3. Global defaults (never stall)
    return {
      strategy: 'global_default',
      similarProfiles: [],
      engagementScore: this.recencyWeightedEngagement(contact),
      recommendedTone: GLOBAL_DEFAULTS.tone,
      recommendedValueProps: GLOBAL_DEFAULTS.valueProps,
      confidenceLevel: 0.1,
    };
  }

  // ─────── Cold-Start Personalization ───────

  private isColdStart(contact: ContactProfile): boolean {
    return contact.engagementHistory.length === 0;
  }

  private coldStartPersonalization(contact: ContactProfile): PersonalizationResult {
    // Only use industry/role/company-size + safe default tone
    // No fancy text heuristics for new contacts
    const exactKey = `${contact.industry}:${contact.role}:${contact.companySize}`;
    const cohort = this.cohortPriors.get(exactKey);

    return {
      strategy: 'cold_start',
      similarProfiles: [],
      engagementScore: 0,
      recommendedTone: cohort?.defaultTone ?? 'professional',
      recommendedValueProps: cohort?.defaultValueProps ?? GLOBAL_DEFAULTS.valueProps,
      confidenceLevel: 0.2,
    };
  }

  // ─────── Helpers ───────

  private getChannelNorm(provider: string | null): ChannelNorm {
    if (!provider) return this.config.channelNormalization['default']!;
    const key = provider.toLowerCase();
    return this.config.channelNormalization[key] ?? this.config.channelNormalization['default']!;
  }

  private inferTone(_profiles: SimilarProfile[]): string {
    // For now, return professional. In production, this would aggregate
    // the tone that worked best for similar profiles.
    return 'professional';
  }

  private inferValueProps(_profiles: SimilarProfile[]): string[] {
    return GLOBAL_DEFAULTS.valueProps;
  }
}

// Singleton
export const personalizationEngine = new PersonalizationEngine();
