/**
 * Engagement Trust Score Service
 * 
 * Implements a trust-based engagement scoring system following the Trust Equation:
 * Trust = (Credibility + Reliability + Intimacy) / Self-Orientation
 * 
 * This service helps measure and improve subscriber trust, moving beyond
 * simple open/click metrics to relationship-based KPIs.
 * 
 * @see https://trustedadvisor.com/build-trust/trust-equation
 * @see https://www.validity.com/blog/12-expert-predictions-for-the-email-marketing-industry-in-2026
 */

export interface SubscriberEngagement {
  subscriberId: string;
  email: string;
  
  // Engagement metrics
  totalEmailsSent: number;
  totalOpens: number;
  totalClicks: number;
  totalReplies: number;
  totalConversions: number;
  
  // Timing metrics
  firstEmailDate: Date;
  lastEngagementDate?: Date;
  averageTimeToOpen?: number; // minutes
  
  // Preference signals
  hasSetPreferences: boolean;
  preferenceLastUpdated?: Date;
  preferredFrequency?: 'daily' | 'weekly' | 'monthly';
  preferredCategories?: string[];
  
  // Negative signals
  totalComplaints: number;
  totalUnsubscribeClicks: number;
  markedAsSpam: boolean;
  
  // Feedback signals
  surveyResponses: number;
  npsScore?: number;
  feedbackSubmissions: number;
}

export interface TrustScore {
  overall: number; // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  
  // Component scores (0-100)
  credibilityScore: number;
  reliabilityScore: number;
  intimacyScore: number;
  selfOrientationScore: number; // Lower is better for trust
  
  // Interpretation
  interpretation: string;
  recommendations: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface CampaignTrustMetrics {
  campaignId: string;
  averageTrustScore: number;
  subscriberSegments: {
    highTrust: number;
    mediumTrust: number;
    lowTrust: number;
    atRisk: number;
  };
  trustTrend: 'improving' | 'stable' | 'declining';
  topRecommendations: string[];
}

export class EngagementTrustService {
  // Weights for trust equation components
  private readonly CREDIBILITY_WEIGHT = 0.3;
  private readonly RELIABILITY_WEIGHT = 0.3;
  private readonly INTIMACY_WEIGHT = 0.25;
  // Self-orientation weight (0.15) is applied as a divisor in the trust equation, not additive

  /**
   * Calculate trust score for a subscriber
   */
  calculateTrustScore(engagement: SubscriberEngagement): TrustScore {
    // Calculate component scores
    const credibility = this.calculateCredibility(engagement);
    const reliability = this.calculateReliability(engagement);
    const intimacy = this.calculateIntimacy(engagement);
    const selfOrientation = this.calculateSelfOrientation(engagement);

    // Trust equation: (C + R + I) / S
    // Normalize self-orientation so lower is better
    const normalizedSelfOrientation = Math.max(10, selfOrientation); // Prevent division by very small numbers
    
    const trustNumerator = (
      credibility * this.CREDIBILITY_WEIGHT +
      reliability * this.RELIABILITY_WEIGHT +
      intimacy * this.INTIMACY_WEIGHT
    );
    
    // Convert to 0-100 scale
    const rawTrust = (trustNumerator / (normalizedSelfOrientation / 100)) * 100;
    const overall = Math.min(100, Math.max(0, rawTrust));

    const grade = this.calculateGrade(overall);
    const riskLevel = this.calculateRiskLevel(overall, engagement);
    const interpretation = this.generateInterpretation(overall, engagement);
    const recommendations = this.generateRecommendations(
      credibility,
      reliability,
      intimacy,
      selfOrientation,
      engagement
    );

    return {
      overall: Math.round(overall),
      grade,
      credibilityScore: Math.round(credibility),
      reliabilityScore: Math.round(reliability),
      intimacyScore: Math.round(intimacy),
      selfOrientationScore: Math.round(selfOrientation),
      interpretation,
      recommendations,
      riskLevel,
    };
  }

  /**
   * Credibility: Do they believe what you say?
   * Based on: consistent delivery, authentication, content quality signals
   */
  private calculateCredibility(engagement: SubscriberEngagement): number {
    let score = 50; // Start at neutral

    // Positive: Opens indicate content is credible
    const openRate = engagement.totalEmailsSent > 0
      ? (engagement.totalOpens / engagement.totalEmailsSent) * 100
      : 0;
    score += Math.min(30, openRate);

    // Positive: Clicks indicate valuable content
    const clickRate = engagement.totalOpens > 0
      ? (engagement.totalClicks / engagement.totalOpens) * 100
      : 0;
    score += Math.min(15, clickRate * 0.5);

    // Negative: Spam complaints destroy credibility
    if (engagement.markedAsSpam) {
      score -= 40;
    }
    score -= engagement.totalComplaints * 10;

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Reliability: Do they know what to expect?
   * Based on: consistent sending, meeting expectations, preference honoring
   */
  private calculateReliability(engagement: SubscriberEngagement): number {
    let score = 40;

    // Positive: Has set preferences (knows what they want)
    if (engagement.hasSetPreferences) {
      score += 20;
    }

    // Positive: Long relationship
    if (engagement.firstEmailDate) {
      const daysAsSubscriber = Math.floor(
        (Date.now() - engagement.firstEmailDate.getTime()) / (1000 * 60 * 60 * 24)
      );
      score += Math.min(20, daysAsSubscriber / 30); // Up to 20 points for 600+ day relationship
    }

    // Positive: Recent engagement
    if (engagement.lastEngagementDate) {
      const daysSinceEngagement = Math.floor(
        (Date.now() - engagement.lastEngagementDate.getTime()) / (1000 * 60 * 60 * 24)
      );
      if (daysSinceEngagement < 7) score += 15;
      else if (daysSinceEngagement < 30) score += 10;
      else if (daysSinceEngagement < 90) score += 5;
      else score -= 10; // Stale subscriber
    }

    // Negative: Unsubscribe link clicks (wavering)
    score -= engagement.totalUnsubscribeClicks * 5;

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Intimacy: Do they feel safe with you?
   * Based on: two-way communication, feedback, preference sharing
   */
  private calculateIntimacy(engagement: SubscriberEngagement): number {
    let score = 30;

    // Positive: Replies (two-way communication!)
    score += Math.min(30, engagement.totalReplies * 10);

    // Positive: Survey responses
    score += Math.min(15, engagement.surveyResponses * 5);

    // Positive: Feedback submissions
    score += Math.min(10, engagement.feedbackSubmissions * 5);

    // Positive: NPS promoter (9-10)
    if (engagement.npsScore !== undefined) {
      if (engagement.npsScore >= 9) score += 15;
      else if (engagement.npsScore >= 7) score += 5;
      else if (engagement.npsScore <= 6) score -= 10;
    }

    // Positive: Updated preferences recently
    if (engagement.preferenceLastUpdated) {
      const daysSinceUpdate = Math.floor(
        (Date.now() - engagement.preferenceLastUpdated.getTime()) / (1000 * 60 * 60 * 24)
      );
      if (daysSinceUpdate < 90) score += 10;
    }

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Self-Orientation: Are you focused on them or yourself?
   * Higher score = more self-oriented = LOWER trust
   * Based on: frequency, promotional ratio, unsubscribe friction
   */
  private calculateSelfOrientation(engagement: SubscriberEngagement): number {
    let score = 30; // Start at reasonable baseline

    // High frequency without engagement = pushy
    if (engagement.totalEmailsSent > 0) {
      const engagementRate = (
        engagement.totalOpens +
        engagement.totalClicks +
        engagement.totalReplies
      ) / engagement.totalEmailsSent;
      
      if (engagementRate < 0.1) score += 30; // Very low engagement
      else if (engagementRate < 0.3) score += 15;
      else score -= 10; // Good engagement = not self-oriented
    }

    // Ignoring preferences = self-oriented
    if (!engagement.hasSetPreferences && engagement.totalEmailsSent > 10) {
      score += 15; // Haven't prompted for preferences
    }

    // Conversions relative to sends (not over-promoting)
    if (engagement.totalEmailsSent > 0) {
      const conversionRate = engagement.totalConversions / engagement.totalEmailsSent;
      if (conversionRate > 0.1) score -= 10; // Good conversions = providing value
    }

    return Math.min(100, Math.max(10, score));
  }

  /**
   * Calculate letter grade
   */
  private calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 85) return 'A';
    if (score >= 70) return 'B';
    if (score >= 55) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }

  /**
   * Calculate risk level
   */
  private calculateRiskLevel(
    score: number,
    engagement: SubscriberEngagement
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Critical if marked as spam or many complaints
    if (engagement.markedAsSpam || engagement.totalComplaints >= 2) {
      return 'critical';
    }

    // High risk if score is very low
    if (score < 30) return 'high';
    if (score < 50) return 'medium';
    return 'low';
  }

  /**
   * Generate human-readable interpretation
   */
  private generateInterpretation(
    score: number,
    _engagement: SubscriberEngagement
  ): string {
    if (score >= 85) {
      return 'This subscriber has high trust in your brand. They engage regularly, provide feedback, and value your communications.';
    }
    if (score >= 70) {
      return 'Good trust level. This subscriber engages with your content but there\'s room to deepen the relationship.';
    }
    if (score >= 55) {
      return 'Moderate trust. This subscriber is somewhat engaged but may need more personalization or value to strengthen the relationship.';
    }
    if (score >= 40) {
      return 'Low trust. This subscriber is at risk of disengaging. Consider a re-engagement campaign or preference update prompt.';
    }
    return 'Trust has eroded significantly. This subscriber should be moved to a win-back segment or sunset flow.';
  }

  /**
   * Generate actionable recommendations
   */
  private generateRecommendations(
    credibility: number,
    reliability: number,
    intimacy: number,
    selfOrientation: number,
    engagement: SubscriberEngagement
  ): string[] {
    const recommendations: string[] = [];

    // Low credibility recommendations
    if (credibility < 50) {
      recommendations.push('Improve email authentication (SPF, DKIM, DMARC) to boost sender credibility');
      recommendations.push('Review content quality - ensure subject lines match email content');
    }

    // Low reliability recommendations
    if (reliability < 50) {
      if (!engagement.hasSetPreferences) {
        recommendations.push('Prompt subscriber to set email preferences in a dedicated campaign');
      }
      recommendations.push('Ensure consistent sending schedule that matches subscriber expectations');
    }

    // Low intimacy recommendations
    if (intimacy < 50) {
      if (engagement.totalReplies === 0) {
        recommendations.push('Enable reply-to address and encourage two-way communication');
      }
      recommendations.push('Send a feedback survey to understand subscriber needs');
      recommendations.push('Add personalized content based on past engagement');
    }

    // High self-orientation recommendations
    if (selfOrientation > 60) {
      recommendations.push('Reduce sending frequency or let subscriber choose frequency');
      recommendations.push('Increase value-add content vs promotional content ratio');
      recommendations.push('Implement preference center to give subscriber more control');
    }

    // Specific situation recommendations
    if (engagement.markedAsSpam) {
      recommendations.push('URGENT: Review why subscriber marked as spam - check authentication and content');
    }

    if (engagement.lastEngagementDate) {
      const daysSince = Math.floor(
        (Date.now() - engagement.lastEngagementDate.getTime()) / (1000 * 60 * 60 * 24)
      );
      if (daysSince > 90) {
        recommendations.push('Subscriber inactive for 90+ days - add to re-engagement or sunset flow');
      }
    }

    return recommendations.slice(0, 5); // Max 5 recommendations
  }

  /**
   * Calculate trust metrics for a campaign audience
   */
  calculateCampaignTrustMetrics(
    campaignId: string,
    subscribers: SubscriberEngagement[],
    previousScores?: Map<string, number>
  ): CampaignTrustMetrics {
    const scores = subscribers.map(s => ({
      id: s.subscriberId,
      score: this.calculateTrustScore(s),
    }));

    const totalSubscribers = scores.length;
    const averageScore = scores.reduce((sum, s) => sum + s.score.overall, 0) / totalSubscribers;

    // Segment subscribers by trust level
    const highTrust = scores.filter(s => s.score.overall >= 70).length;
    const mediumTrust = scores.filter(s => s.score.overall >= 50 && s.score.overall < 70).length;
    const lowTrust = scores.filter(s => s.score.overall >= 30 && s.score.overall < 50).length;
    const atRisk = scores.filter(s => s.score.overall < 30).length;

    // Calculate trend if previous scores available
    let trustTrend: 'improving' | 'stable' | 'declining' = 'stable';
    if (previousScores && previousScores.size > 0) {
      let improved = 0;
      let declined = 0;
      
      for (const score of scores) {
        const prev = previousScores.get(score.id);
        if (prev !== undefined) {
          if (score.score.overall > prev + 5) improved++;
          else if (score.score.overall < prev - 5) declined++;
        }
      }

      if (improved > declined * 1.5) trustTrend = 'improving';
      else if (declined > improved * 1.5) trustTrend = 'declining';
    }

    // Generate top recommendations
    const allRecommendations = scores.flatMap(s => s.score.recommendations);
    const recommendationCounts = new Map<string, number>();
    for (const rec of allRecommendations) {
      recommendationCounts.set(rec, (recommendationCounts.get(rec) || 0) + 1);
    }
    const topRecommendations = [...recommendationCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([rec]) => rec);

    return {
      campaignId,
      averageTrustScore: Math.round(averageScore),
      subscriberSegments: {
        highTrust,
        mediumTrust,
        lowTrust,
        atRisk,
      },
      trustTrend,
      topRecommendations,
    };
  }

  /**
   * Get trust score benchmarks by industry
   */
  getTrustBenchmarks(): Record<string, { average: number; excellent: number }> {
    return {
      ecommerce: { average: 55, excellent: 75 },
      saas: { average: 60, excellent: 80 },
      media: { average: 50, excellent: 70 },
      finance: { average: 65, excellent: 85 },
      healthcare: { average: 70, excellent: 90 },
      nonprofit: { average: 65, excellent: 85 },
    };
  }
}

/**
 * Factory function
 */
export function createEngagementTrustService(): EngagementTrustService {
  return new EngagementTrustService();
}

export default EngagementTrustService;
