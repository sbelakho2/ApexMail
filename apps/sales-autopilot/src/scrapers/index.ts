/**
 * Scraper Index - Exports all scraping modules
 */

export { isUrlAllowed, getCrawlDelay, getSitemapUrls, clearRobotsCache } from './robots-service.js';
export { acquireToken, waitForRateLimit, getRateLimitStatus, resetRateLimits } from './rate-limiter.js';
export {
    resolveMxRecords,
    identifyEmailProvider,
    hasEmailCapability,
    getEmailInfrastructure,
    validateEmailExists,
    batchResolveMx,
} from './dns-resolver.js';
export {
    scrapeProductHunt,
    scrapeG2,
    scrapeCapterra,
    scrapeCrunchbase,
    enrichWithMxRecords,
    scrapedToLeads,
    runDiscoveryJob,
    exportLeadsToCsv,
    getLeadScoringModel,
    setLeadScoringModel,
    calculateLeadScore,
} from './saas-hunter.js';

// Hunter Training System
export {
    extractFeatures,
    LeadScoringModel,
    generateSyntheticTrainingData,
    trainUntilQualityThreshold,
    calculateQualityMetrics,
    type LeadFeatures,
    type TrainingSample,
    type LeadLabel,
    type QualityMetrics,
} from './hunter-training.js';

// Hunter Quality Testing
export {
    runQualityTests,
    runOptimizationLoop,
    runFullTrainingPipeline,
    validateCompany,
    scrapeCompanyWebsite,
    calculateStringSimilarity,
    GROUND_TRUTH_COMPANIES,
} from './hunter-quality-test.js';
