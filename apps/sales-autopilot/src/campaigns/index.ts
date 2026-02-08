/**
 * Campaigns Index — all campaign modules
 */

// ── Core drip engine ──
export {
    createCampaign,
    updateCampaignStatus,
    addSequenceStep,
    enrollLead,
    processEnrollmentStep,
    getReadyEnrollments,
    getCampaign,
    getTenantCampaigns,
    getEnrollment,
    getLeadEnrollments,
    recordEngagement,
    pauseEnrollment,
    resumeEnrollment,
    startCampaignProcessor,
    stopCampaignProcessor,
    setCampaignRepository,
    hydrateCaches,
} from './drip-engine.js';

// ── Repository ──
export { CampaignRepository } from './repository.js';

// ── Templates (Cialdini-optimised) ──
export {
    campaignTemplates,
    getTemplate,
    getTemplatesByCategory,
    getTemplatesByPrinciple,
    cloneTemplate,
} from './templates.js';

// ── Multi-armed bandits (Thompson sampling) ──
export { BanditManager, banditManager } from './bandits.js';

// ── Funnel tracking & control groups ──
export { FunnelTracker, funnelTracker } from './funnel-tracker.js';

// ── Personalisation engine ──
export { PersonalizationEngine, personalizationEngine } from './personalization.js';

// ── Copy gates (lint, token validation, semantic drift) ──
export {
    lintCopy,
    validateTokens,
    checkSemanticDrift,
    validateAndProcessCopy,
} from './copy-gates.js';

// ── Cadence governor (touch limits, timezone, stop signals) ──
export { CadenceGovernor, cadenceGovernor } from './cadence-governor.js';

// ── Safety monitor (rollback, poison pill, lead validation) ──
export { SafetyMonitor, safetyMonitor, validateLeadList } from './safety.js';

// ── Migration hub (provider migration guides) ──
export {
    getProvider,
    getAllProviderSlugs,
    generateMigrationPageContent,
} from './migration-hub.js';

// ── Error encyclopedia ──
export {
    getErrorEntry,
    getErrorsByCategory,
    getAllErrorCodes,
    searchErrors,
    ERROR_ENTRIES,
} from './error-encyclopedia.js';

// ── Activation path (5-minute onboarding) ──
export {
    ActivationTracker,
    activationTracker,
    ACTIVATION_STEPS,
    validateSandboxSend,
    SANDBOX_DEFAULTS,
} from './activation-path.js';

// ── Hourly optimisation loop ──
export {
    HourlyLoopOrchestrator,
    hourlyLoop,
} from './hourly-loop.js';

// ── Operator console ──
export {
    OperatorConsole,
    operatorConsole,
} from './operator-console.js';

