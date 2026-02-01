/**
 * Campaigns Index
 */

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
} from './drip-engine.js';

export {
    campaignTemplates,
    getTemplate,
    getTemplatesByCategory,
    cloneTemplate,
} from './templates.js';
