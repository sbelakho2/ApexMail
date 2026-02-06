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
    setCampaignRepository,
} from './drip-engine.js';

export { CampaignRepository } from './repository.js';

export {
    campaignTemplates,
    getTemplate,
    getTemplatesByCategory,
    cloneTemplate,
} from './templates.js';
