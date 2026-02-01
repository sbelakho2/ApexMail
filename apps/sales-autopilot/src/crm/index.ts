/**
 * CRM Index
 */

export {
    createDefaultPipeline,
    getPipeline,
    addStageAutomation,
    storeLead,
    getLead,
    updateLead,
    moveLeadToStage,
    recordActivity,
    getLeadActivities,
    createTask,
    updateTask,
    completeTask,
    getLeadTasks,
    getOverdueTasks,
    filterLeads,
    getPipelineStats,
    getLeadsNeedingFollowUp,
    getRottenLeads,
} from './pipeline.js';
