/**
 * @apexmail/ai — Assistant barrel export
 */
export {
    UnifiedAssistant, detectIntent, parseActions, stripActionBlocks,
    SYSTEM_PROMPT, checkActionSecurity, sanitizeInput, redactPII,
    DEFAULT_AUTONOMOUS_CONFIG, ACTION_RISK_LEVELS,
    detectSentimentScore, canAutoApprove,
    createEscalationTicket, createAuditEntry, generateProactiveMessage,
} from './unified.js';
export { ActionRouter } from './actions.js';
export type {
    AssistantActionType,
    AssistantAction,
    AssistantResponse,
    AssistantConfig,
} from './unified.js';
export type { ActionResult, ActionHandler, ActionRouterConfig } from './actions.js';
