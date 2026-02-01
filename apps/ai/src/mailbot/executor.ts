/**
 * @apexmail/ai - Mailbot Natural Language Command Executor
 * 
 * Executes natural language commands for email marketing operations.
 * Translates user intent into API actions with confirmation flows.
 */

import { IntentDetector } from '../chatbot/assistant.js';
import { InferenceEngine } from '../inference/engine.js';
import type {
    MailbotRequest,
    MailbotResponse,
    MailbotAction,
    MailbotActionType,
} from '../types.js';

/**
 * Command parameter extraction result
 */
interface ExtractedParams {
    campaignName?: string;
    listName?: string;
    segmentName?: string;
    subject?: string;
    content?: string;
    scheduledTime?: Date;
    tags?: string[];
    filter?: Record<string, unknown>;
    count?: number;
    email?: string;
}

/**
 * Command definition
 */
interface CommandDefinition {
    type: MailbotActionType;
    patterns: RegExp[];
    paramExtractors: Array<{
        name: keyof ExtractedParams;
        pattern: RegExp;
        transform?: (match: string) => unknown;
    }>;
    requiresConfirmation: boolean;
    description: string;
}

/**
 * Mailbot Executor
 * 
 * Processes natural language commands and translates them into
 * structured API actions with proper validation and confirmation.
 */
export class MailbotExecutor {
    private intentDetector: IntentDetector;
    private engine: InferenceEngine;
    private commands: CommandDefinition[];
    private pendingActions: Map<string, MailbotAction> = new Map();

    constructor() {
        this.intentDetector = new IntentDetector();
        this.engine = new InferenceEngine();
        this.commands = this.initializeCommands();
    }

    /**
     * Process a natural language command
     */
    async process(request: MailbotRequest): Promise<MailbotResponse> {
        const { command, context, userId } = request;
        const startTime = Date.now();

        try {
            // Parse the command
            const parsedCommand = this.parseCommand(command);

            if (!parsedCommand) {
                return {
                    success: false,
                    message: "I couldn't understand that command. Try something like:\n" +
                        "• Create a campaign called 'Summer Sale'\n" +
                        "• Send campaign 'Welcome Series' to list 'New Subscribers'\n" +
                        "• Show me the stats for campaign 'Newsletter'\n" +
                        "• Pause all scheduled campaigns",
                    latencyMs: Date.now() - startTime,
                };
            }

            // Build the action
            const action = this.buildAction(parsedCommand, context);

            // Check if confirmation is required
            if (parsedCommand.definition.requiresConfirmation) {
                const confirmationId = this.generateConfirmationId();
                this.pendingActions.set(confirmationId, action);

                return {
                    success: true,
                    message: this.buildConfirmationMessage(action),
                    action,
                    requiresConfirmation: true,
                    confirmationId,
                    latencyMs: Date.now() - startTime,
                };
            }

            // Execute immediately if no confirmation needed
            return {
                success: true,
                message: this.buildSuccessMessage(action),
                action,
                requiresConfirmation: false,
                latencyMs: Date.now() - startTime,
            };
        } catch (error) {
            return {
                success: false,
                message: `Error processing command: ${error instanceof Error ? error.message : 'Unknown error'}`,
                latencyMs: Date.now() - startTime,
            };
        }
    }

    /**
     * Confirm a pending action
     */
    confirmAction(confirmationId: string): MailbotResponse {
        const action = this.pendingActions.get(confirmationId);

        if (!action) {
            return {
                success: false,
                message: 'No pending action found with that confirmation ID.',
                latencyMs: 0,
            };
        }

        this.pendingActions.delete(confirmationId);

        return {
            success: true,
            message: this.buildSuccessMessage(action),
            action,
            requiresConfirmation: false,
            latencyMs: 0,
        };
    }

    /**
     * Cancel a pending action
     */
    cancelAction(confirmationId: string): MailbotResponse {
        const action = this.pendingActions.get(confirmationId);

        if (!action) {
            return {
                success: false,
                message: 'No pending action found with that confirmation ID.',
                latencyMs: 0,
            };
        }

        this.pendingActions.delete(confirmationId);

        return {
            success: true,
            message: `Action cancelled: ${action.type}`,
            latencyMs: 0,
        };
    }

    /**
     * Get suggestions for command completion
     */
    getSuggestions(partialCommand: string): string[] {
        const suggestions: string[] = [];
        const lower = partialCommand.toLowerCase();

        // Match against command patterns
        for (const cmd of this.commands) {
            for (const pattern of cmd.patterns) {
                const source = pattern.source.toLowerCase();
                if (source.includes(lower) || lower.includes(source.slice(0, 10))) {
                    suggestions.push(this.getExampleForCommand(cmd));
                    break;
                }
            }
        }

        return suggestions.slice(0, 5);
    }

    /**
     * Get all available commands
     */
    getAvailableCommands(): Array<{ type: string; description: string; example: string }> {
        return this.commands.map((cmd) => ({
            type: cmd.type,
            description: cmd.description,
            example: this.getExampleForCommand(cmd),
        }));
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private initializeCommands(): CommandDefinition[] {
        return [
            // Campaign commands
            {
                type: 'create_campaign',
                patterns: [
                    /create\s+(?:a\s+)?(?:new\s+)?campaign\s+(?:called|named)?\s*['""]?(.+?)['""]?$/i,
                    /new\s+campaign\s+['""](.+?)['""]$/i,
                    /start\s+(?:a\s+)?campaign\s+['""](.+?)['""]$/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /['""](.+?)['""]|(?:called|named)\s+(.+?)$/i },
                ],
                requiresConfirmation: false,
                description: 'Create a new email campaign',
            },
            {
                type: 'send_campaign',
                patterns: [
                    /send\s+(?:the\s+)?campaign\s+['""](.+?)['""](?:\s+to\s+(?:list\s+)?['""](.+?)['""'])?/i,
                    /send\s+['""](.+?)['""](?:\s+to\s+['""](.+?)['""'])?/i,
                    /launch\s+(?:the\s+)?campaign\s+['""](.+?)['""]/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /campaign\s+['""](.+?)['""]/i },
                    { name: 'listName', pattern: /to\s+(?:list\s+)?['""](.+?)['""]/i },
                ],
                requiresConfirmation: true,
                description: 'Send a campaign to subscribers',
            },
            {
                type: 'schedule_campaign',
                patterns: [
                    /schedule\s+(?:the\s+)?campaign\s+['""](.+?)['""](?:\s+for\s+(.+))?/i,
                    /schedule\s+['""](.+?)['""]\s+(?:for|at)\s+(.+)/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /['""](.+?)['""]/i },
                    { name: 'scheduledTime', pattern: /(?:for|at)\s+(.+)$/i, transform: (s) => this.parseDateTime(s) },
                ],
                requiresConfirmation: true,
                description: 'Schedule a campaign for later',
            },
            {
                type: 'pause_campaign',
                patterns: [
                    /pause\s+(?:the\s+)?campaign\s+['""](.+?)['""]/i,
                    /stop\s+(?:the\s+)?campaign\s+['""](.+?)['""]/i,
                    /pause\s+all\s+(?:scheduled\s+)?campaigns/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: true,
                description: 'Pause a running or scheduled campaign',
            },
            {
                type: 'delete_campaign',
                patterns: [
                    /delete\s+(?:the\s+)?campaign\s+['""](.+?)['""]/i,
                    /remove\s+(?:the\s+)?campaign\s+['""](.+?)['""]/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: true,
                description: 'Delete a campaign',
            },

            // Contact commands
            {
                type: 'add_contact',
                patterns: [
                    /add\s+(?:the\s+)?contact\s+(.+?)(?:\s+to\s+(?:list\s+)?['""](.+?)['"""])?$/i,
                    /add\s+(.+?@.+?)(?:\s+to\s+['""](.+?)['""'])?$/i,
                ],
                paramExtractors: [
                    { name: 'email', pattern: /([^\s]+@[^\s]+)/i },
                    { name: 'listName', pattern: /to\s+(?:list\s+)?['""](.+?)['""]/i },
                ],
                requiresConfirmation: false,
                description: 'Add a contact to a list',
            },
            {
                type: 'remove_contact',
                patterns: [
                    /remove\s+(?:the\s+)?contact\s+(.+?)(?:\s+from\s+(?:list\s+)?['""](.+?)['"""])?$/i,
                    /unsubscribe\s+(.+?@.+?)(?:\s+from\s+['""](.+?)['""'])?$/i,
                ],
                paramExtractors: [
                    { name: 'email', pattern: /([^\s]+@[^\s]+)/i },
                    { name: 'listName', pattern: /from\s+(?:list\s+)?['""](.+?)['""]/i },
                ],
                requiresConfirmation: true,
                description: 'Remove a contact from a list',
            },
            {
                type: 'import_contacts',
                patterns: [
                    /import\s+(?:contacts?\s+)?(?:from\s+)?['""](.+?)['""]/i,
                    /upload\s+(?:contacts?\s+)?(?:from\s+)?['""](.+?)['""]/i,
                ],
                paramExtractors: [],
                requiresConfirmation: true,
                description: 'Import contacts from a file',
            },

            // List commands
            {
                type: 'create_list',
                patterns: [
                    /create\s+(?:a\s+)?(?:new\s+)?list\s+(?:called|named)?\s*['""](.+?)['""]/i,
                    /new\s+list\s+['""](.+?)['""]/i,
                ],
                paramExtractors: [
                    { name: 'listName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: false,
                description: 'Create a new contact list',
            },
            {
                type: 'delete_list',
                patterns: [
                    /delete\s+(?:the\s+)?list\s+['""](.+?)['""]/i,
                    /remove\s+(?:the\s+)?list\s+['""](.+?)['""]/i,
                ],
                paramExtractors: [
                    { name: 'listName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: true,
                description: 'Delete a contact list',
            },

            // Segment commands
            {
                type: 'create_segment',
                patterns: [
                    /create\s+(?:a\s+)?segment\s+(?:called|named)?\s*['""](.+?)['""](?:\s+where\s+(.+))?/i,
                    /segment\s+(?:contacts?\s+)?(?:where|with)\s+(.+)/i,
                ],
                paramExtractors: [
                    { name: 'segmentName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: false,
                description: 'Create a new segment',
            },

            // Analytics commands
            {
                type: 'get_stats',
                patterns: [
                    /show\s+(?:me\s+)?(?:the\s+)?stats?\s+(?:for\s+)?(?:campaign\s+)?['""](.+?)['""]/i,
                    /(?:get|fetch)\s+(?:the\s+)?metrics?\s+(?:for\s+)?['""](.+?)['""]/i,
                    /how\s+(?:is|did)\s+['""](.+?)['""]\s+(?:doing|perform)/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: false,
                description: 'Get campaign statistics',
            },
            {
                type: 'export_report',
                patterns: [
                    /export\s+(?:the\s+)?report\s+(?:for\s+)?['""](.+?)['""]/i,
                    /download\s+(?:the\s+)?analytics?\s+(?:for\s+)?['""](.+?)['""]/i,
                ],
                paramExtractors: [
                    { name: 'campaignName', pattern: /['""](.+?)['""]/i },
                ],
                requiresConfirmation: false,
                description: 'Export a campaign report',
            },
        ];
    }

    private parseCommand(
        command: string
    ): { definition: CommandDefinition; params: ExtractedParams } | null {
        for (const cmdDef of this.commands) {
            for (const pattern of cmdDef.patterns) {
                if (pattern.test(command)) {
                    const params = this.extractParams(command, cmdDef);
                    return { definition: cmdDef, params };
                }
            }
        }

        return null;
    }

    private extractParams(command: string, cmdDef: CommandDefinition): ExtractedParams {
        const params: ExtractedParams = {};

        for (const extractor of cmdDef.paramExtractors) {
            const match = command.match(extractor.pattern);
            if (match) {
                const value = match[1] || match[2];
                if (value) {
                    if (extractor.transform) {
                        (params as Record<string, unknown>)[extractor.name] = extractor.transform(value);
                    } else {
                        (params as Record<string, unknown>)[extractor.name] = value;
                    }
                }
            }
        }

        return params;
    }

    private buildAction(
        parsed: { definition: CommandDefinition; params: ExtractedParams },
        context?: MailbotRequest['context']
    ): MailbotAction {
        const { definition, params } = parsed;

        return {
            type: definition.type,
            params: {
                ...params,
                // Add context-derived defaults
                listId: context?.activeList,
                campaignId: context?.activeCampaign,
            },
            description: definition.description,
        };
    }

    private buildConfirmationMessage(action: MailbotAction): string {
        const messages: Record<MailbotActionType, (params: ExtractedParams) => string> = {
            create_campaign: (p) => `Create campaign "${p.campaignName}"?`,
            send_campaign: (p) => `⚠️ Send campaign "${p.campaignName}"${p.listName ? ` to list "${p.listName}"` : ''}? This action cannot be undone.`,
            schedule_campaign: (p) => `Schedule campaign "${p.campaignName}" for ${p.scheduledTime || 'the specified time'}?`,
            pause_campaign: (p) => `Pause campaign "${p.campaignName}"?`,
            delete_campaign: (p) => `⚠️ Delete campaign "${p.campaignName}"? This action cannot be undone.`,
            add_contact: (p) => `Add contact "${p.email}"${p.listName ? ` to list "${p.listName}"` : ''}?`,
            remove_contact: (p) => `⚠️ Remove contact "${p.email}"${p.listName ? ` from list "${p.listName}"` : ''}?`,
            import_contacts: () => `Import contacts from the specified file?`,
            create_list: (p) => `Create list "${p.listName}"?`,
            delete_list: (p) => `⚠️ Delete list "${p.listName}"? All contacts will be removed.`,
            create_segment: (p) => `Create segment "${p.segmentName}"?`,
            get_stats: (p) => `Get stats for "${p.campaignName}"?`,
            export_report: (p) => `Export report for "${p.campaignName}"?`,
        };

        const messageBuilder = messages[action.type];
        return messageBuilder
            ? `${messageBuilder(action.params as ExtractedParams)}\n\nReply "confirm" or "cancel".`
            : `Execute ${action.type}?`;
    }

    private buildSuccessMessage(action: MailbotAction): string {
        const messages: Record<MailbotActionType, (params: ExtractedParams) => string> = {
            create_campaign: (p) => `✅ Campaign "${p.campaignName}" created successfully.`,
            send_campaign: (p) => `✅ Campaign "${p.campaignName}" is now sending.`,
            schedule_campaign: (p) => `✅ Campaign "${p.campaignName}" scheduled for ${p.scheduledTime}.`,
            pause_campaign: (p) => `✅ Campaign "${p.campaignName}" has been paused.`,
            delete_campaign: (p) => `✅ Campaign "${p.campaignName}" has been deleted.`,
            add_contact: (p) => `✅ Contact "${p.email}" added${p.listName ? ` to "${p.listName}"` : ''}.`,
            remove_contact: (p) => `✅ Contact "${p.email}" removed${p.listName ? ` from "${p.listName}"` : ''}.`,
            import_contacts: () => `✅ Contacts imported successfully.`,
            create_list: (p) => `✅ List "${p.listName}" created.`,
            delete_list: (p) => `✅ List "${p.listName}" deleted.`,
            create_segment: (p) => `✅ Segment "${p.segmentName}" created.`,
            get_stats: (p) => `📊 Fetching stats for "${p.campaignName}"...`,
            export_report: (p) => `📄 Exporting report for "${p.campaignName}"...`,
        };

        const messageBuilder = messages[action.type];
        return messageBuilder
            ? messageBuilder(action.params as ExtractedParams)
            : `✅ Action ${action.type} completed.`;
    }

    private getExampleForCommand(cmd: CommandDefinition): string {
        const examples: Record<MailbotActionType, string> = {
            create_campaign: 'Create a campaign called "Summer Sale"',
            send_campaign: 'Send campaign "Welcome Series" to list "New Subscribers"',
            schedule_campaign: 'Schedule campaign "Newsletter" for tomorrow at 9am',
            pause_campaign: 'Pause campaign "Flash Sale"',
            delete_campaign: 'Delete campaign "Old Promo"',
            add_contact: 'Add contact john@example.com to list "VIP"',
            remove_contact: 'Remove contact jane@example.com from list "Newsletter"',
            import_contacts: 'Import contacts from "contacts.csv"',
            create_list: 'Create a list called "Premium Members"',
            delete_list: 'Delete list "Inactive"',
            create_segment: 'Create segment "Engaged Users" where opens > 50%',
            get_stats: 'Show me stats for campaign "Black Friday"',
            export_report: 'Export report for "Q4 Newsletter"',
        };

        return examples[cmd.type] || cmd.description;
    }

    private parseDateTime(input: string): Date | undefined {
        const now = new Date();
        const lower = input.toLowerCase().trim();

        // Relative times
        if (lower === 'now') return now;
        if (lower.includes('tomorrow')) {
            const tomorrow = new Date(now);
            tomorrow.setDate(tomorrow.getDate() + 1);
            
            const timeMatch = lower.match(/at\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?/i);
            if (timeMatch) {
                let hours = parseInt(timeMatch[1]);
                const minutes = parseInt(timeMatch[2] || '0');
                const meridiem = timeMatch[3]?.toLowerCase();
                
                if (meridiem === 'pm' && hours < 12) hours += 12;
                if (meridiem === 'am' && hours === 12) hours = 0;
                
                tomorrow.setHours(hours, minutes, 0, 0);
            } else {
                tomorrow.setHours(9, 0, 0, 0); // Default to 9am
            }
            return tomorrow;
        }

        // In X hours/minutes
        const inMatch = lower.match(/in\s+(\d+)\s+(hour|minute|day|week)s?/i);
        if (inMatch) {
            const amount = parseInt(inMatch[1]);
            const unit = inMatch[2].toLowerCase();
            const result = new Date(now);
            
            switch (unit) {
                case 'minute':
                    result.setMinutes(result.getMinutes() + amount);
                    break;
                case 'hour':
                    result.setHours(result.getHours() + amount);
                    break;
                case 'day':
                    result.setDate(result.getDate() + amount);
                    break;
                case 'week':
                    result.setDate(result.getDate() + amount * 7);
                    break;
            }
            return result;
        }

        // Try parsing as date
        const parsed = new Date(input);
        return isNaN(parsed.getTime()) ? undefined : parsed;
    }

    private generateConfirmationId(): string {
        return `confirm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    }
}

export { CommandDefinition, ExtractedParams };
