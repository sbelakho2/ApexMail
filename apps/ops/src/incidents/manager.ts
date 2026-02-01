/**
 * @apexmail/ops - Incident Manager
 * 
 * Comprehensive incident management with workflows, timeline, and post-mortems.
 */

import {
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimeline,
    IncidentTimelineEvent,
    Alert,
} from '../types.js';
import { EventEmitter } from 'events';
import pino from 'pino';

const logger = pino({ name: 'incident-manager' });

export interface IncidentManagerConfig {
    autoCreateFromAlerts: boolean;
    criticalAlertThreshold: number;
    slackChannelPrefix: string;
    postMortemDueDays: number;
}

interface IncidentRole {
    userId: string;
    role: 'commander' | 'communication' | 'technical' | 'scribe';
    assignedAt: Date;
}

interface PostMortem {
    id: string;
    incidentId: string;
    status: 'pending' | 'in_progress' | 'completed';
    dueDate: Date;
    summary?: string;
    timeline?: string;
    rootCause?: string;
    contributing_factors?: string[];
    actionItems?: {
        id: string;
        description: string;
        assignee: string;
        dueDate: Date;
        status: 'open' | 'in_progress' | 'completed';
    }[];
    lessonsLearned?: string[];
    completedAt?: Date;
    completedBy?: string;
}

export class IncidentManager extends EventEmitter {
    private config: IncidentManagerConfig;
    private incidents: Map<string, Incident> = new Map();
    private incidentHistory: Incident[] = [];
    private timelines: Map<string, IncidentTimeline> = new Map();
    private roles: Map<string, IncidentRole[]> = new Map();
    private postMortems: Map<string, PostMortem> = new Map();
    private relatedAlerts: Map<string, string[]> = new Map(); // incidentId -> alertIds

    constructor(config: IncidentManagerConfig) {
        super();
        this.config = config;
    }

    /**
     * Creates a new incident
     */
    createIncident(params: {
        title: string;
        description: string;
        severity: IncidentSeverity;
        affectedServices: string[];
        reportedBy: string;
        relatedAlertIds?: string[];
    }): Incident {
        const incident: Incident = {
            id: `inc-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            title: params.title,
            description: params.description,
            severity: params.severity,
            status: 'investigating',
            affectedServices: params.affectedServices,
            createdAt: new Date(),
            updatedAt: new Date(),
            reportedBy: params.reportedBy,
        };

        this.incidents.set(incident.id, incident);

        // Initialize timeline
        const timeline: IncidentTimeline = {
            incidentId: incident.id,
            events: [
                {
                    id: `evt-${Date.now()}`,
                    timestamp: new Date(),
                    type: 'created',
                    actor: params.reportedBy,
                    description: 'Incident created',
                    metadata: {
                        title: incident.title,
                        severity: incident.severity,
                    },
                },
            ],
        };
        this.timelines.set(incident.id, timeline);

        // Track related alerts
        if (params.relatedAlertIds?.length) {
            this.relatedAlerts.set(incident.id, params.relatedAlertIds);
        }

        // Create Slack channel for incident
        this.createIncidentChannel(incident);

        this.emit('incident:created', incident);
        logger.info({ incidentId: incident.id, severity: incident.severity }, 'Incident created');

        return incident;
    }

    /**
     * Creates a new incident from an alert
     */
    createFromAlert(alert: Alert): Incident {
        return this.createIncident({
            title: `Alert: ${alert.name}`,
            description: alert.description,
            severity: this.mapAlertSeverityToIncident(alert.severity),
            affectedServices: [alert.labels?.service || 'unknown'],
            reportedBy: 'system',
            relatedAlertIds: [alert.id],
        });
    }

    /**
     * Maps alert severity to incident severity
     */
    private mapAlertSeverityToIncident(
        alertSeverity: string
    ): IncidentSeverity {
        switch (alertSeverity) {
            case 'critical':
                return 'critical';
            case 'error':
                return 'high';
            case 'warning':
                return 'medium';
            default:
                return 'low';
        }
    }

    /**
     * Updates incident status
     */
    updateStatus(
        incidentId: string,
        status: IncidentStatus,
        message: string,
        updatedBy: string
    ): void {
        const incident = this.incidents.get(incidentId);
        if (!incident) return;

        const previousStatus = incident.status;
        incident.status = status;
        incident.updatedAt = new Date();

        if (status === 'resolved') {
            incident.resolvedAt = new Date();
            incident.resolvedBy = updatedBy;
        }

        // Add timeline event
        this.addTimelineEvent(incidentId, {
            type: 'status_change',
            actor: updatedBy,
            description: message,
            metadata: {
                previousStatus,
                newStatus: status,
            },
        });

        this.emit('incident:status:changed', {
            incident,
            previousStatus,
            newStatus: status,
            message,
        });

        logger.info(
            { incidentId, previousStatus, newStatus: status },
            'Incident status updated'
        );

        // Handle post-incident tasks
        if (status === 'resolved') {
            this.handleResolution(incident);
        }
    }

    /**
     * Updates incident severity
     */
    updateSeverity(
        incidentId: string,
        severity: IncidentSeverity,
        reason: string,
        updatedBy: string
    ): void {
        const incident = this.incidents.get(incidentId);
        if (!incident) return;

        const previousSeverity = incident.severity;
        incident.severity = severity;
        incident.updatedAt = new Date();

        this.addTimelineEvent(incidentId, {
            type: 'severity_change',
            actor: updatedBy,
            description: reason,
            metadata: {
                previousSeverity,
                newSeverity: severity,
            },
        });

        this.emit('incident:severity:changed', {
            incident,
            previousSeverity,
            newSeverity: severity,
        });
    }

    /**
     * Assigns a role to a user
     */
    assignRole(
        incidentId: string,
        userId: string,
        role: IncidentRole['role'],
        assignedBy: string
    ): void {
        const incident = this.incidents.get(incidentId);
        if (!incident) return;

        const roles = this.roles.get(incidentId) || [];

        // Remove existing assignment for this role
        const filtered = roles.filter((r) => r.role !== role);
        filtered.push({
            userId,
            role,
            assignedAt: new Date(),
        });

        this.roles.set(incidentId, filtered);

        if (role === 'commander') {
            incident.commander = userId;
        }

        this.addTimelineEvent(incidentId, {
            type: 'role_assigned',
            actor: assignedBy,
            description: `${userId} assigned as ${role}`,
            metadata: { userId, role },
        });

        this.emit('incident:role:assigned', { incidentId, userId, role });
    }

    /**
     * Adds a timeline event
     */
    addTimelineEvent(
        incidentId: string,
        event: Omit<IncidentTimelineEvent, 'id' | 'timestamp'>
    ): void {
        const timeline = this.timelines.get(incidentId);
        if (!timeline) return;

        const fullEvent: IncidentTimelineEvent = {
            id: `evt-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
            timestamp: new Date(),
            ...event,
        };

        timeline.events.push(fullEvent);
        this.emit('incident:timeline:event', { incidentId, event: fullEvent });
    }

    /**
     * Adds a note to the incident
     */
    addNote(incidentId: string, content: string, author: string): void {
        this.addTimelineEvent(incidentId, {
            type: 'note',
            actor: author,
            description: content,
        });
    }

    /**
     * Links an alert to an incident
     */
    linkAlert(incidentId: string, alertId: string): void {
        const alerts = this.relatedAlerts.get(incidentId) || [];
        if (!alerts.includes(alertId)) {
            alerts.push(alertId);
            this.relatedAlerts.set(incidentId, alerts);

            this.addTimelineEvent(incidentId, {
                type: 'note',
                actor: 'system',
                description: `Alert ${alertId} linked to incident`,
                metadata: { alertId },
            });
        }
    }

    /**
     * Creates Slack channel for incident
     */
    private createIncidentChannel(incident: Incident): void {
        const channelName = `${this.config.slackChannelPrefix}-${incident.id}`;
        
        this.emit('slack:create_channel', {
            name: channelName,
            incident,
        });

        this.addTimelineEvent(incident.id, {
            type: 'note',
            actor: 'system',
            description: `Slack channel #${channelName} created`,
        });
    }

    /**
     * Handles post-resolution tasks
     */
    private handleResolution(incident: Incident): void {
        // Calculate duration
        const duration = incident.resolvedAt
            ? incident.resolvedAt.getTime() - incident.createdAt.getTime()
            : 0;

        logger.info(
            { incidentId: incident.id, duration: duration / 1000 / 60 },
            'Incident resolved'
        );

        // Create post-mortem for high/critical incidents
        if (incident.severity === 'critical' || incident.severity === 'high') {
            this.createPostMortem(incident);
        }

        // Move to history
        this.incidentHistory.push(incident);
        this.incidents.delete(incident.id);
    }

    /**
     * Creates a post-mortem for an incident
     */
    createPostMortem(incident: Incident): PostMortem {
        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + this.config.postMortemDueDays);

        const postMortem: PostMortem = {
            id: `pm-${incident.id}`,
            incidentId: incident.id,
            status: 'pending',
            dueDate,
        };

        this.postMortems.set(postMortem.id, postMortem);
        this.emit('postmortem:created', postMortem);

        logger.info(
            { postMortemId: postMortem.id, incidentId: incident.id },
            'Post-mortem created'
        );

        return postMortem;
    }

    /**
     * Updates a post-mortem
     */
    updatePostMortem(
        postMortemId: string,
        updates: Partial<PostMortem>
    ): PostMortem | null {
        const postMortem = this.postMortems.get(postMortemId);
        if (!postMortem) return null;

        Object.assign(postMortem, updates);

        if (updates.status === 'completed') {
            postMortem.completedAt = new Date();
        }

        this.emit('postmortem:updated', postMortem);
        return postMortem;
    }

    /**
     * Adds an action item to a post-mortem
     */
    addActionItem(
        postMortemId: string,
        item: {
            description: string;
            assignee: string;
            dueDate: Date;
        }
    ): void {
        const postMortem = this.postMortems.get(postMortemId);
        if (!postMortem) return;

        if (!postMortem.actionItems) {
            postMortem.actionItems = [];
        }

        postMortem.actionItems.push({
            id: `action-${Date.now()}`,
            ...item,
            status: 'open',
        });

        this.emit('postmortem:action_added', { postMortemId, item });
    }

    /**
     * Gets an incident by ID
     */
    getIncident(incidentId: string): Incident | undefined {
        return (
            this.incidents.get(incidentId) ||
            this.incidentHistory.find((i) => i.id === incidentId)
        );
    }

    /**
     * Gets active incidents
     */
    getActiveIncidents(): Incident[] {
        return Array.from(this.incidents.values());
    }

    /**
     * Gets incident timeline
     */
    getTimeline(incidentId: string): IncidentTimeline | undefined {
        return this.timelines.get(incidentId);
    }

    /**
     * Gets incident roles
     */
    getRoles(incidentId: string): IncidentRole[] {
        return this.roles.get(incidentId) || [];
    }

    /**
     * Gets related alerts for an incident
     */
    getRelatedAlerts(incidentId: string): string[] {
        return this.relatedAlerts.get(incidentId) || [];
    }

    /**
     * Gets post-mortem for an incident
     */
    getPostMortem(incidentId: string): PostMortem | undefined {
        return this.postMortems.get(`pm-${incidentId}`);
    }

    /**
     * Gets incident history
     */
    getHistory(options: {
        limit?: number;
        offset?: number;
        severity?: IncidentSeverity[];
        startDate?: Date;
        endDate?: Date;
    } = {}): Incident[] {
        const {
            limit = 50,
            offset = 0,
            severity,
            startDate,
            endDate,
        } = options;

        let incidents = [...this.incidentHistory];

        if (severity) {
            incidents = incidents.filter((i) => severity.includes(i.severity));
        }

        if (startDate) {
            incidents = incidents.filter((i) => i.createdAt >= startDate);
        }

        if (endDate) {
            incidents = incidents.filter((i) => i.createdAt <= endDate);
        }

        return incidents
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
            .slice(offset, offset + limit);
    }

    /**
     * Gets incident statistics
     */
    getStatistics(period: { start: Date; end: Date }): {
        total: number;
        bySeverity: Record<IncidentSeverity, number>;
        mttr: number;
        mtta: number;
        affectedServicesCount: Record<string, number>;
    } {
        const relevantIncidents = this.incidentHistory.filter(
            (i) =>
                i.createdAt >= period.start &&
                i.createdAt <= period.end
        );

        const bySeverity: Record<IncidentSeverity, number> = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        const affectedServicesCount: Record<string, number> = {};
        const resolutionTimes: number[] = [];
        const acknowledgeTimes: number[] = [];

        for (const incident of relevantIncidents) {
            bySeverity[incident.severity]++;

            for (const service of incident.affectedServices) {
                affectedServicesCount[service] =
                    (affectedServicesCount[service] || 0) + 1;
            }

            if (incident.resolvedAt) {
                resolutionTimes.push(
                    incident.resolvedAt.getTime() - incident.createdAt.getTime()
                );
            }

            if (incident.acknowledgedAt) {
                acknowledgeTimes.push(
                    incident.acknowledgedAt.getTime() - incident.createdAt.getTime()
                );
            }
        }

        // MTTR (Mean Time To Resolve) in minutes
        const mttr =
            resolutionTimes.length > 0
                ? resolutionTimes.reduce((a, b) => a + b, 0) /
                  resolutionTimes.length /
                  1000 /
                  60
                : 0;

        // MTTA (Mean Time To Acknowledge) in minutes
        const mtta =
            acknowledgeTimes.length > 0
                ? acknowledgeTimes.reduce((a, b) => a + b, 0) /
                  acknowledgeTimes.length /
                  1000 /
                  60
                : 0;

        return {
            total: relevantIncidents.length,
            bySeverity,
            mttr,
            mtta,
            affectedServicesCount,
        };
    }

    /**
     * Gets overdue post-mortems
     */
    getOverduePostMortems(): PostMortem[] {
        const now = new Date();
        return Array.from(this.postMortems.values()).filter(
            (pm) =>
                pm.status !== 'completed' &&
                pm.dueDate < now
        );
    }

    /**
     * Broadcasts update to all incident stakeholders
     */
    broadcastUpdate(
        incidentId: string,
        message: string,
        channels: ('slack' | 'email' | 'status_page')[]
    ): void {
        const incident = this.incidents.get(incidentId);
        if (!incident) return;

        for (const channel of channels) {
            this.emit(`broadcast:${channel}`, {
                incident,
                message,
            });
        }

        this.addTimelineEvent(incidentId, {
            type: 'communication',
            actor: 'system',
            description: `Broadcast sent to: ${channels.join(', ')}`,
            metadata: { message, channels },
        });
    }

    /**
     * Exports incident data for reporting
     */
    exportIncident(incidentId: string): {
        incident: Incident | undefined;
        timeline: IncidentTimeline | undefined;
        roles: IncidentRole[];
        relatedAlerts: string[];
        postMortem: PostMortem | undefined;
    } {
        return {
            incident: this.getIncident(incidentId),
            timeline: this.getTimeline(incidentId),
            roles: this.getRoles(incidentId),
            relatedAlerts: this.getRelatedAlerts(incidentId),
            postMortem: this.getPostMortem(incidentId),
        };
    }
}
