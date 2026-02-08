/**
 * @apexmail/ops - Status Page Service
 * 
 * Public status page for service health and incident communication.
 * 
 * FIX-500-155: All Maps backed by Postgres for production persistence.
 * L1 in-memory cache with write-through to DB on every mutation.
 */

import { Pool } from 'pg';
import crypto from 'node:crypto';
import {
    StatusPageData,
    StatusPageComponent,
    StatusPageGroup,
    StatusPageIncident,
    StatusPageUpdate,
    MaintenanceWindow,
    ComponentStatus,
    ServiceHealth,
} from '../types.js';
import { EventEmitter } from 'events';

export interface StatusPageConfig {
    publicUrl: string;
    companyName: string;
    supportUrl?: string;
    logo?: string;
    favicon?: string;
    timezone: string;
    allowSubscriptions: boolean;
}

interface Subscriber {
    id: string;
    email: string;
    components: string[]; // Empty = all components
    subscribedAt: Date;
    confirmed: boolean;
}

export class StatusPageService extends EventEmitter {
    private config: StatusPageConfig;
    private db: Pool | null;
    private components: Map<string, StatusPageComponent> = new Map();
    private groups: Map<string, StatusPageGroup> = new Map();
    private incidents: Map<string, StatusPageIncident> = new Map();
    private maintenance: Map<string, MaintenanceWindow> = new Map();
    private subscribers: Map<string, Subscriber> = new Map();
    private dbLoaded = false;

    constructor(config: StatusPageConfig, db?: Pool) {
        super();
        this.setMaxListeners(50); // FIX-500-332: Prevent maxListeners warning
        this.config = config;
        this.db = db ?? null;
        this.initializeDefaultComponents();
    }

    /**
     * FIX-500-155: Load state from DB into cache.
     */
    async loadFromDb(): Promise<void> {
        if (!this.db || this.dbLoaded) return;
        try {
            // Components
            const { rows: compRows } = await this.db.query('SELECT * FROM status_page_components ORDER BY sort_order');
            for (const r of compRows) {
                const comp: StatusPageComponent = { id: r.id, name: r.name, description: r.description, status: r.status, group: r.group_id, order: r.sort_order, visible: r.visible };
                this.components.set(comp.id, comp);
            }
            // Groups
            const { rows: grpRows } = await this.db.query('SELECT * FROM status_page_groups ORDER BY sort_order');
            for (const r of grpRows) {
                const grp: StatusPageGroup = { id: r.id, name: r.name, description: r.description, status: r.status, order: r.sort_order, components: [] };
                this.groups.set(grp.id, grp);
            }
            // Incidents
            const { rows: incRows } = await this.db.query('SELECT * FROM status_page_incidents ORDER BY created_at DESC');
            for (const r of incRows) {
                const { rows: updRows } = await this.db.query('SELECT * FROM status_page_incident_updates WHERE incident_id = $1 ORDER BY created_at', [r.id]);
                const updates: StatusPageUpdate[] = updRows.map((u: Record<string, unknown>) => ({ id: u.id as string, status: u.status as string, body: u.body as string, createdAt: new Date(u.created_at as string), author: u.author as string }));
                const inc: StatusPageIncident = { id: r.id, title: r.title, status: r.status, impact: r.impact, affectedComponents: r.affected_components || [], createdAt: new Date(r.created_at), updatedAt: new Date(r.updated_at), updates, resolvedAt: r.resolved_at ? new Date(r.resolved_at) : undefined };
                this.incidents.set(inc.id, inc);
            }
            // Maintenance
            const { rows: mntRows } = await this.db.query('SELECT * FROM status_page_maintenance ORDER BY scheduled_start');
            for (const r of mntRows) {
                const mnt: MaintenanceWindow = { id: r.id, title: r.title, description: r.description, scheduledStart: new Date(r.scheduled_start), scheduledEnd: new Date(r.scheduled_end), status: r.status, affectedComponents: r.affected_components || [], actualStart: r.actual_start ? new Date(r.actual_start) : undefined, actualEnd: r.actual_end ? new Date(r.actual_end) : undefined };
                this.maintenance.set(mnt.id, mnt);
            }
            // Subscribers
            const { rows: subRows } = await this.db.query('SELECT * FROM status_page_subscribers');
            for (const r of subRows) {
                this.subscribers.set(r.id, { id: r.id, email: r.email, components: r.components || [], subscribedAt: new Date(r.subscribed_at), confirmed: r.confirmed });
            }
            this.dbLoaded = true;
        } catch (err) {
            // Tables may not exist yet; defaults are fine
            this.dbLoaded = true;
        }
    }

    /**
     * Initializes default components
     */
    private initializeDefaultComponents(): void {
        // Web Application
        this.registerComponent({
            id: 'web-app',
            name: 'Web Application',
            description: 'Main web application interface',
            status: 'operational',
            group: 'core',
            order: 1,
            visible: true,
        });

        // API
        this.registerComponent({
            id: 'api',
            name: 'API',
            description: 'REST API for integrations',
            status: 'operational',
            group: 'core',
            order: 2,
            visible: true,
        });

        // Email Sending
        this.registerComponent({
            id: 'email-sending',
            name: 'Email Sending',
            description: 'Email delivery service',
            status: 'operational',
            group: 'email',
            order: 1,
            visible: true,
        });

        // Email Tracking
        this.registerComponent({
            id: 'email-tracking',
            name: 'Email Tracking',
            description: 'Opens, clicks, and engagement tracking',
            status: 'operational',
            group: 'email',
            order: 2,
            visible: true,
        });

        // Webhooks
        this.registerComponent({
            id: 'webhooks',
            name: 'Webhooks',
            description: 'Webhook delivery system',
            status: 'operational',
            group: 'integrations',
            order: 1,
            visible: true,
        });

        // Analytics
        this.registerComponent({
            id: 'analytics',
            name: 'Analytics',
            description: 'Reporting and analytics dashboard',
            status: 'operational',
            group: 'core',
            order: 3,
            visible: true,
        });

        // Register groups
        this.registerGroup({
            id: 'core',
            name: 'Core Services',
            description: 'Essential platform services',
            components: [],
            status: 'operational',
            order: 1,
        });

        this.registerGroup({
            id: 'email',
            name: 'Email Services',
            description: 'Email delivery and tracking',
            components: [],
            status: 'operational',
            order: 2,
        });

        this.registerGroup({
            id: 'integrations',
            name: 'Integrations',
            description: 'Third-party integrations',
            components: [],
            status: 'operational',
            order: 3,
        });
    }

    /**
     * Registers a component
     * FIX-500-155: Write-through to DB.
     */
    registerComponent(component: StatusPageComponent): void {
        this.components.set(component.id, component);
        if (this.db) {
            this.db.query(
                `INSERT INTO status_page_components (id, name, description, status, group_id, sort_order, visible)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
                   status = EXCLUDED.status, group_id = EXCLUDED.group_id, sort_order = EXCLUDED.sort_order,
                   visible = EXCLUDED.visible, updated_at = NOW()`,
                [component.id, component.name, component.description, component.status, component.group, component.order, component.visible]
            ).catch(() => { /* best-effort */ });
        }
        this.emit('component:registered', component);
    }

    /**
     * Registers a group
     * FIX-500-155: Write-through to DB.
     */
    registerGroup(group: StatusPageGroup): void {
        this.groups.set(group.id, group);
        if (this.db) {
            this.db.query(
                `INSERT INTO status_page_groups (id, name, description, status, sort_order)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
                   status = EXCLUDED.status, sort_order = EXCLUDED.sort_order`,
                [group.id, group.name, group.description, group.status, group.order]
            ).catch(() => { /* best-effort */ });
        }
        this.emit('group:registered', group);
    }

    /**
     * Updates component status
     * FIX-500-155: Write-through to DB.
     */
    updateComponentStatus(
        componentId: string,
        status: ComponentStatus,
        reason?: string
    ): void {
        const component = this.components.get(componentId);
        if (!component) return;

        const previousStatus = component.status;
        component.status = status;

        // FIX-500-155: Persist status change
        if (this.db) {
            this.db.query(
                'UPDATE status_page_components SET status = $1, updated_at = NOW() WHERE id = $2',
                [status, componentId]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('component:status:changed', {
            componentId,
            previousStatus,
            newStatus: status,
            reason,
        });

        // Update group status
        this.updateGroupStatuses();

        // Notify subscribers if degraded
        if (status !== 'operational' && previousStatus === 'operational') {
            this.notifySubscribers(componentId, 'degraded', reason);
        }
    }

    /**
     * Updates all group statuses based on component statuses
     */
    private updateGroupStatuses(): void {
        for (const [groupId, group] of this.groups) {
            const groupComponents = Array.from(this.components.values()).filter(
                (c) => c.group === groupId
            );

            if (groupComponents.length === 0) {
                group.status = 'operational';
                continue;
            }

            // Group status is the worst status of its components
            const statuses = groupComponents.map((c) => c.status);
            group.status = this.getWorstStatus(statuses);
        }
    }

    /**
     * Gets the worst status from an array
     */
    private getWorstStatus(statuses: ComponentStatus[]): ComponentStatus {
        const priority: ComponentStatus[] = [
            'major_outage',
            'partial_outage',
            'degraded',
            'maintenance',
            'operational',
        ];

        for (const status of priority) {
            if (statuses.includes(status)) {
                return status;
            }
        }

        return 'operational';
    }

    /**
     * Creates a new incident
     */
    createIncident(params: {
        title: string;
        impact: 'none' | 'minor' | 'major' | 'critical';
        affectedComponents: string[];
        message: string;
    }): StatusPageIncident {
        const incident: StatusPageIncident = {
            id: `incident-${crypto.randomUUID()}`,
            title: params.title,
            status: 'investigating',
            impact: params.impact,
            affectedComponents: params.affectedComponents,
            createdAt: new Date(),
            updatedAt: new Date(),
            updates: [
                {
                    id: `update-${Date.now()}`,
                    status: 'investigating',
                    body: params.message,
                    createdAt: new Date(),
                    author: 'system',
                },
            ],
        };

        this.incidents.set(incident.id, incident);

        // FIX-500-155: Persist incident + first update
        if (this.db) {
            this.db.query(
                `INSERT INTO status_page_incidents (id, title, status, impact, affected_components, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [incident.id, incident.title, incident.status, incident.impact, incident.affectedComponents, incident.createdAt, incident.updatedAt]
            ).catch(() => { /* best-effort */ });
            const firstUpdate = incident.updates[0];
            if (firstUpdate) {
                this.db.query(
                    `INSERT INTO status_page_incident_updates (id, incident_id, status, body, author, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)`,
                    [firstUpdate.id, incident.id, firstUpdate.status, firstUpdate.body, firstUpdate.author, firstUpdate.createdAt]
                ).catch(() => { /* best-effort */ });
            }
        }

        // Update affected component statuses
        for (const componentId of params.affectedComponents) {
            const status = this.impactToComponentStatus(params.impact);
            this.updateComponentStatus(componentId, status, params.title);
        }

        this.emit('incident:created', incident);
        this.notifySubscribersIncident(incident, 'created');

        return incident;
    }

    /**
     * Updates an incident
     */
    updateIncident(
        incidentId: string,
        params: {
            status?: 'investigating' | 'identified' | 'monitoring' | 'resolved';
            message: string;
            author?: string;
        }
    ): StatusPageIncident | null {
        const incident = this.incidents.get(incidentId);
        if (!incident) return null;

        if (params.status) {
            incident.status = params.status;
        }

        incident.updatedAt = new Date();

        if (params.status === 'resolved') {
            incident.resolvedAt = new Date();
            
            // Restore affected component statuses
            for (const componentId of incident.affectedComponents) {
                this.updateComponentStatus(componentId, 'operational');
            }
        }

        const update: StatusPageUpdate = {
            id: `update-${Date.now()}`,
            status: params.status || incident.status,
            body: params.message,
            createdAt: new Date(),
            author: params.author || 'system',
        };

        incident.updates.push(update);

        // FIX-500-155: Persist incident update
        if (this.db) {
            this.db.query(
                `UPDATE status_page_incidents SET status = $1, updated_at = $2, resolved_at = $3 WHERE id = $4`,
                [incident.status, incident.updatedAt, incident.resolvedAt ?? null, incident.id]
            ).catch(() => { /* best-effort */ });
            this.db.query(
                `INSERT INTO status_page_incident_updates (id, incident_id, status, body, author, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [update.id, incidentId, update.status, update.body, update.author, update.createdAt]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('incident:updated', { incident, update });
        this.notifySubscribersIncident(incident, 'updated');

        return incident;
    }

    /**
     * Converts impact level to component status
     */
    private impactToComponentStatus(impact: string): ComponentStatus {
        switch (impact) {
            case 'critical':
                return 'major_outage';
            case 'major':
                return 'partial_outage';
            case 'minor':
                return 'degraded';
            default:
                return 'operational';
        }
    }

    /**
     * Schedules maintenance
     */
    scheduleMaintenance(params: {
        title: string;
        description: string;
        scheduledStart: Date;
        scheduledEnd: Date;
        affectedComponents: string[];
    }): MaintenanceWindow {
        const maintenance: MaintenanceWindow = {
            id: `maint-${crypto.randomUUID()}`,
            title: params.title,
            description: params.description,
            scheduledStart: params.scheduledStart,
            scheduledEnd: params.scheduledEnd,
            status: 'scheduled',
            affectedComponents: params.affectedComponents,
        };

        this.maintenance.set(maintenance.id, maintenance);

        // FIX-500-155: Persist maintenance
        if (this.db) {
            this.db.query(
                `INSERT INTO status_page_maintenance (id, title, description, scheduled_start, scheduled_end, status, affected_components)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [maintenance.id, maintenance.title, maintenance.description, maintenance.scheduledStart, maintenance.scheduledEnd, maintenance.status, maintenance.affectedComponents]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('maintenance:scheduled', maintenance);
        this.notifySubscribersMaintenance(maintenance);

        return maintenance;
    }

    /**
     * Starts a scheduled maintenance
     * FIX-500-155: Write-through to DB.
     */
    startMaintenance(maintenanceId: string): void {
        const maintenance = this.maintenance.get(maintenanceId);
        if (!maintenance) return;

        maintenance.status = 'in_progress';
        maintenance.actualStart = new Date();

        if (this.db) {
            this.db.query(
                'UPDATE status_page_maintenance SET status = $1, actual_start = $2 WHERE id = $3',
                [maintenance.status, maintenance.actualStart, maintenanceId]
            ).catch(() => { /* best-effort */ });
        }

        // Update affected component statuses
        for (const componentId of maintenance.affectedComponents) {
            this.updateComponentStatus(componentId, 'maintenance', maintenance.title);
        }

        this.emit('maintenance:started', maintenance);
    }

    /**
     * Completes a maintenance window
     * FIX-500-155: Write-through to DB.
     */
    completeMaintenance(maintenanceId: string): void {
        const maintenance = this.maintenance.get(maintenanceId);
        if (!maintenance) return;

        maintenance.status = 'completed';
        maintenance.actualEnd = new Date();

        if (this.db) {
            this.db.query(
                'UPDATE status_page_maintenance SET status = $1, actual_end = $2 WHERE id = $3',
                [maintenance.status, maintenance.actualEnd, maintenanceId]
            ).catch(() => { /* best-effort */ });
        }

        // Restore component statuses
        for (const componentId of maintenance.affectedComponents) {
            this.updateComponentStatus(componentId, 'operational');
        }

        this.emit('maintenance:completed', maintenance);
    }

    /**
     * Cancels a scheduled maintenance
     * FIX-500-155: Write-through to DB.
     */
    cancelMaintenance(maintenanceId: string): void {
        const maintenance = this.maintenance.get(maintenanceId);
        if (!maintenance) return;

        maintenance.status = 'cancelled';

        if (this.db) {
            this.db.query(
                'UPDATE status_page_maintenance SET status = $1 WHERE id = $2',
                ['cancelled', maintenanceId]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('maintenance:cancelled', maintenance);
    }

    /**
     * Gets full status page data
     */
    getStatusPageData(): StatusPageData {
        const components = Array.from(this.components.values())
            .filter((c) => c.visible)
            .sort((a, b) => a.order - b.order);

        const groups = Array.from(this.groups.values())
            .map((group) => ({
                ...group,
                components: components.filter((c) => c.group === group.id),
            }))
            .sort((a, b) => a.order - b.order);

        const activeIncidents = Array.from(this.incidents.values())
            .filter((i) => i.status !== 'resolved')
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

        const scheduledMaintenance = Array.from(this.maintenance.values())
            .filter((m) => m.status === 'scheduled' || m.status === 'in_progress')
            .sort((a, b) => a.scheduledStart.getTime() - b.scheduledStart.getTime());

        const overallStatus = this.getWorstStatus(components.map((c) => c.status));

        const uptime = this.calculateUptime();

        return {
            overallStatus,
            components,
            groups,
            activeIncidents,
            scheduledMaintenance,
            uptime,
        };
    }

    /**
     * Calculates uptime percentages
     */
    private calculateUptime(): { daily: number; weekly: number; monthly: number } {
        // In a real implementation, this would query historical data
        // For now, return calculated estimates based on incidents
        const now = Date.now();
        const dayMs = 24 * 60 * 60 * 1000;

        const calculateForPeriod = (days: number): number => {
            const startTime = now - days * dayMs;
            const incidents = Array.from(this.incidents.values()).filter((i) => {
                const incidentStart = i.createdAt.getTime();
                const incidentEnd = i.resolvedAt?.getTime() || now;
                return incidentEnd > startTime && incidentStart < now;
            });

            let downtimeMs = 0;
            for (const incident of incidents) {
                if (incident.impact === 'major' || incident.impact === 'critical') {
                    const start = Math.max(incident.createdAt.getTime(), startTime);
                    const end = Math.min(incident.resolvedAt?.getTime() || now, now);
                    downtimeMs += end - start;
                }
            }

            const totalMs = days * dayMs;
            return Math.max(0, ((totalMs - downtimeMs) / totalMs) * 100);
        };

        return {
            daily: calculateForPeriod(1),
            weekly: calculateForPeriod(7),
            monthly: calculateForPeriod(30),
        };
    }

    /**
     * Adds a subscriber
     * FIX-500-155: Write-through to DB.
     */
    addSubscriber(email: string, components: string[] = []): string {
        const id = `sub-${crypto.randomUUID()}`;
        
        this.subscribers.set(id, {
            id,
            email,
            components,
            subscribedAt: new Date(),
            confirmed: false,
        });

        if (this.db) {
            this.db.query(
                'INSERT INTO status_page_subscribers (id, email, components, confirmed) VALUES ($1, $2, $3, false)',
                [id, email, components]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('subscriber:added', { id, email });
        return id;
    }

    /**
     * Confirms a subscriber
     * FIX-500-155: Write-through to DB.
     */
    confirmSubscriber(subscriberId: string): boolean {
        const subscriber = this.subscribers.get(subscriberId);
        if (!subscriber) return false;

        subscriber.confirmed = true;

        if (this.db) {
            this.db.query(
                'UPDATE status_page_subscribers SET confirmed = true WHERE id = $1',
                [subscriberId]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('subscriber:confirmed', subscriber);
        return true;
    }

    /**
     * Removes a subscriber
     * FIX-500-155: Write-through to DB.
     */
    removeSubscriber(subscriberId: string): void {
        this.subscribers.delete(subscriberId);

        if (this.db) {
            this.db.query(
                'DELETE FROM status_page_subscribers WHERE id = $1',
                [subscriberId]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('subscriber:removed', { subscriberId });
    }

    /**
     * Notifies subscribers of component status changes
     */
    private notifySubscribers(
        componentId: string,
        type: 'degraded' | 'restored',
        reason?: string
    ): void {
        const component = this.components.get(componentId);
        if (!component) return;

        const relevantSubscribers = Array.from(this.subscribers.values()).filter(
            (s) =>
                s.confirmed &&
                (s.components.length === 0 || s.components.includes(componentId))
        );

        for (const subscriber of relevantSubscribers) {
            this.emit('notification:send', {
                type: 'component_status',
                subscriber,
                data: {
                    component,
                    statusType: type,
                    reason,
                },
            });
        }
    }

    /**
     * Notifies subscribers of incident updates
     */
    private notifySubscribersIncident(
        incident: StatusPageIncident,
        type: 'created' | 'updated'
    ): void {
        const relevantSubscribers = Array.from(this.subscribers.values()).filter(
            (s) =>
                s.confirmed &&
                (s.components.length === 0 ||
                    incident.affectedComponents.some((c) => s.components.includes(c)))
        );

        for (const subscriber of relevantSubscribers) {
            this.emit('notification:send', {
                type: 'incident',
                subscriber,
                data: {
                    incident,
                    updateType: type,
                },
            });
        }
    }

    /**
     * Notifies subscribers of scheduled maintenance
     */
    private notifySubscribersMaintenance(maintenance: MaintenanceWindow): void {
        const relevantSubscribers = Array.from(this.subscribers.values()).filter(
            (s) =>
                s.confirmed &&
                (s.components.length === 0 ||
                    maintenance.affectedComponents.some((c) => s.components.includes(c)))
        );

        for (const subscriber of relevantSubscribers) {
            this.emit('notification:send', {
                type: 'maintenance',
                subscriber,
                data: { maintenance },
            });
        }
    }

    /**
     * Updates from service health checks
     */
    updateFromHealth(health: ServiceHealth): void {
        const componentMapping: Record<string, string> = {
            'api': 'api',
            'web': 'web-app',
            'email-sender': 'email-sending',
            'email-tracker': 'email-tracking',
            'webhook-service': 'webhooks',
            'analytics': 'analytics',
        };

        const componentId = componentMapping[health.service];
        if (!componentId) return;

        let status: ComponentStatus = 'operational';
        switch (health.status) {
            case 'degraded':
                status = 'degraded';
                break;
            case 'unhealthy':
                status = 'partial_outage';
                break;
        }

        const component = this.components.get(componentId);
        if (component && component.status !== status) {
            this.updateComponentStatus(componentId, status);
        }
    }

    /**
     * Gets incident history
     */
    getIncidentHistory(options: {
        limit?: number;
        offset?: number;
        includeResolved?: boolean;
    } = {}): StatusPageIncident[] {
        const { limit = 10, offset = 0, includeResolved = true } = options;

        let incidents = Array.from(this.incidents.values());

        if (!includeResolved) {
            incidents = incidents.filter((i) => i.status !== 'resolved');
        }

        return incidents
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
            .slice(offset, offset + limit);
    }

    /**
     * Gets maintenance history
     */
    getMaintenanceHistory(options: {
        limit?: number;
        offset?: number;
        status?: MaintenanceWindow['status'][];
    } = {}): MaintenanceWindow[] {
        const { limit = 10, offset = 0, status } = options;

        let windows = Array.from(this.maintenance.values());

        if (status) {
            windows = windows.filter((m) => status.includes(m.status));
        }

        return windows
            .sort((a, b) => b.scheduledStart.getTime() - a.scheduledStart.getTime())
            .slice(offset, offset + limit);
    }
}
