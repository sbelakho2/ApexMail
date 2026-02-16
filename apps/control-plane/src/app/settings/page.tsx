'use client';

import { useState, useEffect, useRef } from 'react';
import { formatDate, cn } from '../../lib/utils';

/**
 * Platform Settings - Configure the SaaS platform
 * 
 * The owner can:
 * - Configure control plane access (IP whitelist, MFA)
 * - Manage integrations (calendar, CRM, payment)
 * - Set email sending limits and defaults
 * - Configure tenant defaults
 * - Manage backup and disaster recovery
 */

interface SettingsSection {
    id: string;
    title: string;
    description: string;
    icon: string;
}

const SETTINGS_SECTIONS: SettingsSection[] = [
    { id: 'access', title: 'Access Control', description: 'IP whitelist, MFA, session settings', icon: 'AC' },
    { id: 'integrations', title: 'Integrations', description: 'Calendar, CRM, payment providers', icon: 'IN' },
    { id: 'email', title: 'Email Configuration', description: 'Sending limits, domains, defaults', icon: 'EM' },
    { id: 'tenants', title: 'Tenant Defaults', description: 'Default plans, limits, features', icon: 'TN' },
    { id: 'ai', title: 'AI Assistant', description: 'Autonomous mode, escalation, proactive', icon: 'AI' },
    { id: 'compliance', title: 'Compliance Settings', description: 'Data retention, privacy, audit', icon: 'CP' },
    { id: 'backup', title: 'Backup & Recovery', description: 'Backup schedule, disaster recovery', icon: 'BK' },
];

export default function SettingsPage() {
    const [activeSection, setActiveSection] = useState('access');
    const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved'>('idle');

    // Access Control State
    const [ipWhitelist, setIpWhitelist] = useState(['10.0.0.0/8', '192.168.1.0/24', '203.0.113.50']);
    const [mfaRequired, setMfaRequired] = useState(true);
    const [sessionTimeout, setSessionTimeout] = useState(480);
    const [newIp, setNewIp] = useState('');

    // Integrations State
    const [integrations] = useState([
        { id: 'google-calendar', name: 'Google Calendar', status: 'connected', icon: 'GC' },
        { id: 'hubspot', name: 'HubSpot CRM', status: 'not_connected', icon: 'HB' },
        { id: 'stripe', name: 'Stripe Payments', status: 'connected', icon: 'ST' },
        { id: 'slack', name: 'Slack Notifications', status: 'connected', icon: 'SL' },
    ]);

    // Email Config State
    const [emailConfig, setEmailConfig] = useState({
        defaultDailyLimit: 10000,
        maxBounceRate: 5,
        warmupEnabled: true,
        warmupDays: 14,
        defaultFromName: 'ApexMail',
        replyToAddress: 'support@apexmail.ee',
    });

    // Tenant Defaults State
    const [tenantDefaults, setTenantDefaults] = useState({
        defaultPlan: 'pro',
        trialDays: 14,
        maxUsersDefault: 5,
        maxEmailsDefault: 50000,
        defaultFeatures: ['api_access', 'analytics', 'webhooks'],
    });

    // Compliance State
    const [complianceConfig, setComplianceConfig] = useState({
        dataRetentionDays: 365,
        auditLogRetentionDays: 730,
        gdprAutoDelete: true,
        hipaaMode: false,
        soc2Mode: true,
    });

    // Backup State
    const [backupConfig, setBackupConfig] = useState({
        backupFrequency: 'daily',
        backupRetentionDays: 30,
        drEnabled: true,
        drRegion: 'us-west-2',
        lastBackup: new Date(1737000000000 - 3600000).toISOString(),
    });

    // AI Assistant State
    const [aiConfig, setAiConfig] = useState({
        enabled: false,
        dryRun: true,
        confidenceThreshold: 0.7,
        maxAutoActionsPerSession: 10,
        maxAutonomousBillingAmount: 0,
        autonomousActionsPerHour: 50,
        sentimentEscalationThreshold: -0.5,
        proactiveOutreach: false,
        auditAllActions: true,
        allowedHoursStart: 0,
        allowedHoursEnd: 24,
        autoApproveActions: [
            'get_billing_status', 'get_billing_history', 'get_campaign_stats',
            'check_api_status', 'check_deliverability', 'get_sender_reputation',
            'get_bounce_report', 'account_health_check', 'verify_domain',
            'analyze_campaigns', 'export_data', 'export_report',
        ],
        alwaysEscalateActions: [
            'cancel_subscription', 'process_refund', 'delete_campaign',
            'delete_list', 'revoke_api_key', 'downgrade_plan',
            'send_campaign', 'import_contacts',
        ],
    });

    // Refs for timeout cleanup (Fix 38)
    const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Cleanup timeouts on unmount (Fix 38)
    useEffect(() => {
        return () => {
            if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
            if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
        };
    }, []);

    // Load saved settings from localStorage on mount (Fix 39)
    useEffect(() => {
        try {
            const saved = localStorage.getItem('control-plane-settings');
            if (saved) {
                const data = JSON.parse(saved);
                if (data.ipWhitelist) setIpWhitelist(data.ipWhitelist);
                if (data.mfaRequired !== undefined) setMfaRequired(data.mfaRequired);
                if (data.sessionTimeout) setSessionTimeout(data.sessionTimeout);
                if (data.emailConfig) setEmailConfig(prev => ({ ...prev, ...data.emailConfig }));
                if (data.tenantDefaults) setTenantDefaults(prev => ({ ...prev, ...data.tenantDefaults }));
                if (data.complianceConfig) setComplianceConfig(prev => ({ ...prev, ...data.complianceConfig }));
                if (data.backupConfig) setBackupConfig(prev => ({ ...prev, ...data.backupConfig }));
                if (data.aiConfig) setAiConfig(prev => ({ ...prev, ...data.aiConfig }));
            }
        } catch {
            // Ignore invalid localStorage data
        }
    }, []);

    function save() {
        setSaveStatus('saving');

        // Persist settings to localStorage (Fix 39)
        try {
            const settingsData = {
                ipWhitelist,
                mfaRequired,
                sessionTimeout,
                emailConfig,
                tenantDefaults,
                complianceConfig,
                backupConfig: { ...backupConfig, lastBackup: backupConfig.lastBackup },
                aiConfig,
            };
            localStorage.setItem('control-plane-settings', JSON.stringify(settingsData));
        } catch {
            // localStorage might be full or unavailable
        }

        // In production: POST to /api/settings endpoint
        // fetch('/api/autopilot/settings', { method: 'PUT', body: JSON.stringify(settingsData) })

        saveTimerRef.current = setTimeout(() => {
            setSaveStatus('saved');
            resetTimerRef.current = setTimeout(() => setSaveStatus('idle'), 2000);
        }, 1000);
    }

    function addIp() {
        if (newIp && !ipWhitelist.includes(newIp)) {
            setIpWhitelist([...ipWhitelist, newIp]);
            setNewIp('');
        }
    }

    function removeIp(ip: string) {
        setIpWhitelist(ipWhitelist.filter(i => i !== ip));
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Platform Settings</h1>
                    <p className="text-muted-foreground mt-1">
                        Configure your SaaS platform settings
                    </p>
                </div>
                <button
                    onClick={save}
                    disabled={saveStatus !== 'idle'}
                    className={cn(
                        'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        saveStatus === 'idle' && 'bg-primary text-primary-foreground hover:bg-primary/90',
                        saveStatus === 'saving' && 'bg-muted text-muted-foreground cursor-not-allowed',
                        saveStatus === 'saved' && 'bg-success text-success-foreground'
                    )}
                >
                    {saveStatus === 'idle' && 'Save Changes'}
                    {saveStatus === 'saving' && 'Saving...'}
                    {saveStatus === 'saved' && 'Saved'}
                </button>
            </div>

            <div className="flex flex-col lg:flex-row gap-6">
                {/* Sidebar Navigation - Horizontal scroll on mobile, vertical on desktop */}
                <div className="w-full lg:w-64 lg:flex-shrink-0">
                    <nav className="flex lg:flex-col gap-2 lg:gap-1 overflow-x-auto lg:overflow-x-visible pb-2 lg:pb-0 -mx-2.5 lg:mx-0 px-2.5 lg:px-0">
                        {SETTINGS_SECTIONS.map(section => (
                            <button
                                key={section.id}
                                onClick={() => setActiveSection(section.id)}
                                className={cn(
                                    'flex items-center gap-2 lg:gap-3 px-3 lg:px-4 py-2 lg:py-3 rounded-lg text-left transition-colors whitespace-nowrap lg:whitespace-normal flex-shrink-0 lg:flex-shrink lg:w-full',
                                    activeSection === section.id
                                        ? 'bg-primary/10 text-primary font-medium'
                                        : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                                )}
                            >
                                <span className="text-lg lg:text-xl">{section.icon}</span>
                                <div>
                                    <div className={cn("text-sm lg:text-base font-medium", activeSection !== section.id && "text-foreground")}>{section.title}</div>
                                    <div className="hidden lg:block text-xs text-muted-foreground">{section.description}</div>
                                </div>
                            </button>
                        ))}
                    </nav>
                </div>

                {/* Settings Content */}
                <div className="flex-1 bg-card rounded-xl border border-border p-6 shadow-sm">
                    {/* Access Control */}
                    {activeSection === 'access' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">Access Control</h2>
                            
                            {/* IP Whitelist */}
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">
                                    IP Whitelist
                                </label>
                                <p className="text-sm text-muted-foreground mb-3">
                                    Only allow access from these IP addresses or CIDR ranges
                                </p>
                                <div className="space-y-2 mb-3">
                                    {ipWhitelist.map(ip => (
                                        <div key={ip} className="flex items-center gap-2">
                                            <code className="flex-1 px-3 py-2 bg-muted/50 rounded-lg text-sm font-mono text-muted-foreground border border-border">
                                                {ip}
                                            </code>
                                            <button
                                                onClick={() => removeIp(ip)}
                                                className="px-3 py-2 text-destructive hover:bg-destructive/10 rounded-lg font-medium transition-colors"
                                            >
                                                Remove
                                            </button>
                                        </div>
                                    ))}
                                </div>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        value={newIp}
                                        onChange={(e) => setNewIp(e.target.value)}
                                        placeholder="10.0.0.0/8 or 192.168.1.1"
                                        className="flex-1 px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                    <button
                                        onClick={addIp}
                                        className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors"
                                    >
                                        Add IP
                                    </button>
                                </div>
                            </div>

                            {/* MFA */}
                            <div className="flex items-center justify-between py-4 border-t border-border">
                                <div>
                                    <div className="font-medium text-foreground">Require MFA</div>
                                    <div className="text-sm text-muted-foreground">
                                        All control plane users must use two-factor authentication
                                    </div>
                                </div>
                                <button
                                    onClick={() => setMfaRequired(!mfaRequired)}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        mfaRequired ? 'bg-primary' : 'bg-muted'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-background rounded-full shadow-sm transition-transform',
                                        mfaRequired ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>

                            {/* Session Timeout */}
                            <div className="py-4 border-t border-border">
                                <label className="block font-medium text-foreground mb-2">
                                    Session Timeout
                                </label>
                                <div className="flex items-center gap-2">
                                    <input
                                        type="number"
                                        value={sessionTimeout}
                                        onChange={(e) => setSessionTimeout(Number(e.target.value))}
                                        className="w-24 px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                    <span className="text-muted-foreground">minutes of inactivity</span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Integrations */}
                    {activeSection === 'integrations' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">Integrations</h2>
                            <div className="space-y-4">
                                {integrations.map(integration => (
                                    <div key={integration.id} className="flex items-center justify-between py-4 border-b border-border last:border-0">
                                        <div className="flex items-center gap-3">
                                            <span className="text-2xl">{integration.icon}</span>
                                            <div>
                                                <div className="font-medium text-foreground">{integration.name}</div>
                                                <div className={cn(
                                                    'text-sm',
                                                    integration.status === 'connected' ? 'text-success' : 'text-muted-foreground'
                                                )}>
                                                    {integration.status === 'connected' ? 'Connected' : 'Not connected'}
                                                </div>
                                            </div>
                                        </div>
                                        <button className={cn(
                                            'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                                            integration.status === 'connected'
                                                ? 'bg-muted text-foreground hover:bg-muted/80'
                                                : 'bg-primary text-primary-foreground hover:bg-primary/90'
                                        )}>
                                            {integration.status === 'connected' ? 'Configure' : 'Connect'}
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Email Configuration */}
                    {activeSection === 'email' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">Email Configuration</h2>
                            
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Default Daily Send Limit
                                    </label>
                                    <input
                                        type="number"
                                        value={emailConfig.defaultDailyLimit}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, defaultDailyLimit: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Max Bounce Rate (%)
                                    </label>
                                    <input
                                        type="number"
                                        value={emailConfig.maxBounceRate}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, maxBounceRate: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Default From Name
                                    </label>
                                    <input
                                        type="text"
                                        value={emailConfig.defaultFromName}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, defaultFromName: e.target.value })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Reply-To Address
                                    </label>
                                    <input
                                        type="email"
                                        value={emailConfig.replyToAddress}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, replyToAddress: e.target.value })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                            </div>

                            <div className="flex items-center justify-between py-4 border-t border-border">
                                <div>
                                    <div className="font-medium text-foreground">Domain Warmup</div>
                                    <div className="text-sm text-muted-foreground">
                                        Gradually increase sending volume for new domains
                                    </div>
                                </div>
                                <button
                                    onClick={() => setEmailConfig({ ...emailConfig, warmupEnabled: !emailConfig.warmupEnabled })}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        emailConfig.warmupEnabled ? 'bg-primary' : 'bg-muted'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-background rounded-full shadow-sm transition-transform',
                                        emailConfig.warmupEnabled ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Tenant Defaults */}
                    {activeSection === 'tenants' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">Tenant Defaults</h2>
                            
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Default Plan
                                    </label>
                                    <select
                                        value={tenantDefaults.defaultPlan}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, defaultPlan: e.target.value })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    >
                                        <option value="free">Free</option>
                                        <option value="starter">Starter</option>
                                        <option value="pro">Pro</option>
                                        <option value="enterprise">Enterprise</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Trial Days
                                    </label>
                                    <input
                                        type="number"
                                        value={tenantDefaults.trialDays}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, trialDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Default Max Users
                                    </label>
                                    <input
                                        type="number"
                                        value={tenantDefaults.maxUsersDefault}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, maxUsersDefault: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Default Max Emails/Month
                                    </label>
                                    <input
                                        type="number"
                                        value={tenantDefaults.maxEmailsDefault}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, maxEmailsDefault: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* AI Assistant */}
                    {activeSection === 'ai' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">AI Assistant</h2>
                            <p className="text-sm text-muted-foreground">
                                Configure autonomous mode to let the AI assistant handle routine customer requests without human intervention.
                                High-risk actions are always escalated to you.
                            </p>

                            {/* Main toggle */}
                            <div className="flex items-center justify-between py-4 border-t border-border">
                                <div>
                                    <div className="font-medium text-foreground">Enable Autonomous Mode</div>
                                    <div className="text-sm text-muted-foreground">
                                        Allow the assistant to auto-execute safe actions for customers
                                    </div>
                                </div>
                                <button
                                    onClick={() => setAiConfig({ ...aiConfig, enabled: !aiConfig.enabled })}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        aiConfig.enabled ? 'bg-primary' : 'bg-muted'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-background rounded-full shadow-sm transition-transform',
                                        aiConfig.enabled ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>

                            {aiConfig.enabled && (
                                <>
                                    {/* Safety toggles */}
                                    <div className="space-y-4 border-t border-border pt-4">
                                        <h3 className="text-sm font-semibold text-foreground">Safety Controls</h3>
                                        {[
                                            { key: 'dryRun', label: 'Dry Run Mode', desc: 'Log decisions without executing — test autonomous mode safely' },
                                            { key: 'auditAllActions', label: 'Audit All Actions', desc: 'Log every autonomous decision for review in the audit log' },
                                            { key: 'proactiveOutreach', label: 'Proactive Outreach', desc: 'Let the assistant proactively message customers about issues' },
                                        ].map(item => (
                                            <div key={item.key} className="flex items-center justify-between py-2">
                                                <div>
                                                    <div className="font-medium text-foreground">{item.label}</div>
                                                    <div className="text-sm text-muted-foreground">{item.desc}</div>
                                                </div>
                                                <button
                                                    onClick={() => setAiConfig({
                                                        ...aiConfig,
                                                        [item.key]: !aiConfig[item.key as keyof typeof aiConfig]
                                                    })}
                                                    className={cn(
                                                        'relative w-14 h-7 rounded-full transition-colors',
                                                        aiConfig[item.key as keyof typeof aiConfig] ? 'bg-primary' : 'bg-muted'
                                                    )}
                                                >
                                                    <div className={cn(
                                                        'absolute top-1 w-5 h-5 bg-background rounded-full shadow-sm transition-transform',
                                                        aiConfig[item.key as keyof typeof aiConfig] ? 'left-8' : 'left-1'
                                                    )} />
                                                </button>
                                            </div>
                                        ))}
                                    </div>

                                    {/* Thresholds */}
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-border pt-4">
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Confidence Threshold
                                            </label>
                                            <p className="text-xs text-muted-foreground mb-1">
                                                Minimum confidence to auto-approve ({(aiConfig.confidenceThreshold * 100).toFixed(0)}%)
                                            </p>
                                            <input
                                                type="range"
                                                min="0.5"
                                                max="0.99"
                                                step="0.01"
                                                value={aiConfig.confidenceThreshold}
                                                onChange={(e) => setAiConfig({ ...aiConfig, confidenceThreshold: Number(e.target.value) })}
                                                className="w-full"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Sentiment Escalation
                                            </label>
                                            <p className="text-xs text-muted-foreground mb-1">
                                                Escalate when sentiment drops below ({aiConfig.sentimentEscalationThreshold.toFixed(1)})
                                            </p>
                                            <input
                                                type="range"
                                                min="-1"
                                                max="0"
                                                step="0.1"
                                                value={aiConfig.sentimentEscalationThreshold}
                                                onChange={(e) => setAiConfig({ ...aiConfig, sentimentEscalationThreshold: Number(e.target.value) })}
                                                className="w-full"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Max Auto Actions / Session
                                            </label>
                                            <input
                                                type="number"
                                                value={aiConfig.maxAutoActionsPerSession}
                                                onChange={(e) => setAiConfig({ ...aiConfig, maxAutoActionsPerSession: Number(e.target.value) })}
                                                className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Max Actions / Hour
                                            </label>
                                            <input
                                                type="number"
                                                value={aiConfig.autonomousActionsPerHour}
                                                onChange={(e) => setAiConfig({ ...aiConfig, autonomousActionsPerHour: Number(e.target.value) })}
                                                className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Max Billing Amount ($)
                                            </label>
                                            <input
                                                type="number"
                                                value={aiConfig.maxAutonomousBillingAmount}
                                                onChange={(e) => setAiConfig({ ...aiConfig, maxAutonomousBillingAmount: Number(e.target.value) })}
                                                className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Allowed Hours (UTC)
                                            </label>
                                            <div className="flex items-center gap-2">
                                                <input
                                                    type="number"
                                                    min="0"
                                                    max="23"
                                                    value={aiConfig.allowedHoursStart}
                                                    onChange={(e) => setAiConfig({ ...aiConfig, allowedHoursStart: Number(e.target.value) })}
                                                    className="w-20 px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                                />
                                                <span className="text-muted-foreground">to</span>
                                                <input
                                                    type="number"
                                                    min="0"
                                                    max="24"
                                                    value={aiConfig.allowedHoursEnd}
                                                    onChange={(e) => setAiConfig({ ...aiConfig, allowedHoursEnd: Number(e.target.value) })}
                                                    className="w-20 px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    {/* Auto-approve actions */}
                                    <div className="border-t border-border pt-4">
                                        <h3 className="text-sm font-semibold text-foreground mb-2">Auto-Approve Actions</h3>
                                        <p className="text-xs text-muted-foreground mb-3">
                                            These safe, read-only actions are executed without human confirmation
                                        </p>
                                        <div className="flex flex-wrap gap-2">
                                            {aiConfig.autoApproveActions.map(action => (
                                                <span key={action} className="px-2 py-1 bg-success/10 text-success text-xs rounded-full font-mono">
                                                    {action}
                                                </span>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Always-escalate actions */}
                                    <div className="border-t border-border pt-4">
                                        <h3 className="text-sm font-semibold text-foreground mb-2">Always Escalate Actions</h3>
                                        <p className="text-xs text-muted-foreground mb-3">
                                            These high-risk actions always require human approval
                                        </p>
                                        <div className="flex flex-wrap gap-2">
                                            {aiConfig.alwaysEscalateActions.map(action => (
                                                <span key={action} className="px-2 py-1 bg-destructive/10 text-destructive text-xs rounded-full font-mono">
                                                    Escalate: {action}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {/* Compliance */}
                    {activeSection === 'compliance' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">Compliance Settings</h2>
                            
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Data Retention (days)
                                    </label>
                                    <input
                                        type="number"
                                        value={complianceConfig.dataRetentionDays}
                                        onChange={(e) => setComplianceConfig({ ...complianceConfig, dataRetentionDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Audit Log Retention (days)
                                    </label>
                                    <input
                                        type="number"
                                        value={complianceConfig.auditLogRetentionDays}
                                        onChange={(e) => setComplianceConfig({ ...complianceConfig, auditLogRetentionDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                            </div>

                            <div className="space-y-4 pt-4 border-t border-border">
                                {[
                                    { key: 'gdprAutoDelete', label: 'GDPR Auto-Delete', desc: 'Automatically delete data upon GDPR request completion' },
                                    { key: 'hipaaMode', label: 'HIPAA Mode', desc: 'Enable HIPAA-compliant data handling' },
                                    { key: 'soc2Mode', label: 'SOC 2 Mode', desc: 'Enable SOC 2 audit logging and controls' },
                                ].map(item => (
                                    <div key={item.key} className="flex items-center justify-between py-2">
                                        <div>
                                            <div className="font-medium text-foreground">{item.label}</div>
                                            <div className="text-sm text-muted-foreground">{item.desc}</div>
                                        </div>
                                        <button
                                            onClick={() => setComplianceConfig({
                                                ...complianceConfig,
                                                [item.key]: !complianceConfig[item.key as keyof typeof complianceConfig]
                                            })}
                                            className={cn(
                                                'relative w-14 h-7 rounded-full transition-colors',
                                                complianceConfig[item.key as keyof typeof complianceConfig] ? 'bg-primary' : 'bg-muted'
                                            )}
                                        >
                                            <div className={cn(
                                                'absolute top-1 w-5 h-5 bg-background rounded-full shadow-sm transition-transform',
                                                complianceConfig[item.key as keyof typeof complianceConfig] ? 'left-8' : 'left-1'
                                            )} />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Backup & Recovery */}
                    {activeSection === 'backup' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-bold text-foreground">Backup & Recovery</h2>
                            
                            <div className="bg-success/10 border border-success/20 rounded-lg p-4 mb-6">
                                <div className="flex items-center gap-2 text-success">
                                    <span>OK</span>
                                    <span className="font-medium">Last backup: {formatDate(backupConfig.lastBackup)}</span>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Backup Frequency
                                    </label>
                                    <select
                                        value={backupConfig.backupFrequency}
                                        onChange={(e) => setBackupConfig({ ...backupConfig, backupFrequency: e.target.value })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    >
                                        <option value="hourly">Hourly</option>
                                        <option value="daily">Daily</option>
                                        <option value="weekly">Weekly</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        Retention (days)
                                    </label>
                                    <input
                                        type="number"
                                        value={backupConfig.backupRetentionDays}
                                        onChange={(e) => setBackupConfig({ ...backupConfig, backupRetentionDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    />
                                </div>
                            </div>

                            <div className="flex items-center justify-between py-4 border-t border-border">
                                <div>
                                    <div className="font-medium text-foreground">Disaster Recovery</div>
                                    <div className="text-sm text-muted-foreground">
                                        Enable cross-region replication for disaster recovery
                                    </div>
                                </div>
                                <button
                                    onClick={() => setBackupConfig({ ...backupConfig, drEnabled: !backupConfig.drEnabled })}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        backupConfig.drEnabled ? 'bg-primary' : 'bg-muted'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-background rounded-full shadow-sm transition-transform',
                                        backupConfig.drEnabled ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>

                            {backupConfig.drEnabled && (
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-2">
                                        DR Region
                                    </label>
                                    <select
                                        value={backupConfig.drRegion}
                                        onChange={(e) => setBackupConfig({ ...backupConfig, drRegion: e.target.value })}
                                        className="w-full px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
                                    >
                                        <option value="us-east-1">US East (N. Virginia)</option>
                                        <option value="us-west-2">US West (Oregon)</option>
                                        <option value="eu-west-1">EU (Ireland)</option>
                                        <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                                    </select>
                                </div>
                            )}

                            <div className="flex gap-2 pt-4 border-t border-border">
                                <button className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors">
                                    Run Backup Now
                                </button>
                                <button className="px-4 py-2 bg-muted text-foreground rounded-lg text-sm hover:bg-muted/80 font-medium transition-colors">
                                    View Backup History
                                </button>
                                <button className="px-4 py-2 bg-warning/10 text-warning rounded-lg text-sm hover:bg-warning/20 font-medium transition-colors">
                                    Test DR Failover
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
