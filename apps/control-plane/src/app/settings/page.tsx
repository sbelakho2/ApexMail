'use client';

import { useState } from 'react';
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
    { id: 'access', title: 'Access Control', description: 'IP whitelist, MFA, session settings', icon: '🔐' },
    { id: 'integrations', title: 'Integrations', description: 'Calendar, CRM, payment providers', icon: '🔗' },
    { id: 'email', title: 'Email Configuration', description: 'Sending limits, domains, defaults', icon: '📧' },
    { id: 'tenants', title: 'Tenant Defaults', description: 'Default plans, limits, features', icon: '👥' },
    { id: 'compliance', title: 'Compliance Settings', description: 'Data retention, privacy, audit', icon: '⚖️' },
    { id: 'backup', title: 'Backup & Recovery', description: 'Backup schedule, disaster recovery', icon: '💾' },
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
        { id: 'google-calendar', name: 'Google Calendar', status: 'connected', icon: '📅' },
        { id: 'hubspot', name: 'HubSpot CRM', status: 'not_connected', icon: '🏢' },
        { id: 'stripe', name: 'Stripe Payments', status: 'connected', icon: '💳' },
        { id: 'slack', name: 'Slack Notifications', status: 'connected', icon: '💬' },
    ]);

    // Email Config State
    const [emailConfig, setEmailConfig] = useState({
        defaultDailyLimit: 10000,
        maxBounceRate: 5,
        warmupEnabled: true,
        warmupDays: 14,
        defaultFromName: 'ApexMail',
        replyToAddress: 'support@apexmail.io',
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
        lastBackup: new Date(Date.now() - 3600000).toISOString(),
    });

    function save() {
        setSaveStatus('saving');
        setTimeout(() => {
            setSaveStatus('saved');
            setTimeout(() => setSaveStatus('idle'), 2000);
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
                    <h1 className="text-2xl font-bold text-gray-900">Platform Settings</h1>
                    <p className="text-gray-600 mt-1">
                        Configure your SaaS platform settings
                    </p>
                </div>
                <button
                    onClick={save}
                    disabled={saveStatus !== 'idle'}
                    className={cn(
                        'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        saveStatus === 'idle' && 'bg-indigo-600 text-white hover:bg-indigo-700',
                        saveStatus === 'saving' && 'bg-gray-400 text-white cursor-not-allowed',
                        saveStatus === 'saved' && 'bg-green-600 text-white'
                    )}
                >
                    {saveStatus === 'idle' && '💾 Save Changes'}
                    {saveStatus === 'saving' && 'Saving...'}
                    {saveStatus === 'saved' && '✓ Saved!'}
                </button>
            </div>

            <div className="flex gap-6">
                {/* Sidebar Navigation */}
                <div className="w-64 flex-shrink-0">
                    <nav className="space-y-1">
                        {SETTINGS_SECTIONS.map(section => (
                            <button
                                key={section.id}
                                onClick={() => setActiveSection(section.id)}
                                className={cn(
                                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-colors',
                                    activeSection === section.id
                                        ? 'bg-indigo-50 text-indigo-700'
                                        : 'text-gray-600 hover:bg-gray-50'
                                )}
                            >
                                <span className="text-xl">{section.icon}</span>
                                <div>
                                    <div className="font-medium">{section.title}</div>
                                    <div className="text-xs text-gray-500">{section.description}</div>
                                </div>
                            </button>
                        ))}
                    </nav>
                </div>

                {/* Settings Content */}
                <div className="flex-1 bg-white rounded-xl border border-gray-200 p-6">
                    {/* Access Control */}
                    {activeSection === 'access' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-semibold text-gray-900">Access Control</h2>
                            
                            {/* IP Whitelist */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    IP Whitelist
                                </label>
                                <p className="text-sm text-gray-500 mb-3">
                                    Only allow access from these IP addresses or CIDR ranges
                                </p>
                                <div className="space-y-2 mb-3">
                                    {ipWhitelist.map(ip => (
                                        <div key={ip} className="flex items-center gap-2">
                                            <code className="flex-1 px-3 py-2 bg-gray-50 rounded-lg text-sm font-mono">
                                                {ip}
                                            </code>
                                            <button
                                                onClick={() => removeIp(ip)}
                                                className="px-3 py-2 text-red-600 hover:bg-red-50 rounded-lg"
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
                                        className="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                    <button
                                        onClick={addIp}
                                        className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700"
                                    >
                                        Add IP
                                    </button>
                                </div>
                            </div>

                            {/* MFA */}
                            <div className="flex items-center justify-between py-4 border-t border-gray-100">
                                <div>
                                    <div className="font-medium text-gray-900">Require MFA</div>
                                    <div className="text-sm text-gray-500">
                                        All control plane users must use two-factor authentication
                                    </div>
                                </div>
                                <button
                                    onClick={() => setMfaRequired(!mfaRequired)}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        mfaRequired ? 'bg-indigo-600' : 'bg-gray-300'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-white rounded-full transition-transform',
                                        mfaRequired ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>

                            {/* Session Timeout */}
                            <div className="py-4 border-t border-gray-100">
                                <label className="block font-medium text-gray-900 mb-2">
                                    Session Timeout
                                </label>
                                <div className="flex items-center gap-2">
                                    <input
                                        type="number"
                                        value={sessionTimeout}
                                        onChange={(e) => setSessionTimeout(Number(e.target.value))}
                                        className="w-24 px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                    <span className="text-gray-500">minutes of inactivity</span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Integrations */}
                    {activeSection === 'integrations' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-semibold text-gray-900">Integrations</h2>
                            <div className="space-y-4">
                                {integrations.map(integration => (
                                    <div key={integration.id} className="flex items-center justify-between py-4 border-b border-gray-100">
                                        <div className="flex items-center gap-3">
                                            <span className="text-2xl">{integration.icon}</span>
                                            <div>
                                                <div className="font-medium text-gray-900">{integration.name}</div>
                                                <div className={cn(
                                                    'text-sm',
                                                    integration.status === 'connected' ? 'text-green-600' : 'text-gray-400'
                                                )}>
                                                    {integration.status === 'connected' ? '✓ Connected' : 'Not connected'}
                                                </div>
                                            </div>
                                        </div>
                                        <button className={cn(
                                            'px-4 py-2 rounded-lg text-sm font-medium',
                                            integration.status === 'connected'
                                                ? 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                                                : 'bg-indigo-600 text-white hover:bg-indigo-700'
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
                            <h2 className="text-lg font-semibold text-gray-900">Email Configuration</h2>
                            
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Default Daily Send Limit
                                    </label>
                                    <input
                                        type="number"
                                        value={emailConfig.defaultDailyLimit}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, defaultDailyLimit: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Max Bounce Rate (%)
                                    </label>
                                    <input
                                        type="number"
                                        value={emailConfig.maxBounceRate}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, maxBounceRate: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Default From Name
                                    </label>
                                    <input
                                        type="text"
                                        value={emailConfig.defaultFromName}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, defaultFromName: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Reply-To Address
                                    </label>
                                    <input
                                        type="email"
                                        value={emailConfig.replyToAddress}
                                        onChange={(e) => setEmailConfig({ ...emailConfig, replyToAddress: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                            </div>

                            <div className="flex items-center justify-between py-4 border-t border-gray-100">
                                <div>
                                    <div className="font-medium text-gray-900">Domain Warmup</div>
                                    <div className="text-sm text-gray-500">
                                        Gradually increase sending volume for new domains
                                    </div>
                                </div>
                                <button
                                    onClick={() => setEmailConfig({ ...emailConfig, warmupEnabled: !emailConfig.warmupEnabled })}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        emailConfig.warmupEnabled ? 'bg-indigo-600' : 'bg-gray-300'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-white rounded-full transition-transform',
                                        emailConfig.warmupEnabled ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Tenant Defaults */}
                    {activeSection === 'tenants' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-semibold text-gray-900">Tenant Defaults</h2>
                            
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Default Plan
                                    </label>
                                    <select
                                        value={tenantDefaults.defaultPlan}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, defaultPlan: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    >
                                        <option value="free">Free</option>
                                        <option value="starter">Starter</option>
                                        <option value="pro">Pro</option>
                                        <option value="enterprise">Enterprise</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Trial Days
                                    </label>
                                    <input
                                        type="number"
                                        value={tenantDefaults.trialDays}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, trialDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Default Max Users
                                    </label>
                                    <input
                                        type="number"
                                        value={tenantDefaults.maxUsersDefault}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, maxUsersDefault: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Default Max Emails/Month
                                    </label>
                                    <input
                                        type="number"
                                        value={tenantDefaults.maxEmailsDefault}
                                        onChange={(e) => setTenantDefaults({ ...tenantDefaults, maxEmailsDefault: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Compliance */}
                    {activeSection === 'compliance' && (
                        <div className="space-y-6">
                            <h2 className="text-lg font-semibold text-gray-900">Compliance Settings</h2>
                            
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Data Retention (days)
                                    </label>
                                    <input
                                        type="number"
                                        value={complianceConfig.dataRetentionDays}
                                        onChange={(e) => setComplianceConfig({ ...complianceConfig, dataRetentionDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Audit Log Retention (days)
                                    </label>
                                    <input
                                        type="number"
                                        value={complianceConfig.auditLogRetentionDays}
                                        onChange={(e) => setComplianceConfig({ ...complianceConfig, auditLogRetentionDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                            </div>

                            <div className="space-y-4 pt-4 border-t border-gray-100">
                                {[
                                    { key: 'gdprAutoDelete', label: 'GDPR Auto-Delete', desc: 'Automatically delete data upon GDPR request completion' },
                                    { key: 'hipaaMode', label: 'HIPAA Mode', desc: 'Enable HIPAA-compliant data handling' },
                                    { key: 'soc2Mode', label: 'SOC 2 Mode', desc: 'Enable SOC 2 audit logging and controls' },
                                ].map(item => (
                                    <div key={item.key} className="flex items-center justify-between py-2">
                                        <div>
                                            <div className="font-medium text-gray-900">{item.label}</div>
                                            <div className="text-sm text-gray-500">{item.desc}</div>
                                        </div>
                                        <button
                                            onClick={() => setComplianceConfig({
                                                ...complianceConfig,
                                                [item.key]: !complianceConfig[item.key as keyof typeof complianceConfig]
                                            })}
                                            className={cn(
                                                'relative w-14 h-7 rounded-full transition-colors',
                                                complianceConfig[item.key as keyof typeof complianceConfig] ? 'bg-indigo-600' : 'bg-gray-300'
                                            )}
                                        >
                                            <div className={cn(
                                                'absolute top-1 w-5 h-5 bg-white rounded-full transition-transform',
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
                            <h2 className="text-lg font-semibold text-gray-900">Backup & Recovery</h2>
                            
                            <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
                                <div className="flex items-center gap-2 text-green-700">
                                    <span>✓</span>
                                    <span className="font-medium">Last backup: {formatDate(backupConfig.lastBackup)}</span>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Backup Frequency
                                    </label>
                                    <select
                                        value={backupConfig.backupFrequency}
                                        onChange={(e) => setBackupConfig({ ...backupConfig, backupFrequency: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    >
                                        <option value="hourly">Hourly</option>
                                        <option value="daily">Daily</option>
                                        <option value="weekly">Weekly</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Retention (days)
                                    </label>
                                    <input
                                        type="number"
                                        value={backupConfig.backupRetentionDays}
                                        onChange={(e) => setBackupConfig({ ...backupConfig, backupRetentionDays: Number(e.target.value) })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    />
                                </div>
                            </div>

                            <div className="flex items-center justify-between py-4 border-t border-gray-100">
                                <div>
                                    <div className="font-medium text-gray-900">Disaster Recovery</div>
                                    <div className="text-sm text-gray-500">
                                        Enable cross-region replication for disaster recovery
                                    </div>
                                </div>
                                <button
                                    onClick={() => setBackupConfig({ ...backupConfig, drEnabled: !backupConfig.drEnabled })}
                                    className={cn(
                                        'relative w-14 h-7 rounded-full transition-colors',
                                        backupConfig.drEnabled ? 'bg-indigo-600' : 'bg-gray-300'
                                    )}
                                >
                                    <div className={cn(
                                        'absolute top-1 w-5 h-5 bg-white rounded-full transition-transform',
                                        backupConfig.drEnabled ? 'left-8' : 'left-1'
                                    )} />
                                </button>
                            </div>

                            {backupConfig.drEnabled && (
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        DR Region
                                    </label>
                                    <select
                                        value={backupConfig.drRegion}
                                        onChange={(e) => setBackupConfig({ ...backupConfig, drRegion: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                    >
                                        <option value="us-east-1">US East (N. Virginia)</option>
                                        <option value="us-west-2">US West (Oregon)</option>
                                        <option value="eu-west-1">EU (Ireland)</option>
                                        <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                                    </select>
                                </div>
                            )}

                            <div className="flex gap-2 pt-4 border-t border-gray-100">
                                <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700">
                                    🔄 Run Backup Now
                                </button>
                                <button className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm hover:bg-gray-200">
                                    📋 View Backup History
                                </button>
                                <button className="px-4 py-2 bg-orange-100 text-orange-700 rounded-lg text-sm hover:bg-orange-200">
                                    ⚠️ Test DR Failover
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
