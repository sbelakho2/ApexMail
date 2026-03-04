import { Shield, Lock, Eye, Database, Network, Key } from '@/components/ui/icons';

export function SecurityIsolation() {
 const securityFeatures = [
 {
 icon: Network,
 title: 'Network Isolation',
 description:
 'Your ApexMail deployment runs in a completely isolated VPC with no shared network paths. Security groups and NACLs controlled by you.',
 details: ['No multi-tenant networking', 'Your firewall rules', 'VPC peering optional'],
 },
 {
 icon: Database,
 title: 'Data Sovereignty',
 description:
 'All data—emails, attachments, logs, and metadata—stays within your network boundary. No data ever leaves your jurisdiction.',
 details: ['Regional compliance', 'Your encryption keys', 'Your backup policies'],
 },
 {
 icon: Key,
 title: 'Key Management',
 description:
 'Bring your own KMS keys for encryption at rest. We never see your encryption keys or have access to decrypt your data.',
 details: ['AWS KMS / GCP KMS / Azure Key Vault', 'Customer-managed keys', 'Key rotation support'],
 },
 {
 icon: Lock,
 title: 'Access Control',
 description:
 'Your IAM policies, your access logs. ApexMail support requires your explicit approval through a PAM workflow.',
 details: ['Zero standing access', 'Break-glass procedures', 'Full audit trail'],
 },
 {
 icon: Eye,
 title: 'Audit Logging',
 description:
 'All administrative actions and data access logged to your SIEM. Immutable logs you control and retain.',
 details: ['CloudTrail / Audit Log integration', 'Splunk / Datadog export', 'Custom retention'],
 },
 {
 icon: Shield,
 title: 'Compliance Certifications',
 description:
 'Private cloud deployments can be included in your SOC 2, HIPAA, PCI-DSS, and FedRAMP audits.',
 details: ['Shared responsibility model', 'Compliance documentation', 'Auditor access'],
 },
 ];

 return (
 <section className="py-20 lg:py-32 relative bg-surface-50">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-16">
 <div className="animate-in inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-100/50 text-xs font-medium mb-6">
            <Shield className="w-4 h-4" />
            Security Isolation
          </div>
 <h2 className="animate-in delay-100 text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
 Your Perimeter. Your Rules.
 </motion.h2>
 <p className="animate-in delay-200 text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed">
 Private cloud means true isolation. No shared databases, no shared caches, 
 no shared anything. Your security team maintains full control.
 </p>
 </div>

 <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
 {securityFeatures.map((feature, index) => (
 <div key={feature.title} className="animate-in delay-100 bg-white rounded-lg border border-surface-200 p-8 shadow-sm hover:border-surface-300 transition-colors">
 <div className="w-10 h-10 rounded-lg bg-surface-50 flex items-center justify-center border border-surface-200 mb-6">
 <feature.icon className="w-5 h-5 text-surface-900" strokeWidth={1.5} />
 </div>
 <h3 className="text-lg font-semibold text-surface-900 mb-2">{feature.title}</h3>
 <p className="text-sm text-surface-600 leading-relaxed mb-6">{feature.description}</p>
 <div className="space-y-2.5">
 {feature.details.map((detail) => (
 <div key={detail} className="flex items-center gap-2.5 text-xs font-medium text-surface-600">
 <div className="w-1 h-1 rounded-full bg-surface-400" />
 {detail}
 </div>
 ))}
 </div>
 </div>
 ))}
 </div>

 {/* Security Comparison */}
 <div className="animate-in delay-500 mt-12 bg-white rounded-lg border border-surface-200 p-8 overflow-hidden shadow-sm">
 <h3 className="text-lg font-semibold text-surface-900 mb-8 text-center">
 Shared vs Private Cloud Security
 </h3>
 <div className="overflow-x-auto">
 <table className="w-full table-fixed text-xs sm:text-sm">
 <thead>
 <tr className="border-b border-surface-100">
 <th className="text-left py-3 px-2 sm:px-4 text-[11px] sm:text-xs font-medium text-surface-500">Security Aspect</th>
 <th className="text-center py-3 px-2 sm:px-4 text-[11px] sm:text-xs font-medium text-surface-500">Shared Cloud</th>
 <th className="text-center py-3 px-2 sm:px-4 text-[11px] sm:text-xs font-semibold text-surface-900 bg-surface-50/50 rounded-t-lg">Private Cloud</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-surface-100">
 {[
 ['Network Isolation', 'Logical (VLANs)', 'Physical (Your VPC)'],
 ['Encryption Keys', 'Provider-managed', 'Customer-managed'],
 ['Data Location', 'Multi-tenant regions', 'Your designated region'],
 ['Access Control', 'Provider IAM', 'Your IAM'],
 ['Audit Logs', 'Provider retention', 'Your retention'],
 ['Compliance Scope', 'Provider attestation', 'Your attestation'],
 ['Incident Response', 'Provider-led', 'Customer-led'],
 ].map(([aspect, shared, privateCloud]) => (
 <tr key={aspect} className="hover:bg-surface-50/50 transition-colors group">
 <td className="py-3 px-2 sm:px-4 text-surface-900 font-medium break-words">{aspect}</td>
 <td className="py-3 px-2 sm:px-4 text-center text-surface-500 break-words">{shared}</td>
 <td className="py-3 px-2 sm:px-4 text-center text-surface-900 font-medium bg-surface-50/30 group-hover:bg-surface-50/60 break-words">{privateCloud}</td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 </div>
 </div>
 </section>
 );
}
