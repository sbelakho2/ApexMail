'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Trash2, Database, Server, Cloud, CheckCircle2 } from 'lucide-react';
import { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';

type DeletionStage = 'pending' | 'primary' | 'replicas' | 'backups' | 'logs' | 'complete';

interface DeletionStep {
 id: DeletionStage;
 label: string;
 icon: typeof Database;
 systems: string[];
}

const deletionSteps: DeletionStep[] = [
 { id: 'primary', label: 'Primary Database', icon: Database, systems: ['PostgreSQL Primary'] },
 { id: 'replicas', label: 'Read Replicas', icon: Server, systems: ['Replica US-East', 'Replica EU-West', 'Replica APAC'] },
 { id: 'backups', label: 'Backup Systems', icon: Cloud, systems: ['S3 Archives', 'Glacier Deep Archive'] },
 { id: 'logs', label: 'Log Aggregators', icon: Server, systems: ['Elasticsearch', 'CloudWatch', 'Datadog'] },
];

export function RightToBeForgotten() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
 const [currentStage, setCurrentStage] = useState<DeletionStage>('pending');
 const [isAnimating, setIsAnimating] = useState(false);

 const startDemo = () => {
 if (isAnimating) return;
 setIsAnimating(true);
 setCurrentStage('pending');

 const stages: DeletionStage[] = ['primary', 'replicas', 'backups', 'logs', 'complete'];
 let index = 0;

 const interval = setInterval(() => {
 if (index < stages.length) {
 setCurrentStage(stages[index]);
 index++;
 } else {
 clearInterval(interval);
 setTimeout(() => {
 setIsAnimating(false);
 setCurrentStage('pending');
 }, 3000);
 }
 }, 1500);
 };

 useEffect(() => {
 if (inView && !isAnimating) {
 const timeout = setTimeout(startDemo, 1000);
 return () => clearTimeout(timeout);
 }
 }, [inView]);

 const getStageStatus = (stepId: DeletionStage): 'pending' | 'active' | 'complete' => {
 const order: DeletionStage[] = ['pending', 'primary', 'replicas', 'backups', 'logs', 'complete'];
 const currentIndex = order.indexOf(currentStage);
 const stepIndex = order.indexOf(stepId);
 
 if (currentStage === 'complete' || stepIndex < currentIndex) return 'complete';
 if (stepIndex === currentIndex) return 'active';
 return 'pending';
 };

 return (
 <section ref={ref} className="py-24 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-16">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-50 text-red-700 border border-red-100 text-xs font-medium mb-6"
 >
 <Trash2 className="w-4 h-4" />
 Right to Be Forgotten
 </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight"
 >
 One Click. Complete Erasure.
 </motion.h2>
 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed"
 >
 GDPR Article 17 compliance made simple. Our cascade deletion propagates through 
 every system—primary, replicas, backups, and logs—within 72 hours.
 </motion.p>
 </div>

 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.3 }}
 className="bg-white border border-surface-200 rounded-2xl p-8 max-w-4xl mx-auto shadow-sm"
 >
 {/* Subject Request */}
 <div className="flex items-center justify-between mb-10 pb-8 border-b border-surface-200">
 <div>
 <div className="text-xs font-medium text-surface-500 mb-1">Deletion Request</div>
 <div className="text-surface-900 font-mono font-medium text-lg">john.doe@example.com</div>
 </div>
 <button
 onClick={startDemo}
 disabled={isAnimating}
 className={cn(
 'px-5 py-2.5 rounded-md font-semibold text-sm transition-all shadow-sm',
 isAnimating
 ? 'bg-surface-100 text-surface-400 cursor-not-allowed'
 : 'bg-red-600 text-white hover:bg-red-700'
 )}
 >
 {isAnimating ? 'Processing...' : 'Execute RTBF'}
 </button>
 </div>

 {/* Cascade Visualization */}
 <div className="space-y-4">
 {deletionSteps.map((step, index) => {
 const status = getStageStatus(step.id);
 const Icon = step.icon;

 return (
 <motion.div
 key={step.id}
 initial={{ opacity: 0, x: -20 }}
 animate={{ opacity: 1, x: 0 }}
 transition={{ delay: index * 0.1 }}
 className={cn(
 'flex items-center gap-4 p-4 rounded-lg border transition-all',
 status === 'active'
 ? 'bg-red-50/50 border-red-200'
 : status === 'complete'
 ? 'bg-emerald-50/50 border-emerald-200'
 : 'bg-white border-surface-200'
 )}
 >
 <div
 className={cn(
 'w-10 h-10 rounded-lg flex items-center justify-center border',
 status === 'active'
 ? 'bg-red-100 text-red-600 border-red-200'
 : status === 'complete'
 ? 'bg-emerald-100 text-emerald-600 border-emerald-200'
 : 'bg-surface-50 text-surface-400 border-surface-200'
 )}
 >
 {status === 'complete' ? (
 <CheckCircle2 className="w-5 h-5" strokeWidth={2} />
 ) : status === 'active' ? (
 <motion.div
 animate={{ rotate: 360 }}
 transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
 >
 <Trash2 className="w-5 h-5" strokeWidth={2} />
 </motion.div>
 ) : (
 <Icon className="w-5 h-5" strokeWidth={1.5} />
 )}
 </div>

 <div className="flex-1">
 <div className="text-surface-900 font-semibold text-sm">{step.label}</div>
 <div className="flex flex-wrap gap-2 mt-1.5">
 {step.systems.map((system) => (
 <span
 key={system}
 className={cn(
 'text-xs px-2 py-0.5 rounded font-medium',
 status === 'complete'
 ? 'bg-emerald-100/50 text-emerald-700'
 : 'bg-surface-100 text-surface-600'
 )}
 >
 {system}
 </span>
 ))}
 </div>
 </div>

 <div
 className={cn(
 'text-xs font-medium',
 status === 'active'
 ? 'text-red-600'
 : status === 'complete'
 ? 'text-emerald-600'
 : 'text-surface-400'
 )}
 >
 {status === 'active' ? 'Deleting...' : status === 'complete' ? 'Erased' : 'Pending'}
 </div>
 </motion.div>
 );
 })}
 </div>

 {/* Completion Message */}
 {currentStage === 'complete' && (
 <motion.div
 initial={{ opacity: 0, scale: 0.9 }}
 animate={{ opacity: 1, scale: 1 }}
 className="mt-8 p-6 bg-emerald-50 border border-emerald-200 rounded-lg text-center "
 >
 <CheckCircle2 className="w-10 h-10 text-emerald-600 mx-auto mb-3" strokeWidth={3} />
 <div className="text-emerald-800 font-bold text-xs mb-1">Erasure Complete</div>
 <div className="text-sm text-emerald-700 font-medium">
 Certificate of deletion generated and logged to immutable audit trail
 </div>
 </motion.div>
 )}
 </motion.div>

 {/* Stats */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.4 }}
 className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8 max-w-3xl mx-auto mt-16 pt-12 border-t border-surface-100"
 >
 {[
 { value: '< 72h', label: 'Complete Erasure' },
 { value: '100%', label: 'System Coverage' },
 { value: 'Auto', label: 'Compliance Certificate' },
 ].map((stat) => (
 <div key={stat.label} className="text-center">
 <div className="text-2xl lg:text-4xl font-bold text-surface-900 tabular-nums mb-1">{stat.value}</div>
 <div className="text-xs font-bold text-surface-600">{stat.label}</div>
 </div>
 ))}
 </motion.div>
 </div>
 </section>
 );
}
