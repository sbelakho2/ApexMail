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
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-12">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-50 text-red-700 border border-red-100 text-[10px] font-bold uppercase tracking-widest mb-4"
 >
 <Trash2 className="w-4 h-4" />
 Right to Be Forgotten
 </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight"
 >
 One Click. Complete Erasure.
 </motion.h2>
 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium"
 >
 GDPR Article 17 compliance made simple. Our cascade deletion propagates through 
 every system—primary, replicas, backups, and logs—within 72 hours.
 </motion.p>
 </div>

 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.3 }}
 className="premium-card p-8 max-w-4xl mx-auto bg-surface-50"
 >
 {/* Subject Request */}
 <div className="flex items-center justify-between mb-10 pb-8 border-b border-surface-200">
 <div>
 <div className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-1">Deletion Request</div>
 <div className="text-surface-900 font-mono font-bold text-lg">john.doe@example.com</div>
 </div>
 <button
 onClick={startDemo}
 disabled={isAnimating}
 className={cn(
 'px-6 py-3 rounded-xl font-bold uppercase tracking-widest text-xs transition-all ',
 isAnimating
 ? 'bg-surface-200 text-surface-400 cursor-not-allowed'
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
 'flex items-center gap-4 p-5 rounded-xl border transition-all ',
 status === 'active'
 ? 'bg-red-50 border-red-200 ring-1 ring-red-500'
 : status === 'complete'
 ? 'bg-green-50 border-green-200'
 : 'bg-white border-surface-200'
 )}
 >
 <div
 className={cn(
 'w-12 h-12 rounded-xl flex items-center justify-center border',
 status === 'active'
 ? 'bg-red-100 text-red-600 border-red-200'
 : status === 'complete'
 ? 'bg-green-100 text-green-600 border-green-200'
 : 'bg-surface-50 text-surface-400 border-surface-200'
 )}
 >
 {status === 'complete' ? (
 <CheckCircle2 className="w-6 h-6" strokeWidth={3} />
 ) : status === 'active' ? (
 <motion.div
 animate={{ rotate: 360 }}
 transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
 >
 <Trash2 className="w-6 h-6" />
 </motion.div>
 ) : (
 <Icon className="w-6 h-6" />
 )}
 </div>

 <div className="flex-1">
 <div className="text-surface-900 font-bold">{step.label}</div>
 <div className="flex flex-wrap gap-2 mt-2">
 {step.systems.map((system) => (
 <span
 key={system}
 className={cn(
 'text-[9px] px-2 py-0.5 rounded font-bold uppercase tracking-tight',
 status === 'complete'
 ? 'bg-green-100 text-green-700'
 : 'bg-surface-100 text-surface-500'
 )}
 >
 {system}
 </span>
 ))}
 </div>
 </div>

 <div
 className={cn(
 'text-[10px] font-bold uppercase tracking-widest',
 status === 'active'
 ? 'text-red-600 animate-pulse'
 : status === 'complete'
 ? 'text-green-600'
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
 className="mt-8 p-6 bg-green-50 border border-green-200 rounded-xl text-center "
 >
 <CheckCircle2 className="w-10 h-10 text-green-600 mx-auto mb-3" strokeWidth={3} />
 <div className="text-green-800 font-bold uppercase tracking-widest text-xs mb-1">Erasure Complete</div>
 <div className="text-sm text-green-700 font-medium">
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
 className="grid grid-cols-3 gap-8 max-w-3xl mx-auto mt-16 pt-12 border-t border-surface-100"
 >
 {[
 { value: '< 72h', label: 'Complete Erasure' },
 { value: '100%', label: 'System Coverage' },
 { value: 'Auto', label: 'Compliance Certificate' },
 ].map((stat) => (
 <div key={stat.label} className="text-center">
 <div className="text-2xl lg:text-4xl font-bold text-surface-900 tabular-nums mb-1">{stat.value}</div>
 <div className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">{stat.label}</div>
 </div>
 ))}
 </motion.div>
 </div>
 </section>
 );
}
