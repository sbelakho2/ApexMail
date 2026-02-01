'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Trash2, Database, Server, Cloud, CheckCircle2 } from 'lucide-react';
import { useState, useEffect } from 'react';

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
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-sm mb-4"
          >
            <Trash2 className="w-4 h-4" />
            Right to Be Forgotten
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            One Click. Complete Erasure.
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
          >
            GDPR Article 17 compliance made simple. Our cascade deletion propagates through 
            every system—primary, replicas, backups, and logs—within 72 hours.
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
          className="glass-card p-8 max-w-4xl mx-auto"
        >
          {/* Subject Request */}
          <div className="flex items-center justify-between mb-8 pb-6 border-b border-surface-700">
            <div>
              <div className="text-sm text-surface-500 mb-1">Deletion Request</div>
              <div className="text-white font-mono">john.doe@example.com</div>
            </div>
            <button
              onClick={startDemo}
              disabled={isAnimating}
              className={`px-4 py-2 rounded-lg font-medium transition-all ${
                isAnimating
                  ? 'bg-surface-700 text-surface-500 cursor-not-allowed'
                  : 'bg-red-600 text-white hover:bg-red-500'
              }`}
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
                  className={`flex items-center gap-4 p-4 rounded-lg transition-all ${
                    status === 'active'
                      ? 'bg-red-500/10 border border-red-500/30'
                      : status === 'complete'
                      ? 'bg-green-500/10 border border-green-500/30'
                      : 'bg-surface-800/50 border border-surface-700'
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center ${
                      status === 'active'
                        ? 'bg-red-500/20 text-red-400'
                        : status === 'complete'
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-surface-700 text-surface-500'
                    }`}
                  >
                    {status === 'complete' ? (
                      <CheckCircle2 className="w-5 h-5" />
                    ) : status === 'active' ? (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                      >
                        <Trash2 className="w-5 h-5" />
                      </motion.div>
                    ) : (
                      <Icon className="w-5 h-5" />
                    )}
                  </div>

                  <div className="flex-1">
                    <div className="text-white font-medium">{step.label}</div>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {step.systems.map((system) => (
                        <span
                          key={system}
                          className={`text-xs px-2 py-0.5 rounded ${
                            status === 'complete'
                              ? 'bg-green-500/20 text-green-400'
                              : 'bg-surface-700 text-surface-400'
                          }`}
                        >
                          {system}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div
                    className={`text-sm font-medium ${
                      status === 'active'
                        ? 'text-red-400'
                        : status === 'complete'
                        ? 'text-green-400'
                        : 'text-surface-500'
                    }`}
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
              className="mt-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg text-center"
            >
              <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
              <div className="text-green-400 font-semibold">Erasure Complete</div>
              <div className="text-sm text-surface-400 mt-1">
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
          className="grid grid-cols-3 gap-6 max-w-2xl mx-auto mt-12"
        >
          {[
            { value: '< 72h', label: 'Complete Erasure' },
            { value: '100%', label: 'System Coverage' },
            { value: 'Auto', label: 'Compliance Certificate' },
          ].map((stat) => (
            <div key={stat.label} className="text-center">
              <div className="text-2xl lg:text-3xl font-bold text-white">{stat.value}</div>
              <div className="text-sm text-surface-400">{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
