'use client';

import { useEffect, useState } from 'react';

type ComponentStatus = 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'under_maintenance';

interface StatusComponent {
  id: string;
  name: string;
  status: ComponentStatus;
}

const statusLabel: Record<ComponentStatus, string> = {
  operational: 'Operational',
  degraded: 'Degraded',
  partial_outage: 'Partial Outage',
  major_outage: 'Major Outage',
  under_maintenance: 'Maintenance',
};

const statusColor: Record<ComponentStatus, string> = {
  operational: 'text-success-600 bg-success-600/10 border-success-600/20',
  degraded: 'text-warning-600 bg-warning-600/10 border-warning-600/20',
  partial_outage: 'text-warning-600 bg-warning-600/10 border-warning-600/20',
  major_outage: 'text-danger-600 bg-danger-600/10 border-danger-600/20',
  under_maintenance: 'text-info-600 bg-info-600/10 border-info-600/20',
};

export function StatusOverview() {
  const [components, setComponents] = useState<StatusComponent[]>([]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const response = await fetch('https://status.apexmail.ee/api/v2/summary.json', { cache: 'no-store' });
        if (!response.ok) throw new Error('Failed to load status summary');

        const data = (await response.json()) as { components?: StatusComponent[] };
        if (cancelled) return;
        setComponents(data.components ?? []);
      } catch {
        if (cancelled) return;
        setComponents([]);
      }
    };

    load();
    const interval = setInterval(load, 60000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <section className="py-12 bg-surface-50 border-b border-surface-200">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-xl font-semibold text-surface-900 mb-6">Component Status</h2>
        {components.length === 0 ? (
          <p className="text-surface-500 text-sm">Live component details are temporarily unavailable.</p>
        ) : (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {components.map((component) => (
              <div key={component.id} className="rounded-lg border border-surface-200 bg-surface-50 p-4">
                <div className="text-sm font-semibold text-surface-900 mb-2">{component.name}</div>
                <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold ${statusColor[component.status]}`}>
                  {statusLabel[component.status]}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
