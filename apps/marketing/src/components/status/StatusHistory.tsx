'use client';

import { useEffect, useState } from 'react';

interface Incident {
  id: string;
  name: string;
  status: string;
  updated_at: string;
}

export function StatusHistory() {
  const [incidents, setIncidents] = useState<Incident[]>([]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const response = await fetch('https://status.apexmail.ee/api/v2/incidents.json', { cache: 'no-store' });
        if (!response.ok) throw new Error('Failed to load incidents');

        const data = (await response.json()) as { incidents?: Incident[] };
        if (cancelled) return;
        setIncidents((data.incidents ?? []).slice(0, 5));
      } catch {
        if (cancelled) return;
        setIncidents([]);
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
        <h2 className="text-xl font-semibold text-surface-900 mb-6">Recent Incidents</h2>
        {incidents.length === 0 ? (
          <p className="text-surface-500 text-sm">No recent incidents reported.</p>
        ) : (
          <ul className="space-y-3">
            {incidents.map((incident) => (
              <li key={incident.id} className="rounded-lg border border-surface-200 bg-white p-4">
                <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                  <p className="font-medium text-surface-900">{incident.name}</p>
                  <span className="text-xs uppercase tracking-wide text-surface-500">{incident.status.replaceAll('_', ' ')}</span>
                </div>
                <p className="text-xs text-surface-500 mt-1">
                  Updated {new Date(incident.updated_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
