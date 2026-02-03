import type { Metadata } from 'next';
import { StatusHero } from '@/components/status/StatusHero';
import { StatusOverview } from '@/components/status/StatusOverview';
import { StatusHistory } from '@/components/status/StatusHistory';
import { StatusSubscribe } from '@/components/status/StatusSubscribe';

export const metadata: Metadata = {
  title: 'System Status | ApexMail',
  description:
    'Real-time system status, uptime history, and incident reports for ApexMail email delivery platform.',
  openGraph: {
    title: 'System Status | ApexMail',
    description:
      'Real-time system status, uptime history, and incident reports for ApexMail email delivery platform.',
  },
};

export default function StatusPage() {
  return (
    <main className="overflow-hidden">
      <StatusHero />
      <StatusOverview />
      <StatusHistory />
      <StatusSubscribe />
    </main>
  );
}
