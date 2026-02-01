import type { Metadata } from 'next';
import { APIConsoleHero } from '@/components/api-console/APIConsoleHero';
import { InteractiveConsole } from '@/components/api-console/InteractiveConsole';
import { EndpointExplorer } from '@/components/api-console/EndpointExplorer';
import { APIConsoleCTA } from '@/components/api-console/APIConsoleCTA';

export const metadata: Metadata = {
  title: 'Live API Console | Try Without Signing Up',
  description:
    'Explore the ApexMail API without creating an account. Send test emails, see webhooks in real-time, and understand the full capabilities.',
  openGraph: {
    title: 'Live API Console | Try Without Signing Up',
    description:
      'Explore the ApexMail API without creating an account. Send test emails, see webhooks in real-time, and understand the full capabilities.',
    type: 'website',
  },
};

export default function APIConsolePage() {
  return (
    <main className="overflow-hidden">
      <APIConsoleHero />
      <InteractiveConsole />
      <EndpointExplorer />
      <APIConsoleCTA />
    </main>
  );
}
