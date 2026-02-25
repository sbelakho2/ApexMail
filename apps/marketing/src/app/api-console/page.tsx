import type { Metadata } from 'next';
import { APIConsoleHero } from '@/components/api-console/APIConsoleHero';
import { InteractiveConsole } from '@/components/api-console/InteractiveConsole';
import { EndpointExplorer } from '@/components/api-console/EndpointExplorer';
import { APIConsoleCTA } from '@/components/api-console/APIConsoleCTA';
import { DemoErrorBoundary } from '@/components/ui/DemoErrorBoundary';

// Force dynamic rendering to avoid ESM/CommonJS issues with html-encoding-sniffer
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'API Sandbox Console | Explore Without Signing Up',
  description:
    'Explore the ApexMail API in a sandbox environment. Preview requests, see simulated webhook events, and understand the full API surface—no account required.',
  openGraph: {
    title: 'API Sandbox Console | Explore Without Signing Up',
    description:
      'Explore the ApexMail API in a sandbox environment. Preview requests, see simulated webhook events, and understand the full API surface.',
    type: 'website',
  },
};

export default function APIConsolePage() {
  return (
    <main className="overflow-hidden">
      <APIConsoleHero />
      <DemoErrorBoundary demoName="API Sandbox">
        <InteractiveConsole />
      </DemoErrorBoundary>
      <DemoErrorBoundary demoName="Endpoint Explorer">
        <EndpointExplorer />
      </DemoErrorBoundary>
      <APIConsoleCTA />
    </main>
  );
}
