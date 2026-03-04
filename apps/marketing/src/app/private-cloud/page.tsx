import type { Metadata } from 'next';
import { PrivateCloudHero } from '@/components/private-cloud/PrivateCloudHero';
import { LatencyComparison } from '@/components/private-cloud/LatencyComparison';
import { DeploymentOptions } from '@/components/private-cloud/DeploymentOptions';
import { SecurityIsolation } from '@/components/private-cloud/SecurityIsolation';
import { DedicatedIPs } from '@/components/private-cloud/DedicatedIPs';
import { PrivateCloudCTA } from '@/components/private-cloud/PrivateCloudCTA';

export const dynamic = 'force-static';
export const revalidate = 3600;

export const metadata: Metadata = {
  title: 'Private Cloud | Your VPC, Your IP, Our Code',
  description:
    'Deploy ApexMail in your own VPC with dedicated IPs. Sub-millisecond latency, complete data sovereignty, and zero shared infrastructure.',
  openGraph: {
    title: 'Private Cloud | Your VPC, Your IP, Our Code',
    description:
      'Deploy ApexMail in your own VPC with dedicated IPs. Sub-millisecond latency, complete data sovereignty, and zero shared infrastructure.',
    type: 'website',
  },
};

export default function PrivateCloudPage() {
  return (
    <main className="overflow-hidden">
      <PrivateCloudHero />
      <LatencyComparison />
      <DeploymentOptions />
      <SecurityIsolation />
      <DedicatedIPs />
      <PrivateCloudCTA />
    </main>
  );
}
