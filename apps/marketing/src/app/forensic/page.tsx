import type { Metadata } from 'next';
import { ForensicHero } from '@/components/forensic/ForensicHero';
import { TimeTravelDemo } from '@/components/forensic/TimeTravelDemo';
import { RenderHistory } from '@/components/forensic/RenderHistory';
import { DebugTools } from '@/components/forensic/DebugTools';
import { ForensicCTA } from '@/components/forensic/ForensicCTA';

export const metadata: Metadata = {
  title: 'Forensic Debugging | Time Travel for Email',
  description:
    'Debug email rendering issues with time-travel capabilities. See exactly what your recipients saw, when they saw it, and why.',
  openGraph: {
    title: 'Forensic Debugging | Time Travel for Email',
    description:
      'Debug email rendering issues with time-travel capabilities. See exactly what your recipients saw, when they saw it, and why.',
    type: 'website',
  },
};

export default function ForensicPage() {
  return (
    <main className="overflow-hidden">
      <ForensicHero />
      <TimeTravelDemo />
      <RenderHistory />
      <DebugTools />
      <ForensicCTA />
    </main>
  );
}
