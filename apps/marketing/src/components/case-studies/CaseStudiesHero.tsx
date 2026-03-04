import { BookOpen } from '@/components/ui/icons';

export function CaseStudiesHero() {
  return (
    <section className="pt-32 pb-20 bg-white">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="animate-in text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100 border border-surface-200 text-sm text-surface-700 mb-6 font-medium">
            <BookOpen className="w-4 h-4" />
            Customer Success
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 text-surface-900">
            Real Results From
            <span className="text-primary-600 block sm:inline sm:ml-3">Real Companies</span>
          </h1>

          <p className="text-xl text-surface-600 max-w-2xl mx-auto leading-relaxed">
            See how engineering teams at startups and enterprises use ApexMail 
            to deliver millions of transactional emails with confidence.
          </p>
        </div>
      </div>
    </section>
  );
}
