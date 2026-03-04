import Link from 'next/link';
import { ArrowRight, Check } from '@/components/ui/icons';

interface CompareCTAProps {
  verdict: {
    title: string;
    points: readonly string[];
  };
}

export function CompareCTA({ verdict }: CompareCTAProps) {
  return (
    <section className="py-20 lg:py-32 bg-surface-50">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="animate-in bg-white border border-surface-200 shadow-sm rounded-lg p-8 lg:p-12">
          <div className="text-center mb-10">
            <h2 className="text-2xl lg:text-3xl font-bold text-surface-900 mb-6 tracking-tight">
                {verdict.title}
            </h2>
            <div className="w-16 h-1 bg-primary-500 mx-auto rounded-full opacity-20" />
          </div>

          <ul className="grid sm:grid-cols-2 gap-4 mb-10">
            {verdict.points.map((point, index) => (
              <li key={index} className="animate-in flex items-start gap-3 p-3 rounded-lg bg-surface-50 border border-surface-100">
                <span className="w-5 h-5 rounded-full bg-primary-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Check className="w-4 h-4 text-primary-600" />
                </span>
                <span className="text-surface-700 text-sm font-medium">{point}</span>
              </motion.li>
            ))}
          </ul>

          <div className="text-center">
            <div className="flex flex-col sm:flex-row justify-center gap-4 mb-6">
                <Link
                href="https://app.apexmail.ee/signup"
                className="btn-primary flex items-center justify-center gap-2 group px-8 py-3"
                >
                Start Free Trial
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </Link>
                <Link href="/pricing" className="btn-secondary px-8 py-3">
                View Pricing
                </Link>
            </div>

            <p className="text-sm text-surface-500 font-medium">
                No credit card required • 3,000 free emails per month • Setup in 5 minutes
            </p>
          </div>
        </div>

        {/* Other Comparisons */}
        <div className="animate-in delay-400 mt-12 text-center">
          <p className="text-sm text-surface-600 mb-4 font-medium">Compare ApexMail to other providers:</p>
          <div className="flex flex-wrap justify-center gap-2">
            {[
              { name: 'SendGrid', href: '/compare/sendgrid' },
              { name: 'Resend', href: '/compare/resend' },
              { name: 'Postmark', href: '/compare/postmark' },
              { name: 'Amazon SES', href: '/compare/amazon-ses' },
            ].map((link) => (
               <Link
                key={link.name}
                href={link.href}
                className="text-sm px-4 py-2 rounded-full bg-white border border-surface-200 text-surface-600 hover:text-primary-600 hover:border-primary-200 transition-colors"
                >
                vs {link.name}
                </Link>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
