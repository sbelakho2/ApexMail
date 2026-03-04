import { Terminal, Zap, Lock } from '@/components/ui/icons';

export function APIConsoleHero() {
  return (
    <section className="relative min-h-[40vh] flex items-center pt-32 pb-20 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto">
          <div className="animate-in inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-6">
            <Terminal className="w-4 h-4 text-surface-500" aria-hidden="true" />
            API Sandbox Console
          </div>

          <h1 className="animate-in delay-100 text-4xl lg:text-6xl font-semibold text-surface-900 mb-6 tracking-tight">
            Explore the API <span className="text-primary-600">Without Signing Up</span>
          </motion.h1>

          <p className="animate-in delay-200 text-xl text-surface-600 mb-10 leading-relaxed font-medium">
            Preview requests, explore endpoints, and see simulated webhook events—all
            in a sandbox. Create a free account to send real emails.
          </p>

          <div className="animate-in delay-300 flex flex-wrap justify-center gap-8">
            <div className="flex items-center gap-2 text-surface-600 font-medium text-xs">
              <Zap className="w-5 h-5 text-surface-400" aria-hidden="true" />
              <span>Sandbox simulation</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-medium text-xs">
              <Lock className="w-5 h-5 text-surface-400" aria-hidden="true" />
              <span>No real emails sent</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-medium text-xs">
              <Terminal className="w-5 h-5 text-surface-400" aria-hidden="true" />
              <span>Copy code snippets</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
