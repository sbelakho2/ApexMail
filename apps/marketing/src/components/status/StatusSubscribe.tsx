import Link from 'next/link';

export function StatusSubscribe() {
  return (
    <section className="py-12 bg-surface-50">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="rounded-lg border border-surface-200 bg-white p-6 sm:p-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-surface-900">Subscribe to status updates</h2>
            <p className="text-sm text-surface-500 mt-1">Get incident notifications and maintenance alerts.</p>
          </div>
          <div className="flex gap-3">
            <Link href="mailto:status@apexmail.ee" className="btn-secondary px-4 py-2 text-sm">
              Email Alerts
            </Link>
            <Link href="https://status.apexmail.ee/history.rss" className="btn-primary px-4 py-2 text-sm" target="_blank" rel="noopener noreferrer">
              RSS Feed
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
