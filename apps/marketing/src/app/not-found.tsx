import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-[60vh] w-full max-w-3xl flex-col items-center justify-center px-6 py-24 text-center">
      <p className="text-sm font-semibold uppercase tracking-widest text-surface-500">404</p>
      <h1 className="mt-3 text-3xl font-bold tracking-tight text-surface-900">Page not found</h1>
      <p className="mt-3 text-surface-600">
        The page you requested does not exist or has moved.
      </p>
      <div className="mt-8 flex items-center gap-3">
        <Link
          href="/"
          className="rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-600"
        >
          Go to homepage
        </Link>
        <Link
          href="/features"
          className="rounded-md border border-surface-200 px-4 py-2 text-sm font-semibold text-surface-900 transition-colors hover:bg-surface-50"
        >
          Explore features
        </Link>
      </div>
    </main>
  );
}
