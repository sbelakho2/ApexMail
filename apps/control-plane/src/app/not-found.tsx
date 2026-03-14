import Link from 'next/link';

export default function NotFound() {
    return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-slate-900">
            <div className="text-center">
                <h1 className="text-6xl font-bold text-slate-100">404</h1>
                <h2 className="mt-4 text-xl font-semibold text-slate-300">
                    Page not found
                </h2>
                <p className="mt-2 text-slate-400">
                    The requested resource could not be located.
                </p>
                <Link
                    href="/"
                    className="mt-6 inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900"
                >
                    Return to Control Plane
                </Link>
            </div>
        </main>
    );
}
