import Link from 'next/link';

export default function HomePage() {
    return (
        <main className="flex min-h-screen flex-col items-center justify-center">
            <div className="text-center">
                <h1 className="text-4xl font-bold">Control Plane</h1>
                <p className="mt-4 text-lg text-slate-400">
                    ApexMail administration and monitoring
                </p>
                <Link
                    href="/audit"
                    className="mt-6 inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
                >
                    View Audit Logs
                </Link>
            </div>
        </main>
    );
}
