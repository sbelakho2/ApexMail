import Link from 'next/link';

export default function HomePage() {
    return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-gray-50">
            <div className="text-center">
                <h1 className="text-4xl font-bold text-gray-900">ApexMail</h1>
                <p className="mt-4 text-lg text-gray-600">
                    Modern email infrastructure for developers
                </p>
                <Link
                    href="/dashboard"
                    className="mt-6 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
                >
                    Go to Dashboard
                </Link>
            </div>
        </main>
    );
}
