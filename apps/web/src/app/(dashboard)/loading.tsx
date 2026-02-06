/**
 * FIX-100: Dashboard-level loading state
 * Shows skeleton UI while dashboard routes are loading
 */
export default function DashboardLoading() {
    return (
        <div className="flex flex-col gap-6 p-6 animate-pulse">
            {/* Page header skeleton */}
            <div className="flex items-center justify-between">
                <div className="space-y-2">
                    <div className="h-8 w-48 bg-muted rounded" />
                    <div className="h-4 w-72 bg-muted/60 rounded" />
                </div>
                <div className="h-9 w-32 bg-muted rounded" />
            </div>

            {/* Stats cards skeleton */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                {Array.from({ length: 4 }).map((_, i) => (
                    <div
                        key={i}
                        className="rounded-xl border border-surface-200 bg-surface-50 p-6 space-y-3"
                    >
                        <div className="h-4 w-20 bg-muted rounded" />
                        <div className="h-7 w-28 bg-muted rounded" />
                        <div className="h-3 w-16 bg-muted/60 rounded" />
                    </div>
                ))}
            </div>

            {/* Chart skeleton */}
            <div className="rounded-xl border border-surface-200 bg-surface-50 p-6 space-y-4">
                <div className="h-5 w-36 bg-muted rounded" />
                <div className="h-64 w-full bg-muted/40 rounded" />
            </div>

            {/* Table skeleton */}
            <div className="rounded-xl border border-surface-200 bg-surface-50 p-6 space-y-3">
                <div className="h-5 w-40 bg-muted rounded" />
                {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex gap-4 py-3 border-b border-surface-100 last:border-0">
                        <div className="h-4 w-1/4 bg-muted/60 rounded" />
                        <div className="h-4 w-1/3 bg-muted/40 rounded" />
                        <div className="h-4 w-1/6 bg-muted/60 rounded" />
                        <div className="h-4 w-1/6 bg-muted/40 rounded" />
                    </div>
                ))}
            </div>
        </div>
    );
}
