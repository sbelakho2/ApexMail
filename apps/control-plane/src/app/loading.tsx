export default function Loading() {
    return (
        <div className="min-h-screen flex items-center justify-center bg-background">
            <div className="flex flex-col items-center gap-4">
                <div className="relative">
                    <div className="w-12 h-12 border-4 border-muted rounded-full" />
                    <div className="absolute top-0 left-0 w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin" />
                </div>
                <p className="text-sm text-muted-foreground font-medium">
                    Loading control plane...
                </p>
            </div>
        </div>
    );
}
