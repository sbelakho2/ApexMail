import { Button } from '@/components/ui/button';

interface PaginationControlsProps {
    page: number;
    totalPages: number;
    onPageChange: (page: number) => void;
}

export function PaginationControls({ page, totalPages, onPageChange }: PaginationControlsProps) {
    const safeTotalPages = Math.max(1, totalPages);
    const isFirstPage = page <= 1;
    const isLastPage = page >= safeTotalPages;

    return (
        <div className="flex items-center gap-2" role="navigation" aria-label="Pagination controls">
            <Button
                variant="outline"
                size="sm"
                disabled={isFirstPage}
                onClick={() => onPageChange(1)}
            >
                First
            </Button>
            <Button
                variant="outline"
                size="sm"
                disabled={isFirstPage}
                onClick={() => onPageChange(Math.max(1, page - 1))}
            >
                Previous
            </Button>
            <span className="px-2 text-sm text-muted-foreground">
                Page {page} of {safeTotalPages}
            </span>
            <Button
                variant="outline"
                size="sm"
                disabled={isLastPage}
                onClick={() => onPageChange(Math.min(safeTotalPages, page + 1))}
            >
                Next
            </Button>
            <Button
                variant="outline"
                size="sm"
                disabled={isLastPage}
                onClick={() => onPageChange(safeTotalPages)}
            >
                Last
            </Button>
        </div>
    );
}
