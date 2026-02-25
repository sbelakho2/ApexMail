import { Button } from '@/components/ui/button';
import { ArrowUpDown } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

type SortDirection = 'asc' | 'desc';

interface SortableTableHeadProps {
    label: string;
    active: boolean;
    direction: SortDirection;
    onClick: () => void;
    className?: string;
}

export function SortableTableHead({ label, active, direction, onClick, className }: SortableTableHeadProps) {
    return (
        <Button
            variant="ghost"
            size="sm"
            className={cn('h-8 gap-1.5 px-2', className)}
            onClick={onClick}
            aria-label={`Sort by ${label} ${active ? `(currently ${direction})` : ''}`}
        >
            <span>{label}</span>
            <ArrowUpDown className={cn('h-4 w-4', active ? 'opacity-100' : 'opacity-50')} />
            <span className={cn('text-[10px] uppercase', active ? 'opacity-100' : 'opacity-0')}>
                {direction}
            </span>
        </Button>
    );
}
