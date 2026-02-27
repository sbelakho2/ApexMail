export interface CalendarEvent {
    id: string;
    title: string;
    leadName: string;
    leadEmail: string;
    leadCompany: string;
    type: 'discovery' | 'demo' | 'follow_up';
    status: 'scheduled' | 'completed' | 'no_show' | 'rescheduled' | 'cancelled';
    startTime: string;
    endTime: string;
    notes: string;
    outcome?: 'qualified' | 'not_qualified' | 'needs_follow_up' | 'closed_won' | 'closed_lost';
    meetingLink: string;
    createdAt?: string;
    updatedAt?: string;
    createdBy?: string;
    noShowReason?: string;
}

export interface AvailabilitySlot {
    id: string;
    dayOfWeek: number;
    startTime: string;
    endTime: string;
    enabled: boolean;
}

export const EVENT_TYPE_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
    discovery: { label: 'Discovery Call', color: 'bg-info/10 text-info', icon: 'Discovery' },
    demo: { label: 'Product Demo', color: 'bg-primary/10 text-primary', icon: 'Demo' },
    follow_up: { label: 'Follow-up', color: 'bg-success/10 text-success', icon: 'Follow-up' },
};

export const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
    scheduled: { label: 'Scheduled', color: 'text-primary' },
    completed: { label: 'Completed', color: 'text-success' },
    no_show: { label: 'No Show', color: 'text-destructive' },
    rescheduled: { label: 'Rescheduled', color: 'text-warning' },
    cancelled: { label: 'Cancelled', color: 'text-muted-foreground' },
};

export const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export const CALENDAR_TABS = [
    { key: 'upcoming', label: 'Upcoming' },
    { key: 'past', label: 'Past' },
    { key: 'availability', label: 'Availability' },
] as const;

function toMinutes(value: string): number {
    const [hours, minutes] = value.split(':').map(Number);
    return (hours * 60) + minutes;
}

export function isValidMeetingLink(link: string): boolean {
    try {
        const parsed = new URL(link);
        return parsed.protocol === 'https:';
    } catch {
        return false;
    }
}

export function getFilteredEvents(
    events: CalendarEvent[],
    statusFilter: 'all' | CalendarEvent['status'],
    eventSearch: string
): CalendarEvent[] {
    return events.filter((event) => {
        const matchesStatus = statusFilter === 'all' ? true : event.status === statusFilter;
        const query = eventSearch.trim().toLowerCase();
        const matchesSearch = !query
            ? true
            : event.title.toLowerCase().includes(query) || event.leadName.toLowerCase().includes(query) || event.leadCompany.toLowerCase().includes(query);
        return matchesStatus && matchesSearch;
    });
}

export function splitCalendarEvents(events: CalendarEvent[], now: Date): { upcomingEvents: CalendarEvent[]; pastEvents: CalendarEvent[] } {
    const upcomingEvents = events.filter((event) => new Date(event.startTime) > now && event.status === 'scheduled');
    const pastEvents = events.filter((event) => new Date(event.startTime) <= now || event.status !== 'scheduled');
    return { upcomingEvents, pastEvents };
}

export function getAvailabilityConflicts(availability: AvailabilitySlot[]): string[] {
    return availability.reduce<string[]>((acc, slot) => {
        if (!slot.enabled) return acc;
        const sameDaySlots = availability.filter((other) => other.id !== slot.id && other.dayOfWeek === slot.dayOfWeek && other.enabled);
        const slotStart = toMinutes(slot.startTime);
        const slotEnd = toMinutes(slot.endTime);
        const hasOverlap = sameDaySlots.some((other) => {
            const otherStart = toMinutes(other.startTime);
            const otherEnd = toMinutes(other.endTime);
            return slotStart < otherEnd && otherStart < slotEnd;
        });
        if (hasOverlap) {
            acc.push(`${DAYS[slot.dayOfWeek]} ${slot.startTime}-${slot.endTime}`);
        }
        return acc;
    }, []);
}

export function getCalendarStats(events: CalendarEvent[]): {
    scheduledCount: number;
    completedCount: number;
    noShowCount: number;
    showRate: string;
} {
    const scheduledCount = events.filter((event) => event.status === 'scheduled').length;
    const completedCount = events.filter((event) => event.status === 'completed').length;
    const noShowCount = events.filter((event) => event.status === 'no_show').length;
    const showRate = completedCount > 0 ? ((completedCount / (completedCount + noShowCount)) * 100).toFixed(0) : 'N/A';
    return { scheduledCount, completedCount, noShowCount, showRate };
}