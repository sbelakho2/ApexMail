'use client';

import { useState, useEffect, useRef } from 'react';
import { formatDate, formatTime, getLocalTimeZone, cn, getStatusChipClasses } from '../../lib/utils';
import { PageEmptyState, PageErrorState, PageLoadingState } from '../../components/ui/async-state';
import { Button } from '../../components/ui/button';
import {
    AvailabilitySlot,
    CALENDAR_TABS,
    CalendarEvent,
    DAYS,
    EVENT_TYPE_CONFIG,
    getAvailabilityConflicts,
    getCalendarStats,
    getFilteredEvents,
    isValidMeetingLink,
    splitCalendarEvents,
    STATUS_CONFIG,
} from './calendar-utils';

/**
 * Demo Calendar - Schedule discovery calls and demos with interested leads
 * 
 * The owner can:
 * - View scheduled demos/calls
 * - Set availability windows
 * - Manage calendar connections
 * - Track demo outcomes
 */

export default function CalendarPage() {
    const [events, setEvents] = useState<CalendarEvent[]>([]);
    const [availability, setAvailability] = useState<AvailabilitySlot[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'upcoming' | 'past' | 'availability'>('upcoming');
    const [statusFilter, setStatusFilter] = useState<'all' | CalendarEvent['status']>('all');
    const [eventSearch, setEventSearch] = useState('');
    const [displayTimezone, setDisplayTimezone] = useState<'local' | 'UTC'>('local');
    const [selectedEvent, setSelectedEvent] = useState<CalendarEvent | null>(null);
    const [showNoShowCapture, setShowNoShowCapture] = useState(false);
    const [noShowReasonInput, setNoShowReasonInput] = useState('');
    const timezone = getLocalTimeZone();
    const modalRef = useRef<HTMLDivElement>(null);
    const lastFocusedElementRef = useRef<HTMLElement | null>(null);

    useEffect(() => {
        loadData();

        try {
            const saved = localStorage.getItem('calendar-page-preferences');
            if (saved) {
                const parsed = JSON.parse(saved);
                if (parsed.activeTab) setActiveTab(parsed.activeTab);
                if (parsed.statusFilter) setStatusFilter(parsed.statusFilter);
                if (parsed.eventSearch) setEventSearch(parsed.eventSearch);
                if (parsed.displayTimezone) setDisplayTimezone(parsed.displayTimezone);
            }
        } catch {
            // ignore invalid local storage payload
        }
    }, []);

    useEffect(() => {
        try {
            localStorage.setItem('calendar-page-preferences', JSON.stringify({ activeTab, statusFilter, eventSearch, displayTimezone }));
        } catch {
            // ignore local persistence failure
        }
    }, [activeTab, statusFilter, eventSearch, displayTimezone]);

    async function loadData() {
        setLoading(true);
        setLoadError(null);
        try {
            const response = await fetch('/api/calendar', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch calendar: ${response.status}`);
            const data = await response.json();
            setEvents(data.events);
            setAvailability(data.availability);
        } catch (err) {
            console.error('Failed to load calendar data:', err);
            setLoadError(err instanceof Error ? err.message : 'Failed to load calendar data');
        } finally {
            setLoading(false);
        }
    }

    async function toggleAvailability(slotId: string) {
        const previousAvailability = availability;
        const slot = availability.find((currentSlot) => currentSlot.id === slotId);
        const nextEnabled = slot ? !slot.enabled : true;

        setAvailability((prev) => prev.map((currentSlot) =>
            currentSlot.id === slotId ? { ...currentSlot, enabled: nextEnabled } : currentSlot
        ));

        try {
            const response = await fetch(`/api/calendar/availability/${slotId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ enabled: nextEnabled }),
            });
            if (!response.ok) {
                throw new Error(`Failed to update availability: ${response.status}`);
            }
        } catch (err) {
            setAvailability(previousAvailability);
            setLoadError(err instanceof Error ? err.message : 'Failed to update availability');
        }
    }

    async function updateEventStatus(eventId: string, status: CalendarEvent['status'], noShowReason?: string) {
        const previousEvents = events;
        const previousSelected = selectedEvent;

        setEvents((prev) => prev.map((event) =>
            event.id === eventId ? { ...event, status, noShowReason } : event
        ));
        if (selectedEvent?.id === eventId) {
            setSelectedEvent((prev) => prev ? { ...prev, status, noShowReason } : null);
        }

        try {
            const response = await fetch(`/api/calendar/events/${eventId}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ status, noShowReason }),
            });
            if (!response.ok) {
                throw new Error(`Failed to update event status: ${response.status}`);
            }
        } catch (err) {
            setEvents(previousEvents);
            setSelectedEvent(previousSelected);
            setLoadError(err instanceof Error ? err.message : 'Failed to update event status');
        }
    }

    const [now, setNow] = useState(() => new Date('2026-01-15T10:00:00Z'));
    useEffect(() => { setNow(new Date()); }, []);

    function isValidMeetingLink(link: string): boolean {
        try {
            const parsed = new URL(link);
            return parsed.protocol === 'https:';
        } catch {
            return false;
        }
    }

    function formatEventDate(iso: string): string {
        if (displayTimezone === 'UTC') {
            return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeZone: 'UTC' }).format(new Date(iso));
        }
        return formatDate(iso);
    }

    function formatEventTime(iso: string): string {
        if (displayTimezone === 'UTC') {
            return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }).format(new Date(iso));
        }
        return formatTime(iso);
    }

    const filteredEvents = getFilteredEvents(events, statusFilter, eventSearch);
    const { upcomingEvents, pastEvents } = splitCalendarEvents(filteredEvents, now);

    const availabilityConflicts = getAvailabilityConflicts(availability);

    useEffect(() => {
        if (!selectedEvent) return;

        lastFocusedElementRef.current = document.activeElement as HTMLElement | null;
        const timer = window.setTimeout(() => {
            const focusables = modalRef.current?.querySelectorAll<HTMLElement>(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (focusables && focusables.length > 0) {
                focusables[0].focus();
            } else {
                modalRef.current?.focus();
            }
        }, 0);

        return () => {
            window.clearTimeout(timer);
            lastFocusedElementRef.current?.focus();
        };
    }, [selectedEvent]);

    function handleModalKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
        if (e.key === 'Escape') {
            setSelectedEvent(null);
            return;
        }

        if (e.key !== 'Tab') return;

        const focusables = modalRef.current?.querySelectorAll<HTMLElement>(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );

        if (!focusables || focusables.length === 0) {
            e.preventDefault();
            return;
        }

        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;

        if (e.shiftKey && active === first) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
        }
    }

    const { scheduledCount, completedCount, noShowCount, showRate } = getCalendarStats(events);

    if (loading) {
        return <PageLoadingState label="Loading calendar..." />;
    }

    if (loadError) {
        return (
            <PageErrorState
                title="Failed to load calendar"
                description={loadError}
                onRetry={loadData}
            />
        );
    }

    return (
        <div className="cp-page cp-page--narrow">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Demo Calendar</h1>
                    <p className="text-muted-foreground mt-1">
                        Schedule and manage discovery calls and demos • Times shown in {displayTimezone === 'UTC' ? 'UTC' : timezone}
                    </p>
                </div>
                <div className="flex gap-2">
                    <select
                        value={displayTimezone}
                        onChange={(event) => setDisplayTimezone(event.target.value as 'local' | 'UTC')}
                        className="px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none"
                        aria-label="Timezone display"
                    >
                        <option value="local">Local Time</option>
                        <option value="UTC">UTC</option>
                    </select>
                    <Button variant="outline" size="md">
                        Connect Calendar
                    </Button>
                    <Button variant="default" size="md">
                        Copy Booking Link
                    </Button>
                </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Upcoming</div>
                    <div className="text-2xl font-bold text-primary">{scheduledCount}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Completed</div>
                    <div className="text-2xl font-bold text-success">{completedCount}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">No Shows</div>
                    <div className="text-2xl font-bold text-destructive">{noShowCount}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Show Rate</div>
                    <div className="text-2xl font-bold text-primary">{showRate}%</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-border mb-6 overflow-x-auto">
                <nav className="flex gap-4 min-w-max">
                    {CALENDAR_TABS.map((tab) => {
                        const label = tab.key === 'upcoming'
                            ? `${tab.label} (${upcomingEvents.length})`
                            : tab.key === 'past'
                                ? `${tab.label} (${pastEvents.length})`
                                : tab.label;

                        return (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key as typeof activeTab)}
                            className={cn(
                                'pb-3 text-sm font-medium transition-colors border-b-2',
                                activeTab === tab.key
                                    ? 'border-primary text-primary'
                                    : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
                            )}
                        >
                            {label}
                        </button>
                        );
                    })}
                </nav>
            </div>

            <div className="mb-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
                <input
                    type="text"
                    value={eventSearch}
                    onChange={(event) => setEventSearch(event.target.value)}
                    placeholder="Search by title, lead, or company"
                    className="px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none"
                />
                <select
                    value={statusFilter}
                    onChange={(event) => setStatusFilter(event.target.value as 'all' | CalendarEvent['status'])}
                    className="px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none"
                >
                    <option value="all">All statuses</option>
                    <option value="scheduled">Scheduled</option>
                    <option value="completed">Completed</option>
                    <option value="no_show">No show</option>
                    <option value="rescheduled">Rescheduled</option>
                    <option value="cancelled">Cancelled</option>
                </select>
            </div>

            {/* Upcoming Events */}
            {activeTab === 'upcoming' && (
                <div className="bg-card rounded-xl border border-border shadow-sm">
                    {upcomingEvents.length === 0 ? (
                        <PageEmptyState
                            title="No upcoming meetings"
                            description="New discovery calls and demos will appear here once booked."
                        />
                    ) : (
                        <div className="divide-y divide-border">
                            {upcomingEvents.map(event => {
                                const typeConfig = EVENT_TYPE_CONFIG[event.type];
                                return (
                                    <div
                                        key={event.id}
                                        className="p-4 hover:bg-muted/50 cursor-pointer flex items-center gap-4 transition-colors"
                                        onClick={() => setSelectedEvent(event)}
                                    >
                                        <div className="text-2xl">{typeConfig.icon}</div>
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="font-medium text-foreground">{event.title}</span>
                                                <span className={cn('px-2.5 py-0.5 rounded text-xs font-medium', typeConfig.color)}>
                                                    {typeConfig.label}
                                                </span>
                                            </div>
                                            <div className="text-sm text-muted-foreground">
                                                {event.leadName} • {event.leadCompany}
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-sm font-medium text-foreground">
                                                {formatEventDate(event.startTime)}
                                            </div>
                                            <div className="text-sm text-muted-foreground">
                                                {formatEventTime(event.startTime)} -
                                                {formatEventTime(event.endTime)}
                                            </div>
                                        </div>
                                        {isValidMeetingLink(event.meetingLink) ? (
                                            <a
                                                href={event.meetingLink}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                onClick={(e) => e.stopPropagation()}
                                                className="inline-flex items-center justify-center min-h-[44px] px-3 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors"
                                            >
                                                Join
                                            </a>
                                        ) : (
                                            <span className="text-xs text-warning">Invalid meeting link</span>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* Past Events */}
            {activeTab === 'past' && (
                <div className="bg-card rounded-xl border border-border shadow-sm">
                    {pastEvents.length === 0 ? (
                        <PageEmptyState
                            title="No past meetings"
                            description="Completed and closed meetings will appear here."
                        />
                    ) : (
                        <div className="divide-y divide-border">
                            {pastEvents.map(event => {
                                const typeConfig = EVENT_TYPE_CONFIG[event.type];
                                const statusConfig = STATUS_CONFIG[event.status];
                                return (
                                    <div
                                        key={event.id}
                                        className="p-4 hover:bg-muted/50 cursor-pointer flex items-center gap-4 transition-colors"
                                        onClick={() => setSelectedEvent(event)}
                                    >
                                        <div className="text-2xl opacity-50">{typeConfig.icon}</div>
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="font-medium text-foreground">{event.title}</span>
                                                <span className={cn('text-xs font-medium px-2 py-0.5 rounded-full border', getStatusChipClasses(event.status))}>
                                                    {statusConfig.label}
                                                </span>
                                            </div>
                                            <div className="text-sm text-muted-foreground">
                                                {event.leadName} • {event.leadCompany}
                                            </div>
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            {formatEventDate(event.startTime)}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* Availability */}
            {activeTab === 'availability' && (
                <div className="bg-card rounded-xl border border-border p-6">
                    <h3 className="text-lg font-semibold text-foreground mb-4">Weekly Availability</h3>
                    <p className="text-sm text-muted-foreground mb-6">
                        Set the times when prospects can book meetings with you.
                    </p>
                    {availabilityConflicts.length > 0 && (
                        <div className="mb-4 rounded-lg border border-warning/30 bg-warning/10 px-4 py-3 text-xs text-warning">
                            Overlapping availability detected: {availabilityConflicts.join(', ')}
                        </div>
                    )}
                    <div className="space-y-4">
                        {[1, 2, 3, 4, 5].map(day => {
                            const daySlots = availability.filter(s => s.dayOfWeek === day);
                            return (
                                <div key={day} className="flex items-center gap-4">
                                    <div className="w-24 font-medium text-foreground">{DAYS[day]}</div>
                                    <div className="flex-1 flex flex-wrap gap-2">
                                        {daySlots.map(slot => (
                                            <button
                                                key={slot.id}
                                                onClick={() => toggleAvailability(slot.id)}
                                                className={cn(
                                                    'px-3 py-1.5 rounded text-sm font-medium transition-colors',
                                                    slot.enabled
                                                        ? 'bg-primary/10 text-primary hover:bg-primary/20'
                                                        : 'bg-muted text-muted-foreground line-through hover:bg-muted/80'
                                                )}
                                            >
                                                {slot.startTime} - {slot.endTime}
                                            </button>
                                        ))}
                                        <button aria-label={`Add availability slot for ${DAYS[day]}`} type="button" className="px-3 py-1.5 border border-dashed border-border rounded text-sm text-muted-foreground hover:border-foreground hover:text-foreground">
                                            + Add
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                    <div className="mt-6 pt-6 border-t border-border">
                        <h4 className="text-sm font-medium text-foreground mb-3">Meeting Settings</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label className="text-sm text-muted-foreground">Discovery Call Duration</label>
                                <select className="mt-1 w-full px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all">
                                    <option>15 minutes</option>
                                    <option selected>30 minutes</option>
                                    <option>45 minutes</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground">Demo Duration</label>
                                <select className="mt-1 w-full px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all">
                                    <option>30 minutes</option>
                                    <option>45 minutes</option>
                                    <option selected>60 minutes</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground">Buffer Between Meetings</label>
                                <select className="mt-1 w-full px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all">
                                    <option>No buffer</option>
                                    <option selected>15 minutes</option>
                                    <option>30 minutes</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground">Booking Notice</label>
                                <select className="mt-1 w-full px-3 py-2 border border-border rounded-lg text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all">
                                    <option>1 hour</option>
                                    <option selected>4 hours</option>
                                    <option>24 hours</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Event Detail Modal */}
            {selectedEvent && (
                <div
                    className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-stretch justify-end z-50"
                    onClick={() => setSelectedEvent(null)}
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="calendar-event-title"
                    tabIndex={-1}
                    onKeyDown={handleModalKeyDown}
                >
                    <div
                        ref={modalRef}
                        className="bg-card p-6 w-full max-w-lg shadow-xl border-l border-border h-full overflow-y-auto"
                        onClick={(e) => e.stopPropagation()}
                        tabIndex={-1}
                    >
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 id="calendar-event-title" className="text-xl font-bold text-foreground">{selectedEvent.title}</h2>
                                <div className="text-sm text-muted-foreground mt-1">
                                    {formatEventDate(selectedEvent.startTime)} • {formatEventTime(selectedEvent.startTime)}
                                </div>
                            </div>
                            <Button
                                onClick={() => setSelectedEvent(null)} 
                                variant="ghost"
                                size="sm"
                                aria-label="Close modal"
                            >
                                Close
                            </Button>
                        </div>

                        <div className="space-y-4 mb-6">
                            <div className="flex items-center gap-3">
                                <span className="text-muted-foreground w-20">Lead:</span>
                                <span className="font-medium text-foreground">{selectedEvent.leadName}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-muted-foreground w-20">Company:</span>
                                <span className="text-foreground">{selectedEvent.leadCompany}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-muted-foreground w-20">Email:</span>
                                <span className="text-foreground">{selectedEvent.leadEmail}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-muted-foreground w-20">Status:</span>
                                <span className={cn('text-xs font-medium px-2 py-0.5 rounded-full border', getStatusChipClasses(selectedEvent.status))}>
                                    {STATUS_CONFIG[selectedEvent.status].label}
                                </span>
                            </div>
                            {selectedEvent.notes && (
                                <div>
                                    <span className="text-muted-foreground block mb-1">Notes:</span>
                                    <p className="text-sm bg-muted/50 rounded-lg p-3 text-foreground border border-border">{selectedEvent.notes}</p>
                                </div>
                            )}
                            <div className="border border-border rounded-lg p-3 bg-muted/20">
                                <div className="text-xs uppercase tracking-wide text-muted-foreground mb-2">Audit Fields (Immutable)</div>
                                <div className="text-xs text-muted-foreground space-y-1">
                                    <div>Event ID: <span className="text-foreground font-mono">{selectedEvent.id}</span></div>
                                    <div>Created: <span className="text-foreground">{selectedEvent.createdAt ? formatEventDate(selectedEvent.createdAt) : 'Unknown'}</span></div>
                                    <div>Updated: <span className="text-foreground">{selectedEvent.updatedAt ? formatEventDate(selectedEvent.updatedAt) : 'Unknown'}</span></div>
                                    <div>Created by: <span className="text-foreground">{selectedEvent.createdBy || 'System'}</span></div>
                                </div>
                            </div>
                        </div>

                        <div className="flex gap-2">
                            {selectedEvent.status === 'scheduled' && (
                                <>
                                    {isValidMeetingLink(selectedEvent.meetingLink) ? (
                                        <a
                                            href={selectedEvent.meetingLink}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="flex-1 inline-flex items-center justify-center min-h-[44px] px-4 py-2 bg-primary text-primary-foreground rounded-lg text-center hover:bg-primary/90 font-medium transition-colors"
                                        >
                                            Join Meeting
                                        </a>
                                    ) : (
                                        <span className="flex-1 inline-flex items-center justify-center min-h-[44px] px-4 py-2 rounded-lg text-sm bg-warning/10 text-warning border border-warning/20">
                                            Invalid meeting URL
                                        </span>
                                    )}
                                    <Button
                                        onClick={() => updateEventStatus(selectedEvent.id, 'completed')}
                                        variant="outline"
                                        size="md"
                                        className="text-success border-success/30 hover:bg-success/10"
                                    >
                                        Mark Complete
                                    </Button>
                                    <Button
                                        onClick={() => setShowNoShowCapture(true)}
                                        variant="outline"
                                        size="md"
                                        className="text-destructive border-destructive/30 hover:bg-destructive/10"
                                    >
                                        No Show
                                    </Button>
                                </>
                            )}
                            {selectedEvent.status !== 'scheduled' && (
                                <Button
                                    onClick={() => setSelectedEvent(null)}
                                    variant="outline"
                                    size="md"
                                    className="flex-1"
                                >
                                    Close
                                </Button>
                            )}
                        </div>
                        {showNoShowCapture && (
                            <div className="mt-4 border border-destructive/20 rounded-lg p-3 bg-destructive/5">
                                <label className="block text-xs font-medium text-foreground mb-2">No-show reason</label>
                                <textarea
                                    value={noShowReasonInput}
                                    onChange={(event) => setNoShowReasonInput(event.target.value)}
                                    placeholder="Capture reason (traffic, conflict, no response, etc.)"
                                    className="w-full min-h-[80px] px-3 py-2 border border-border bg-background rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-primary outline-none"
                                />
                                <div className="mt-2 flex justify-end gap-2">
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => {
                                            setShowNoShowCapture(false);
                                            setNoShowReasonInput('');
                                        }}
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        className="text-destructive border-destructive/30 hover:bg-destructive/10"
                                        onClick={async () => {
                                            await updateEventStatus(selectedEvent.id, 'no_show', noShowReasonInput.trim() || undefined);
                                            setShowNoShowCapture(false);
                                            setNoShowReasonInput('');
                                        }}
                                    >
                                        Save Reason
                                    </Button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
