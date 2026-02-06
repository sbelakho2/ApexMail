'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn } from '../../lib/utils';

/**
 * Demo Calendar - Schedule discovery calls and demos with interested leads
 * 
 * The owner can:
 * - View scheduled demos/calls
 * - Set availability windows
 * - Manage calendar connections
 * - Track demo outcomes
 */

interface CalendarEvent {
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
}

interface AvailabilitySlot {
    id: string;
    dayOfWeek: number;
    startTime: string;
    endTime: string;
    enabled: boolean;
}

const EVENT_TYPE_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
    discovery: { label: 'Discovery Call', color: 'bg-info/10 text-info', icon: '🔍' },
    demo: { label: 'Product Demo', color: 'bg-primary/10 text-primary', icon: '🎬' },
    follow_up: { label: 'Follow-up', color: 'bg-success/10 text-success', icon: '📞' },
};

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
    scheduled: { label: 'Scheduled', color: 'text-primary' },
    completed: { label: 'Completed', color: 'text-success' },
    no_show: { label: 'No Show', color: 'text-destructive' },
    rescheduled: { label: 'Rescheduled', color: 'text-warning' },
    cancelled: { label: 'Cancelled', color: 'text-muted-foreground' },
};

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];



export default function CalendarPage() {
    const [events, setEvents] = useState<CalendarEvent[]>([]);
    const [availability, setAvailability] = useState<AvailabilitySlot[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'upcoming' | 'past' | 'availability'>('upcoming');
    const [selectedEvent, setSelectedEvent] = useState<CalendarEvent | null>(null);

    useEffect(() => {
        loadData();
    }, []);

    async function loadData() {
        try {
            const response = await fetch('/api/calendar', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch calendar: ${response.status}`);
            const data = await response.json();
            setEvents(data.events);
            setAvailability(data.availability);
        } catch (err) {
            console.error('Failed to load calendar data:', err);
        } finally {
            setLoading(false);
        }
    }

    function toggleAvailability(slotId: string) {
        setAvailability(prev => prev.map(s =>
            s.id === slotId ? { ...s, enabled: !s.enabled } : s
        ));
    }

    function updateEventStatus(eventId: string, status: CalendarEvent['status']) {
        setEvents(prev => prev.map(e =>
            e.id === eventId ? { ...e, status } : e
        ));
        if (selectedEvent?.id === eventId) {
            setSelectedEvent(prev => prev ? { ...prev, status } : null);
        }
    }

    const [now, setNow] = useState(() => new Date('2026-01-15T10:00:00Z'));
    useEffect(() => { setNow(new Date()); }, []);

    const upcomingEvents = events.filter(e => new Date(e.startTime) > now && e.status === 'scheduled');
    const pastEvents = events.filter(e => new Date(e.startTime) <= now || e.status !== 'scheduled');

    // Stats
    const scheduledCount = events.filter(e => e.status === 'scheduled').length;
    const completedCount = events.filter(e => e.status === 'completed').length;
    const noShowCount = events.filter(e => e.status === 'no_show').length;
    const showRate = completedCount > 0 ? ((completedCount / (completedCount + noShowCount)) * 100).toFixed(0) : 'N/A';

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Demo Calendar</h1>
                    <p className="text-muted-foreground mt-1">
                        Schedule and manage discovery calls and demos
                    </p>
                </div>
                <div className="flex gap-2">
                    <button className="px-4 py-2 bg-card border border-border rounded-lg text-sm hover:bg-muted font-medium text-foreground transition-colors">
                        🔗 Connect Calendar
                    </button>
                    <button className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors">
                        📋 Copy Booking Link
                    </button>
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
                    {[
                        { key: 'upcoming', label: `Upcoming (${upcomingEvents.length})` },
                        { key: 'past', label: `Past (${pastEvents.length})` },
                        { key: 'availability', label: 'Availability' },
                    ].map(tab => (
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
                            {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Upcoming Events */}
            {activeTab === 'upcoming' && (
                <div className="bg-card rounded-xl border border-border shadow-sm">
                    {upcomingEvents.length === 0 ? (
                        <div className="p-8 text-center text-muted-foreground">
                            No upcoming meetings scheduled
                        </div>
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
                                                {formatDate(event.startTime)}
                                            </div>
                                            <div className="text-sm text-muted-foreground">
                                                {new Date(event.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} -
                                                {new Date(event.endTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                            </div>
                                        </div>
                                        <a
                                            href={event.meetingLink}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            onClick={(e) => e.stopPropagation()}
                                            className="px-3 py-1.5 bg-primary text-primary-foreground rounded text-sm hover:bg-primary/90 font-medium transition-colors"
                                        >
                                            Join
                                        </a>
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
                        <div className="p-8 text-center text-muted-foreground">
                            No past meetings
                        </div>
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
                                                <span className={cn('text-sm font-medium', statusConfig.color)}>
                                                    {statusConfig.label}
                                                </span>
                                            </div>
                                            <div className="text-sm text-muted-foreground">
                                                {event.leadName} • {event.leadCompany}
                                            </div>
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            {formatDate(event.startTime)}
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
                                        <button className="px-3 py-1.5 border border-dashed border-border rounded text-sm text-muted-foreground hover:border-foreground hover:text-foreground">
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
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedEvent(null)}>
                    <div className="bg-card rounded-xl p-6 w-full max-w-lg shadow-xl border border-border" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-foreground">{selectedEvent.title}</h2>
                                <div className="text-sm text-muted-foreground mt-1">
                                    {formatDate(selectedEvent.startTime)} • {new Date(selectedEvent.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </div>
                            </div>
                            <button 
                                onClick={() => setSelectedEvent(null)} 
                                className="text-muted-foreground hover:text-foreground transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
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
                                <span className={STATUS_CONFIG[selectedEvent.status].color}>
                                    {STATUS_CONFIG[selectedEvent.status].label}
                                </span>
                            </div>
                            {selectedEvent.notes && (
                                <div>
                                    <span className="text-muted-foreground block mb-1">Notes:</span>
                                    <p className="text-sm bg-muted/50 rounded-lg p-3 text-foreground border border-border">{selectedEvent.notes}</p>
                                </div>
                            )}
                        </div>

                        <div className="flex gap-2">
                            {selectedEvent.status === 'scheduled' && (
                                <>
                                    <a
                                        href={selectedEvent.meetingLink}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex-1 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-center hover:bg-primary/90 font-medium transition-colors"
                                    >
                                        🔗 Join Meeting
                                    </a>
                                    <button
                                        onClick={() => updateEventStatus(selectedEvent.id, 'completed')}
                                        className="px-4 py-2 bg-success/10 text-success rounded-lg hover:bg-success/20 font-medium transition-colors"
                                    >
                                        ✓ Mark Complete
                                    </button>
                                    <button
                                        onClick={() => updateEventStatus(selectedEvent.id, 'no_show')}
                                        className="px-4 py-2 bg-destructive/10 text-destructive rounded-lg hover:bg-destructive/20 font-medium transition-colors"
                                    >
                                        ✗ No Show
                                    </button>
                                </>
                            )}
                            {selectedEvent.status !== 'scheduled' && (
                                <button
                                    onClick={() => setSelectedEvent(null)}
                                    className="flex-1 px-4 py-2 bg-muted text-muted-foreground rounded-lg hover:bg-muted/80 font-medium transition-colors"
                                >
                                    Close
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
