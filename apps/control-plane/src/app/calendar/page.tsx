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
    discovery: { label: 'Discovery Call', color: 'bg-blue-100 text-blue-700', icon: '🔍' },
    demo: { label: 'Product Demo', color: 'bg-violet-100 text-violet-700', icon: '🎬' },
    follow_up: { label: 'Follow-up', color: 'bg-emerald-100 text-emerald-700', icon: '📞' },
};

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
    scheduled: { label: 'Scheduled', color: 'text-blue-600' },
    completed: { label: 'Completed', color: 'text-emerald-600' },
    no_show: { label: 'No Show', color: 'text-red-600' },
    rescheduled: { label: 'Rescheduled', color: 'text-amber-600' },
    cancelled: { label: 'Cancelled', color: 'text-surface-600' },
};

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

const DEMO_EVENTS: CalendarEvent[] = [
    { id: '1', title: 'Discovery Call - TechCorp', leadName: 'John Smith', leadEmail: 'john@techcorp.io', leadCompany: 'TechCorp', type: 'discovery', status: 'scheduled', startTime: new Date(Date.now() + 86400000).toISOString(), endTime: new Date(Date.now() + 86400000 + 1800000).toISOString(), notes: 'Interested in enterprise features', meetingLink: 'https://meet.apexmail.io/demo/abc123' },
    { id: '2', title: 'Product Demo - Growth.io', leadName: 'Sarah Williams', leadEmail: 'sarah@growth.io', leadCompany: 'Growth.io', type: 'demo', status: 'scheduled', startTime: new Date(Date.now() + 172800000).toISOString(), endTime: new Date(Date.now() + 172800000 + 3600000).toISOString(), notes: '50 users, 100k emails/month', meetingLink: 'https://meet.apexmail.io/demo/def456' },
    { id: '3', title: 'Follow-up - StartupXYZ', leadName: 'Mike Johnson', leadEmail: 'mike@startupxyz.com', leadCompany: 'StartupXYZ', type: 'follow_up', status: 'completed', startTime: new Date(Date.now() - 86400000).toISOString(), endTime: new Date(Date.now() - 86400000 + 1800000).toISOString(), notes: 'Discussing pricing options', outcome: 'needs_follow_up', meetingLink: 'https://meet.apexmail.io/demo/ghi789' },
    { id: '4', title: 'Demo - Enterprise Co', leadName: 'Alice Brown', leadEmail: 'alice@enterprise.co', leadCompany: 'Enterprise Co', type: 'demo', status: 'no_show', startTime: new Date(Date.now() - 172800000).toISOString(), endTime: new Date(Date.now() - 172800000 + 3600000).toISOString(), notes: 'Large enterprise deal', meetingLink: 'https://meet.apexmail.io/demo/jkl012' },
];

const DEFAULT_AVAILABILITY: AvailabilitySlot[] = [
    { id: '1', dayOfWeek: 1, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '2', dayOfWeek: 1, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '3', dayOfWeek: 2, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '4', dayOfWeek: 2, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '5', dayOfWeek: 3, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '6', dayOfWeek: 3, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '7', dayOfWeek: 4, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '8', dayOfWeek: 4, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '9', dayOfWeek: 5, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '10', dayOfWeek: 5, startTime: '14:00', endTime: '16:00', enabled: true },
];

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
            // In production: fetch from Sales Autopilot API
            setEvents(DEMO_EVENTS);
            setAvailability(DEFAULT_AVAILABILITY);
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

    const upcomingEvents = events.filter(e => new Date(e.startTime) > new Date() && e.status === 'scheduled');
    const pastEvents = events.filter(e => new Date(e.startTime) <= new Date() || e.status !== 'scheduled');

    // Stats
    const scheduledCount = events.filter(e => e.status === 'scheduled').length;
    const completedCount = events.filter(e => e.status === 'completed').length;
    const noShowCount = events.filter(e => e.status === 'no_show').length;
    const showRate = completedCount > 0 ? ((completedCount / (completedCount + noShowCount)) * 100).toFixed(0) : 'N/A';

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Demo Calendar</h1>
                    <p className="text-surface-600 mt-1">
                        Schedule and manage discovery calls and demos
                    </p>
                </div>
                <div className="flex gap-2">
                    <button className="px-4 py-2 bg-surface-0 border border-surface-200 rounded-lg text-sm hover:bg-surface-50 font-medium text-surface-700 transition-colors">
                        🔗 Connect Calendar
                    </button>
                    <button className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 font-medium transition-colors">
                        📋 Copy Booking Link
                    </button>
                </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Upcoming</div>
                    <div className="text-2xl font-bold text-blue-600">{scheduledCount}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Completed</div>
                    <div className="text-2xl font-bold text-emerald-600">{completedCount}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">No Shows</div>
                    <div className="text-2xl font-bold text-red-600">{noShowCount}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Show Rate</div>
                    <div className="text-2xl font-bold text-blue-600">{showRate}%</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-surface-200 mb-6 overflow-x-auto">
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
                                    ? 'border-blue-600 text-blue-600'
                                    : 'border-transparent text-surface-500 hover:text-surface-700 hover:border-surface-300'
                            )}
                        >
                            {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Upcoming Events */}
            {activeTab === 'upcoming' && (
                <div className="bg-surface-0 rounded-xl border border-surface-200 shadow-sm">
                    {upcomingEvents.length === 0 ? (
                        <div className="p-8 text-center text-surface-500">
                            No upcoming meetings scheduled
                        </div>
                    ) : (
                        <div className="divide-y divide-surface-100">
                            {upcomingEvents.map(event => {
                                const typeConfig = EVENT_TYPE_CONFIG[event.type];
                                return (
                                    <div
                                        key={event.id}
                                        className="p-4 hover:bg-surface-50 cursor-pointer flex items-center gap-4 transition-colors"
                                        onClick={() => setSelectedEvent(event)}
                                    >
                                        <div className="text-2xl">{typeConfig.icon}</div>
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="font-medium text-surface-900">{event.title}</span>
                                                <span className={cn('px-2 py-0.5 rounded text-xs font-medium', typeConfig.color)}>
                                                    {typeConfig.label}
                                                </span>
                                            </div>
                                            <div className="text-sm text-surface-500">
                                                {event.leadName} • {event.leadCompany}
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-sm font-medium text-surface-900">
                                                {formatDate(event.startTime)}
                                            </div>
                                            <div className="text-sm text-surface-500">
                                                {new Date(event.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} -
                                                {new Date(event.endTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                            </div>
                                        </div>
                                        <a
                                            href={event.meetingLink}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            onClick={(e) => e.stopPropagation()}
                                            className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 font-medium transition-colors"
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
                <div className="bg-surface-0 rounded-xl border border-surface-200 shadow-sm">
                    {pastEvents.length === 0 ? (
                        <div className="p-8 text-center text-surface-500">
                            No past meetings
                        </div>
                    ) : (
                        <div className="divide-y divide-surface-100">
                            {pastEvents.map(event => {
                                const typeConfig = EVENT_TYPE_CONFIG[event.type];
                                const statusConfig = STATUS_CONFIG[event.status];
                                return (
                                    <div
                                        key={event.id}
                                        className="p-4 hover:bg-surface-50 cursor-pointer flex items-center gap-4 transition-colors"
                                        onClick={() => setSelectedEvent(event)}
                                    >
                                        <div className="text-2xl opacity-50">{typeConfig.icon}</div>
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="font-medium text-surface-700">{event.title}</span>
                                                <span className={cn('text-sm font-medium', statusConfig.color)}>
                                                    {statusConfig.label}
                                                </span>
                                            </div>
                                            <div className="text-sm text-surface-500">
                                                {event.leadName} • {event.leadCompany}
                                            </div>
                                        </div>
                                        <div className="text-sm text-surface-500">
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
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6">
                    <h3 className="text-lg font-semibold text-surface-900 mb-4">Weekly Availability</h3>
                    <p className="text-sm text-surface-500 mb-6">
                        Set the times when prospects can book meetings with you.
                    </p>
                    <div className="space-y-4">
                        {[1, 2, 3, 4, 5].map(day => {
                            const daySlots = availability.filter(s => s.dayOfWeek === day);
                            return (
                                <div key={day} className="flex items-center gap-4">
                                    <div className="w-24 font-medium text-surface-700">{DAYS[day]}</div>
                                    <div className="flex-1 flex flex-wrap gap-2">
                                        {daySlots.map(slot => (
                                            <button
                                                key={slot.id}
                                                onClick={() => toggleAvailability(slot.id)}
                                                className={cn(
                                                    'px-3 py-1.5 rounded text-sm font-medium transition-colors',
                                                    slot.enabled
                                                        ? 'bg-blue-100 text-blue-700 hover:bg-blue-200'
                                                        : 'bg-surface-100 text-surface-400 line-through hover:bg-surface-200'
                                                )}
                                            >
                                                {slot.startTime} - {slot.endTime}
                                            </button>
                                        ))}
                                        <button className="px-3 py-1.5 border border-dashed border-surface-300 rounded text-sm text-surface-400 hover:border-surface-400 hover:text-surface-500">
                                            + Add
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                    <div className="mt-6 pt-6 border-t border-surface-200">
                        <h4 className="text-sm font-medium text-surface-700 mb-3">Meeting Settings</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label className="text-sm text-surface-500">Discovery Call Duration</label>
                                <select className="mt-1 w-full px-3 py-2 border border-surface-200 rounded-lg text-sm bg-surface-0 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all">
                                    <option>15 minutes</option>
                                    <option selected>30 minutes</option>
                                    <option>45 minutes</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-sm text-surface-500">Demo Duration</label>
                                <select className="mt-1 w-full px-3 py-2 border border-surface-200 rounded-lg text-sm bg-surface-0 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all">
                                    <option>30 minutes</option>
                                    <option>45 minutes</option>
                                    <option selected>60 minutes</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-sm text-surface-500">Buffer Between Meetings</label>
                                <select className="mt-1 w-full px-3 py-2 border border-surface-200 rounded-lg text-sm bg-surface-0 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all">
                                    <option>No buffer</option>
                                    <option selected>15 minutes</option>
                                    <option>30 minutes</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-sm text-surface-500">Booking Notice</label>
                                <select className="mt-1 w-full px-3 py-2 border border-surface-200 rounded-lg text-sm bg-surface-0 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all">
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
                <div className="fixed inset-0 bg-surface-900/50 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedEvent(null)}>
                    <div className="bg-surface-0 rounded-xl p-6 w-full max-w-lg shadow-xl border border-surface-200" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-surface-900">{selectedEvent.title}</h2>
                                <div className="text-sm text-surface-500 mt-1">
                                    {formatDate(selectedEvent.startTime)} • {new Date(selectedEvent.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </div>
                            </div>
                            <button 
                                onClick={() => setSelectedEvent(null)} 
                                className="text-surface-400 hover:text-surface-600 transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
                        </div>

                        <div className="space-y-4 mb-6">
                            <div className="flex items-center gap-3">
                                <span className="text-surface-500 w-20">Lead:</span>
                                <span className="font-medium text-surface-900">{selectedEvent.leadName}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-surface-500 w-20">Company:</span>
                                <span className="text-surface-700">{selectedEvent.leadCompany}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-surface-500 w-20">Email:</span>
                                <span className="text-surface-700">{selectedEvent.leadEmail}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-surface-500 w-20">Status:</span>
                                <span className={STATUS_CONFIG[selectedEvent.status].color}>
                                    {STATUS_CONFIG[selectedEvent.status].label}
                                </span>
                            </div>
                            {selectedEvent.notes && (
                                <div>
                                    <span className="text-surface-500 block mb-1">Notes:</span>
                                    <p className="text-sm bg-surface-50 rounded-lg p-3 text-surface-700 border border-surface-100">{selectedEvent.notes}</p>
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
                                        className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg text-center hover:bg-blue-700 font-medium transition-colors"
                                    >
                                        🔗 Join Meeting
                                    </a>
                                    <button
                                        onClick={() => updateEventStatus(selectedEvent.id, 'completed')}
                                        className="px-4 py-2 bg-emerald-100 text-emerald-700 rounded-lg hover:bg-emerald-200 font-medium transition-colors"
                                    >
                                        ✓ Mark Complete
                                    </button>
                                    <button
                                        onClick={() => updateEventStatus(selectedEvent.id, 'no_show')}
                                        className="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 font-medium transition-colors"
                                    >
                                        ✗ No Show
                                    </button>
                                </>
                            )}
                            {selectedEvent.status !== 'scheduled' && (
                                <button
                                    onClick={() => setSelectedEvent(null)}
                                    className="flex-1 px-4 py-2 bg-surface-100 text-surface-700 rounded-lg hover:bg-surface-200 font-medium transition-colors"
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
