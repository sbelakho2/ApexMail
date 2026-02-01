/**
 * Calendar & Demo Scheduling
 */

import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import type {
    DemoSlot,
    SchedulingPreferences,
    AvailableHours,
    SlotStatus,
    MeetingType,
} from '../types.js';

const logger = createLogger('calendar');

// In-memory storage for demo
const slots = new Map<string, DemoSlot>();
const preferences = new Map<string, SchedulingPreferences>();

/**
 * Sets scheduling preferences for a user
 */
export function setSchedulingPreferences(
    prefs: SchedulingPreferences
): void {
    preferences.set(prefs.userId, prefs);
    logger.info('Set scheduling preferences', { userId: prefs.userId });
}

/**
 * Gets scheduling preferences for a user
 */
export function getSchedulingPreferences(
    userId: string
): SchedulingPreferences | null {
    return preferences.get(userId) || null;
}

/**
 * Creates default scheduling preferences
 */
export function createDefaultPreferences(userId: string): SchedulingPreferences {
    const defaultPrefs: SchedulingPreferences = {
        userId,
        defaultDuration: config.calendar.slotDurationMinutes,
        bufferBefore: config.calendar.bufferMinutes,
        bufferAfter: config.calendar.bufferMinutes,
        availableDays: [1, 2, 3, 4, 5], // Monday-Friday
        availableHours: [
            {
                dayOfWeek: 1,
                startHour: config.calendar.availableHoursStart,
                startMinute: 0,
                endHour: config.calendar.availableHoursEnd,
                endMinute: 0,
            },
            {
                dayOfWeek: 2,
                startHour: config.calendar.availableHoursStart,
                startMinute: 0,
                endHour: config.calendar.availableHoursEnd,
                endMinute: 0,
            },
            {
                dayOfWeek: 3,
                startHour: config.calendar.availableHoursStart,
                startMinute: 0,
                endHour: config.calendar.availableHoursEnd,
                endMinute: 0,
            },
            {
                dayOfWeek: 4,
                startHour: config.calendar.availableHoursStart,
                startMinute: 0,
                endHour: config.calendar.availableHoursEnd,
                endMinute: 0,
            },
            {
                dayOfWeek: 5,
                startHour: config.calendar.availableHoursStart,
                startMinute: 0,
                endHour: config.calendar.availableHoursEnd,
                endMinute: 0,
            },
        ],
        timezone: config.calendar.timezone,
        maxBookingsPerDay: 8,
        minNoticeHours: 24,
        maxAdvanceDays: 30,
    };

    preferences.set(userId, defaultPrefs);
    return defaultPrefs;
}

/**
 * Gets available slots for a user within a date range
 */
export function getAvailableSlots(
    userId: string,
    tenantId: string,
    startDate: Date,
    endDate: Date,
    durationMinutes?: number
): DemoSlot[] {
    const prefs = preferences.get(userId) || createDefaultPreferences(userId);
    const duration = durationMinutes || prefs.defaultDuration;
    const availableSlots: DemoSlot[] = [];

    const now = new Date();
    const minBookingTime = new Date(
        now.getTime() + prefs.minNoticeHours * 60 * 60 * 1000
    );
    const maxBookingTime = new Date(
        now.getTime() + prefs.maxAdvanceDays * 24 * 60 * 60 * 1000
    );

    // Adjust start/end based on constraints
    const effectiveStart = new Date(
        Math.max(startDate.getTime(), minBookingTime.getTime())
    );
    const effectiveEnd = new Date(
        Math.min(endDate.getTime(), maxBookingTime.getTime())
    );

    // Get existing bookings for the user
    const existingBookings = Array.from(slots.values()).filter(
        (s) =>
            s.userId === userId &&
            s.status === 'booked' &&
            s.startTime >= effectiveStart &&
            s.startTime <= effectiveEnd
    );

    // Generate slots for each day
    const currentDate = new Date(effectiveStart);
    currentDate.setHours(0, 0, 0, 0);

    while (currentDate <= effectiveEnd) {
        const dayOfWeek = currentDate.getDay();

        // Check if this day is available
        const dayHours = prefs.availableHours.find(
            (h) => h.dayOfWeek === dayOfWeek
        );

        if (dayHours && prefs.availableDays.includes(dayOfWeek)) {
            // Generate slots for this day
            const daySlots = generateDaySlots(
                currentDate,
                dayHours,
                duration,
                prefs.bufferBefore,
                prefs.bufferAfter,
                existingBookings,
                userId,
                tenantId,
                prefs.timezone
            );

            // Filter out slots before minBookingTime
            const validSlots = daySlots.filter(
                (s) => s.startTime >= minBookingTime
            );

            availableSlots.push(...validSlots);
        }

        currentDate.setDate(currentDate.getDate() + 1);
    }

    // Check max bookings per day
    const bookingsPerDay = new Map<string, number>();
    for (const booking of existingBookings) {
        const dayKey = booking.startTime.toISOString().split('T')[0];
        bookingsPerDay.set(dayKey, (bookingsPerDay.get(dayKey) || 0) + 1);
    }

    return availableSlots.filter((slot) => {
        const dayKey = slot.startTime.toISOString().split('T')[0];
        return (bookingsPerDay.get(dayKey) || 0) < prefs.maxBookingsPerDay;
    });
}

/**
 * Generates time slots for a specific day
 */
function generateDaySlots(
    date: Date,
    hours: AvailableHours,
    durationMinutes: number,
    bufferBefore: number,
    bufferAfter: number,
    existingBookings: DemoSlot[],
    userId: string,
    tenantId: string,
    timezone: string
): DemoSlot[] {
    const slots: DemoSlot[] = [];

    const startTime = new Date(date);
    startTime.setHours(hours.startHour, hours.startMinute, 0, 0);

    const endTime = new Date(date);
    endTime.setHours(hours.endHour, hours.endMinute, 0, 0);

    const slotInterval = durationMinutes; // Slot every X minutes

    let currentSlotStart = new Date(startTime);

    while (currentSlotStart < endTime) {
        const currentSlotEnd = new Date(
            currentSlotStart.getTime() + durationMinutes * 60 * 1000
        );

        // Check if slot end exceeds available hours
        if (currentSlotEnd > endTime) {
            break;
        }

        // Check for conflicts with existing bookings (including buffer)
        const slotWithBufferStart = new Date(
            currentSlotStart.getTime() - bufferBefore * 60 * 1000
        );
        const slotWithBufferEnd = new Date(
            currentSlotEnd.getTime() + bufferAfter * 60 * 1000
        );

        const hasConflict = existingBookings.some((booking) => {
            const bookingEnd = booking.endTime;
            return (
                (slotWithBufferStart < bookingEnd &&
                    slotWithBufferEnd > booking.startTime)
            );
        });

        if (!hasConflict) {
            slots.push({
                id: generateId('slot'),
                tenantId,
                userId,
                startTime: new Date(currentSlotStart),
                endTime: new Date(currentSlotEnd),
                timezone,
                status: 'available',
                bookedBy: null,
                leadId: null,
                meetingType: 'demo',
                meetingLink: null,
                notes: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            });
        }

        currentSlotStart = new Date(
            currentSlotStart.getTime() + slotInterval * 60 * 1000
        );
    }

    return slots;
}

/**
 * Books a slot
 */
export function bookSlot(
    slotId: string,
    leadId: string,
    bookedBy: string,
    meetingType: MeetingType = 'demo',
    notes?: string
): DemoSlot | null {
    const slot = slots.get(slotId);
    if (!slot || slot.status !== 'available') {
        return null;
    }

    slot.status = 'booked';
    slot.leadId = leadId;
    slot.bookedBy = bookedBy;
    slot.meetingType = meetingType;
    slot.notes = notes || null;
    slot.meetingLink = generateMeetingLink(slot);
    slot.updatedAt = new Date();

    slots.set(slotId, slot);

    logger.info('Booked slot', {
        slotId,
        leadId,
        startTime: slot.startTime,
        meetingType,
    });

    return slot;
}

/**
 * Creates a slot directly (for manual scheduling)
 */
export function createSlot(
    tenantId: string,
    userId: string,
    startTime: Date,
    endTime: Date,
    options?: {
        meetingType?: MeetingType;
        leadId?: string;
        bookedBy?: string;
        notes?: string;
    }
): DemoSlot {
    const slot: DemoSlot = {
        id: generateId('slot'),
        tenantId,
        userId,
        startTime,
        endTime,
        timezone: config.calendar.timezone,
        status: options?.leadId ? 'booked' : 'available',
        bookedBy: options?.bookedBy || null,
        leadId: options?.leadId || null,
        meetingType: options?.meetingType || 'demo',
        meetingLink: options?.leadId ? generateMeetingLink({ id: generateId('slot') } as DemoSlot) : null,
        notes: options?.notes || null,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    slots.set(slot.id, slot);
    return slot;
}

/**
 * Cancels a booking
 */
export function cancelBooking(
    slotId: string,
    reason?: string
): DemoSlot | null {
    const slot = slots.get(slotId);
    if (!slot || slot.status !== 'booked') {
        return null;
    }

    slot.status = 'cancelled';
    slot.notes = reason
        ? `${slot.notes || ''}\nCancelled: ${reason}`.trim()
        : slot.notes;
    slot.updatedAt = new Date();

    logger.info('Cancelled booking', { slotId, reason });

    return slot;
}

/**
 * Reschedules a booking
 */
export function rescheduleBooking(
    oldSlotId: string,
    newSlotId: string
): DemoSlot | null {
    const oldSlot = slots.get(oldSlotId);
    const newSlot = slots.get(newSlotId);

    if (!oldSlot || oldSlot.status !== 'booked') {
        return null;
    }

    if (!newSlot || newSlot.status !== 'available') {
        return null;
    }

    // Transfer booking to new slot
    newSlot.status = 'booked';
    newSlot.leadId = oldSlot.leadId;
    newSlot.bookedBy = oldSlot.bookedBy;
    newSlot.meetingType = oldSlot.meetingType;
    newSlot.notes = `Rescheduled from ${oldSlot.startTime.toISOString()}`;
    newSlot.meetingLink = generateMeetingLink(newSlot);
    newSlot.updatedAt = new Date();

    // Cancel old slot
    oldSlot.status = 'cancelled';
    oldSlot.notes = `Rescheduled to ${newSlot.startTime.toISOString()}`;
    oldSlot.updatedAt = new Date();

    logger.info('Rescheduled booking', {
        oldSlotId,
        newSlotId,
        leadId: newSlot.leadId,
    });

    return newSlot;
}

/**
 * Marks a meeting as completed
 */
export function completeSlot(
    slotId: string,
    notes?: string
): DemoSlot | null {
    const slot = slots.get(slotId);
    if (!slot || slot.status !== 'booked') {
        return null;
    }

    slot.status = 'completed';
    if (notes) {
        slot.notes = `${slot.notes || ''}\nNotes: ${notes}`.trim();
    }
    slot.updatedAt = new Date();

    return slot;
}

/**
 * Gets upcoming bookings for a user
 */
export function getUpcomingBookings(
    userId: string,
    limit: number = 10
): DemoSlot[] {
    const now = new Date();

    return Array.from(slots.values())
        .filter(
            (s) =>
                s.userId === userId &&
                s.status === 'booked' &&
                s.startTime > now
        )
        .sort((a, b) => a.startTime.getTime() - b.startTime.getTime())
        .slice(0, limit);
}

/**
 * Gets bookings for a lead
 */
export function getLeadBookings(leadId: string): DemoSlot[] {
    return Array.from(slots.values())
        .filter((s) => s.leadId === leadId)
        .sort((a, b) => a.startTime.getTime() - b.startTime.getTime());
}

/**
 * Generates a meeting link
 */
function generateMeetingLink(slot: DemoSlot): string {
    // In production, integrate with actual video conferencing service
    // For now, generate a placeholder link
    return `https://meet.apexmail.ee/${slot.id}`;
}

/**
 * Generates ICS calendar file content
 */
export function generateIcsFile(slot: DemoSlot, organizerEmail: string): string {
    const uid = `${slot.id}@apexmail.ee`;
    const now = new Date();
    const formatDate = (date: Date) =>
        date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

    return `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//ApexMail//Demo Scheduler//EN
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
UID:${uid}
DTSTAMP:${formatDate(now)}
DTSTART:${formatDate(slot.startTime)}
DTEND:${formatDate(slot.endTime)}
SUMMARY:${slot.meetingType.charAt(0).toUpperCase() + slot.meetingType.slice(1)} Call
DESCRIPTION:Meeting scheduled via ApexMail\\n\\nJoin: ${slot.meetingLink}
ORGANIZER:mailto:${organizerEmail}
STATUS:CONFIRMED
SEQUENCE:0
END:VEVENT
END:VCALENDAR`;
}

/**
 * Parses natural language time requests
 */
export function parseTimeRequest(
    text: string,
    baseDate: Date = new Date()
): Date | null {
    const lowerText = text.toLowerCase();

    // Tomorrow
    if (/tomorrow/i.test(lowerText)) {
        const tomorrow = new Date(baseDate);
        tomorrow.setDate(tomorrow.getDate() + 1);

        const timeMatch = lowerText.match(/(\d{1,2})(?::(\d{2}))?\s*(am|pm)?/i);
        if (timeMatch) {
            let hours = parseInt(timeMatch[1], 10);
            const minutes = timeMatch[2] ? parseInt(timeMatch[2], 10) : 0;
            const meridiem = timeMatch[3]?.toLowerCase();

            if (meridiem === 'pm' && hours < 12) hours += 12;
            if (meridiem === 'am' && hours === 12) hours = 0;

            tomorrow.setHours(hours, minutes, 0, 0);
        } else {
            tomorrow.setHours(10, 0, 0, 0); // Default to 10am
        }

        return tomorrow;
    }

    // Next week
    if (/next\s+(monday|tuesday|wednesday|thursday|friday)/i.test(lowerText)) {
        const dayMatch = lowerText.match(
            /next\s+(monday|tuesday|wednesday|thursday|friday)/i
        );
        if (dayMatch) {
            const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
            const targetDay = dayNames.indexOf(dayMatch[1].toLowerCase());

            const result = new Date(baseDate);
            const currentDay = result.getDay();
            const daysUntilTarget = (targetDay - currentDay + 7) % 7 || 7;

            result.setDate(result.getDate() + daysUntilTarget);
            result.setHours(10, 0, 0, 0); // Default to 10am

            return result;
        }
    }

    // Specific date
    const dateMatch = lowerText.match(
        /(\d{1,2})[\/\-](\d{1,2})(?:[\/\-](\d{2,4}))?/
    );
    if (dateMatch) {
        const month = parseInt(dateMatch[1], 10) - 1;
        const day = parseInt(dateMatch[2], 10);
        const year = dateMatch[3]
            ? parseInt(dateMatch[3], 10) + (dateMatch[3].length === 2 ? 2000 : 0)
            : baseDate.getFullYear();

        const result = new Date(year, month, day, 10, 0, 0, 0);
        return result;
    }

    return null;
}
