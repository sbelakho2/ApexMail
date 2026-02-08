/**
 * Calendar & Demo Scheduling
 */

import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import { getDbPool } from '../db.js';
import { recordActivity } from '../crm/pipeline.js';
import type {
    DemoSlot,
    SchedulingPreferences,
    AvailableHours,
    MeetingType,
} from '../types.js';

const logger = createLogger({ name: 'calendar', level: 'info' });

/**
 * FIX-500-152: L1 in-memory cache backed by Postgres.
 * All mutations write-through to DB.
 * FIX-500-248: Capped at MAX_CACHE_SIZE to prevent unbounded growth.
 */
const moduleSlots = new Map<string, DemoSlot>();
const preferences = new Map<string, SchedulingPreferences>();
const MAX_CACHE_SIZE = 10000;

/**
 * FIX-500-248: Periodic eviction of past/expired demo slots from the cache.
 */
setInterval(() => {
    const now = Date.now();
    let evicted = 0;
    for (const [id, slot] of moduleSlots) {
        // Evict slots whose endTime is in the past
        if (slot.endTime && new Date(slot.endTime).getTime() < now) {
            moduleSlots.delete(id);
            evicted++;
        }
    }
    // If still over cap, evict oldest entries
    if (moduleSlots.size > MAX_CACHE_SIZE) {
        const excess = moduleSlots.size - MAX_CACHE_SIZE;
        const iter = moduleSlots.keys();
        for (let i = 0; i < excess; i++) {
            const key = iter.next().value;
            if (key) moduleSlots.delete(key);
        }
        evicted += excess;
    }
    if (preferences.size > MAX_CACHE_SIZE) {
        const excess = preferences.size - MAX_CACHE_SIZE;
        const iter = preferences.keys();
        for (let i = 0; i < excess; i++) {
            const key = iter.next().value;
            if (key) preferences.delete(key);
        }
    }
    if (evicted > 0) {
        logger.info('Evicted expired/excess slots from cache', { evicted, slotsRemaining: moduleSlots.size, prefsRemaining: preferences.size });
    }
}, 5 * 60 * 1000).unref(); // Every 5 minutes

/**
 * FIX-500-125: Retrieve a slot by ID from the module-level store.
 */
export function getSlot(slotId: string): DemoSlot | null {
    return moduleSlots.get(slotId) ?? null;
}

/**
 * Sets scheduling preferences for a user
 * FIX-500-152: Write-through to DB.
 */
export async function setSchedulingPreferences(
    prefs: SchedulingPreferences
): Promise<void> {
    preferences.set(prefs.userId, prefs);

    try {
        const pool = getDbPool();
        await pool.query(
            `INSERT INTO scheduling_preferences (user_id, default_duration, buffer_before, buffer_after,
             available_days, available_hours, timezone, max_bookings_per_day, min_notice_hours, max_advance_days)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (user_id) DO UPDATE SET
               default_duration = EXCLUDED.default_duration,
               buffer_before = EXCLUDED.buffer_before,
               buffer_after = EXCLUDED.buffer_after,
               available_days = EXCLUDED.available_days,
               available_hours = EXCLUDED.available_hours,
               timezone = EXCLUDED.timezone,
               max_bookings_per_day = EXCLUDED.max_bookings_per_day,
               min_notice_hours = EXCLUDED.min_notice_hours,
               max_advance_days = EXCLUDED.max_advance_days,
               updated_at = NOW()`,
            [prefs.userId, prefs.defaultDuration, prefs.bufferBefore, prefs.bufferAfter,
             prefs.availableDays, JSON.stringify(prefs.availableHours), prefs.timezone,
             prefs.maxBookingsPerDay, prefs.minNoticeHours, prefs.maxAdvanceDays]
        );
    } catch (err) {
        logger.error('Failed to persist scheduling preferences', { userId: prefs.userId, error: err instanceof Error ? err.message : String(err) });
    }

    logger.info('Set scheduling preferences', { userId: prefs.userId });
}

/**
 * Gets scheduling preferences for a user
 * FIX-500-152: Falls back to DB if not in cache.
 */
export async function getSchedulingPreferences(
    userId: string
): Promise<SchedulingPreferences | null> {
    const cached = preferences.get(userId);
    if (cached) return cached;

    try {
        const pool = getDbPool();
        const { rows } = await pool.query(
            'SELECT * FROM scheduling_preferences WHERE user_id = $1',
            [userId]
        );
        if (rows.length > 0) {
            const row = rows[0];
            const prefs: SchedulingPreferences = {
                userId: row.user_id,
                defaultDuration: row.default_duration,
                bufferBefore: row.buffer_before,
                bufferAfter: row.buffer_after,
                availableDays: row.available_days,
                availableHours: row.available_hours as AvailableHours[],
                timezone: row.timezone,
                maxBookingsPerDay: row.max_bookings_per_day,
                minNoticeHours: row.min_notice_hours,
                maxAdvanceDays: row.max_advance_days,
            };
            preferences.set(userId, prefs);
            return prefs;
        }
    } catch (err) {
        logger.warn('Failed to load preferences from DB', { userId, error: err instanceof Error ? err.message : String(err) });
    }

    return null;
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
 * FIX-500-314: Cap total generated slots to MAX_GENERATED_SLOTS.
 */
export function getAvailableSlots(
    userId: string,
    tenantId: string,
    startDate: Date,
    endDate: Date,
    durationMinutes?: number
): DemoSlot[] {
    const MAX_GENERATED_SLOTS = 500;
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
    const existingBookings = Array.from(moduleSlots.values()).filter(
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
            // FIX-500-314: Pass remaining budget to prevent unbounded generation
            const remainingBudget = MAX_GENERATED_SLOTS - availableSlots.length;
            if (remainingBudget <= 0) break;

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
                prefs.timezone,
                remainingBudget
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
        const dayKey = booking.startTime.toISOString().split('T')[0] ?? '';
        bookingsPerDay.set(dayKey, (bookingsPerDay.get(dayKey) || 0) + 1);
    }

    return availableSlots.filter((slot) => {
        const dayKey = slot.startTime.toISOString().split('T')[0] ?? '';
        return (bookingsPerDay.get(dayKey) || 0) < prefs.maxBookingsPerDay;
    });
}

/**
 * Generates time slots for a specific day
 * FIX-500-314: Accepts a remaining slot budget to prevent unbounded generation.
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
    timezone: string,
    maxSlots: number = 500
): DemoSlot[] {
    const slots: DemoSlot[] = [];

    const startTime = new Date(date);
    startTime.setHours(hours.startHour, hours.startMinute, 0, 0);

    const endTime = new Date(date);
    endTime.setHours(hours.endHour, hours.endMinute, 0, 0);

    const slotInterval = durationMinutes; // Slot every X minutes

    let currentSlotStart = new Date(startTime);

    while (currentSlotStart < endTime) {
        // FIX-500-314: Stop generating once we hit the cap
        if (slots.length >= maxSlots) {
            break;
        }

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
            // FIX-500-125: Persist generated slots to the module-level Map.
            // Previously, generated slots had ephemeral IDs that only existed
            // in the returned array — bookSlot() looked them up in the Map
            // and always returned null. Now every generated slot is stored
            // so it can be found and booked.
            const newSlot: DemoSlot = {
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
            };
            moduleSlots.set(newSlot.id, newSlot);
            // FIX-500-152: Fire-and-forget persist for generated available slots
            persistSlot(newSlot).catch(() => { /* best-effort */ });
            slots.push(newSlot);
        }

        currentSlotStart = new Date(
            currentSlotStart.getTime() + slotInterval * 60 * 1000
        );
    }

    return slots;
}

/**
 * FIX-500-152: Persist a slot to the DB (upsert).
 */
async function persistSlot(slot: DemoSlot): Promise<void> {
    try {
        const pool = getDbPool();
        await pool.query(
            `INSERT INTO demo_slots (id, tenant_id, user_id, start_time, end_time, timezone, status,
             booked_by, lead_id, meeting_type, meeting_link, notes, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (id) DO UPDATE SET
               status = EXCLUDED.status, booked_by = EXCLUDED.booked_by,
               lead_id = EXCLUDED.lead_id, meeting_type = EXCLUDED.meeting_type,
               meeting_link = EXCLUDED.meeting_link, notes = EXCLUDED.notes,
               updated_at = EXCLUDED.updated_at`,
            [slot.id, slot.tenantId, slot.userId, slot.startTime, slot.endTime,
             slot.timezone, slot.status, slot.bookedBy, slot.leadId,
             slot.meetingType, slot.meetingLink, slot.notes, slot.createdAt, slot.updatedAt]
        );
    } catch (err) {
        logger.error('Failed to persist slot to DB', { slotId: slot.id, error: err instanceof Error ? err.message : String(err) });
    }
}

/**
 * Books a slot
 * FIX-500-152: Write-through to DB.
 * FIX-500-309: Use CAS (Compare-And-Swap) pattern — only book if the DB
 * row's status is still 'available'. This prevents two concurrent requests
 * from both succeeding on the same slot.
 */
export async function bookSlot(
    slotId: string,
    leadId: string,
    bookedBy: string,
    meetingType: MeetingType = 'demo',
    notes?: string
): Promise<DemoSlot | null> {
    const slot = moduleSlots.get(slotId);
    if (!slot || slot.status !== 'available') {
        return null;
    }

    // FIX-500-309: Atomic CAS in the database — only update if still available
    try {
        const pool = getDbPool();
        const casResult = await pool.query(
            `UPDATE demo_slots
             SET status = 'booked', lead_id = $2, booked_by = $3,
                 meeting_type = $4, notes = $5, updated_at = NOW()
             WHERE id = $1 AND status = 'available'
             RETURNING *`,
            [slotId, leadId, bookedBy, meetingType, notes || null]
        );
        if ((casResult.rowCount ?? 0) === 0) {
            // Another request booked it first — update our cache and return null
            slot.status = 'booked';
            return null;
        }
    } catch (err) {
        logger.error('Failed CAS booking in DB', { slotId, error: err instanceof Error ? err.message : String(err) });
        return null;
    }

    // CAS succeeded — update in-memory cache
    slot.status = 'booked';
    slot.leadId = leadId;
    slot.bookedBy = bookedBy;
    slot.meetingType = meetingType;
    slot.notes = notes || null;
    slot.meetingLink = generateMeetingLink(slot);
    slot.updatedAt = new Date();

    moduleSlots.set(slotId, slot);

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
 * FIX-500-152: Write-through to DB.
 */
export async function createSlot(
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
): Promise<DemoSlot> {
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

    moduleSlots.set(slot.id, slot);
    await persistSlot(slot);
    return slot;
}

/**
 * Cancels a booking
 * FIX-500-152: Write-through to DB.
 */
export async function cancelBooking(
    slotId: string,
    reason?: string
): Promise<DemoSlot | null> {
    const slot = moduleSlots.get(slotId);
    if (!slot || slot.status !== 'booked') {
        return null;
    }

    slot.status = 'cancelled';
    slot.notes = reason
        ? `${slot.notes || ''}\nCancelled: ${reason}`.trim()
        : slot.notes;
    slot.updatedAt = new Date();

    await persistSlot(slot);

    logger.info('Cancelled booking', { slotId, reason });

    return slot;
}

/**
 * Reschedules a booking
 * FIX-500-152: Write-through to DB.
 */
export async function rescheduleBooking(
    oldSlotId: string,
    newSlotId: string
): Promise<DemoSlot | null> {
    const oldSlot = moduleSlots.get(oldSlotId);
    const newSlot = moduleSlots.get(newSlotId);

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

    await persistSlot(newSlot);
    await persistSlot(oldSlot);

    // FIX-500-472: Record CRM activity for the reschedule
    if (newSlot.leadId) {
        await recordActivity(newSlot.leadId, {
            type: 'demo_rescheduled',
            description: `Demo rescheduled from ${oldSlot.startTime.toISOString()} to ${newSlot.startTime.toISOString()}`,
            data: { oldSlotId, newSlotId, newTime: newSlot.startTime.toISOString() },
            userId: null,
        });
    }

    logger.info('Rescheduled booking', {
        oldSlotId,
        newSlotId,
        leadId: newSlot.leadId,
    });

    return newSlot;
}

/**
 * Marks a meeting as completed
 * FIX-500-152: Write-through to DB.
 */
export async function completeSlot(
    slotId: string,
    notes?: string
): Promise<DemoSlot | null> {
    const slot = moduleSlots.get(slotId);
    if (!slot || slot.status !== 'booked') {
        return null;
    }

    slot.status = 'completed';
    if (notes) {
        slot.notes = `${slot.notes || ''}\nNotes: ${notes}`.trim();
    }
    slot.updatedAt = new Date();

    await persistSlot(slot);

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

    return Array.from(moduleSlots.values())
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
    return Array.from(moduleSlots.values())
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
 * Minimal slot data needed for ICS file generation
 */
export interface IcsSlotData {
    id: string;
    startTime: Date;
    endTime: Date;
    meetingType: MeetingType;
    meetingLink: string | null;
}

/**
 * Generates ICS calendar file content
 */
export function generateIcsFile(slot: IcsSlotData, organizerEmail: string): string {
    const uid = `${slot.id}@apexmail.ee`;
    const now = new Date();
    const formatDate = (date: Date) =>
        date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

    return `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//ApexMail//Calendar Scheduler//EN
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
        if (timeMatch && timeMatch[1]) {
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
        if (dayMatch && dayMatch[1]) {
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
        /(\d{1,2})[/-](\d{1,2})(?:[/-](\d{2,4}))?/
    );
    if (dateMatch && dateMatch[1] && dateMatch[2]) {
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
