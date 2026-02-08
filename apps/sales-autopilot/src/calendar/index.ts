/**
 * Calendar Index
 */

export {
    setSchedulingPreferences,
    getSchedulingPreferences,
    createDefaultPreferences,
    getAvailableSlots,
    getSlot,
    bookSlot,
    createSlot,
    cancelBooking,
    rescheduleBooking,
    completeSlot,
    getUpcomingBookings,
    getLeadBookings,
    generateIcsFile,
    parseTimeRequest,
} from './scheduler.js';

export type { IcsSlotData } from './scheduler.js';
