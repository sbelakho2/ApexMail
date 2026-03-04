/** 
 * Calendar Availability - Manage booking availability slots
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/calendar/availability');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/calendar/availability');
