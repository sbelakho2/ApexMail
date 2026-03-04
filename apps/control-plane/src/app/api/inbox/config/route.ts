/** 
 * Inbox Configuration - Configure AI inbox settings
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/inbox/config');
export const PUT = (r: Request) => proxyToRust(r, '/v1/admin/inbox/config');
