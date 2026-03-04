/** 
 * Audit Alerts Configuration - Configure audit alert rules
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/audit/alerts');
export const PUT = (r: Request) => proxyToRust(r, '/v1/admin/audit/alerts');
