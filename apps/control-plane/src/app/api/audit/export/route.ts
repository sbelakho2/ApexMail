/** 
 * Audit Export - Export audit logs
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/audit/export');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/audit/export');
