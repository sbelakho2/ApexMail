/** 
 * Integrations API - Manage third-party integrations
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/integrations');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/integrations');
